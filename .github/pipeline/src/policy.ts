/**
 * The only place a PASS / HUMAN_REVIEW / BLOCK decision is made.
 *
 * Rules live in config/policy.json (not in this file). evaluate() is a pure
 * function: worst matching decision wins (BLOCK > HUMAN_REVIEW > PASS).
 *
 * Inputs come from index.ts after it merges:
 *   heuristics.findings + engineering.findings + compliance.findings
 * plus extras.outsideGrantedToolset from audit.ts (R-TOOL-ESCAPE).
 *
 * shouldInvokeAgents() is the cheap skip used by --skip-agents-when-low-risk.
 */
import fs from "node:fs";
import path from "node:path";
import {
  DECISION_RANK,
  projectRoot,
  type Finding,
  type GateDecision,
  type GateResult,
  type Heuristics,
} from "./types.ts";

export interface PolicyWhen {
  heuristicControl?: string;
  agentOnlySeverity?: "critical" | "high";
  sensitivePathWithoutTests?: boolean;
  highSeverityLowConfidence?: number;
  category?: string;
  outsideGrantedToolset?: boolean;
  possibleSubstantialModification?: boolean;
}

export interface PolicyRule {
  id: string;
  decision: GateDecision;
  when: PolicyWhen;
}

export interface PolicyFile {
  version: number;
  rules: PolicyRule[];
}

export interface EvaluateExtras {
  outsideGrantedToolset?: boolean;
}

/** Load config/policy.json. Hashed into evidence/manifest.json as policyHash. */
export function loadPolicy(root = projectRoot()): PolicyFile {
  const raw = fs.readFileSync(path.join(root, "config/policy.json"), "utf8");
  return JSON.parse(raw) as PolicyFile;
}

/** True when the heuristic floor is interesting enough to spend Cursor tokens. */
export function shouldInvokeAgents(heuristics: Heuristics): boolean {
  if (heuristics.sensitivePaths.length > 0) return true;
  if (heuristics.newPackages.length > 0) return true;
  if (heuristics.possibleSubstantialModification) return true;
  if (heuristics.riskTier !== "low") return true;
  if (heuristics.findings.some((f) => f.severity === "high" || f.severity === "critical")) return true;
  return false;
}

/** Heuristic-only hits (e.g. B010.3, A008) — used by BLOCK rules that ignore LLM opinion. */
function hasHeuristicControl(findings: Finding[], controlId: string): boolean {
  return findings.some((f) => f.source === "heuristic" && f.control_ids.includes(controlId));
}

/** Agent finding at this severity with no matching heuristic control_id — R-AGENT-CRITICAL-REVIEW. */
function agentOnlyAtLeast(findings: Finding[], severity: "critical" | "high"): boolean {
  return findings.some((f) => {
    if (f.source !== "agent") return false;
    if (severity === "critical" && f.severity !== "critical") return false;
    if (severity === "high" && !(f.severity === "high" || f.severity === "critical")) return false;
    const corroborated = findings.some(
      (other) =>
        other.source === "heuristic" &&
        other.control_ids.some((id) => f.control_ids.includes(id)),
    );
    return !corroborated;
  });
}

/** All `when` keys on a policy.json rule are ANDed. Empty `when` never matches. */
function ruleMatches(
  rule: PolicyRule,
  findings: Finding[],
  heuristics: Heuristics,
  extras: EvaluateExtras,
): boolean {
  const when = rule.when;
  if (when.heuristicControl && !hasHeuristicControl(findings, when.heuristicControl)) return false;
  if (when.agentOnlySeverity && !agentOnlyAtLeast(findings, when.agentOnlySeverity)) return false;
  if (when.sensitivePathWithoutTests) {
    if (!(heuristics.requiresTestsPaths.length > 0 && !heuristics.hasTestChanges)) return false;
  }
  if (typeof when.highSeverityLowConfidence === "number") {
    const hit = findings.some(
      (f) =>
        (f.severity === "high" || f.severity === "critical") &&
        f.confidence < when.highSeverityLowConfidence!,
    );
    if (!hit) return false;
  }
  if (when.category && !findings.some((f) => f.category === when.category)) return false;
  if (when.outsideGrantedToolset && !extras.outsideGrantedToolset) return false;
  if (when.possibleSubstantialModification && !heuristics.possibleSubstantialModification) return false;
  return Object.keys(when).length > 0;
}

/** Pure function. Precedence: BLOCK > HUMAN_REVIEW > PASS. Records every firing rule. */
export function evaluate(
  findings: Finding[],
  heuristics: Heuristics,
  extras: EvaluateExtras = {},
  policy: PolicyFile = loadPolicy(),
): GateResult {
  const fired: PolicyRule[] = [];
  for (const rule of policy.rules) {
    if (ruleMatches(rule, findings, heuristics, extras)) fired.push(rule);
  }

  let decision: GateDecision = "PASS";
  for (const rule of fired) {
    if (DECISION_RANK[rule.decision] > DECISION_RANK[decision]) decision = rule.decision;
  }

  return {
    decision,
    ruleIds: fired.map((r) => r.id),
    flags: {
      possibleSubstantialModification: heuristics.possibleSubstantialModification,
      aiInvolvement: heuristics.aiInvolvement,
    },
  };
}
