/**
 * Shared contracts for the assurance pipeline.
 *
 * Finding / Heuristics / GateResult / AuditRecord are the objects that
 * travel between heuristics.ts → agents.ts → policy.ts → evidence.ts.
 *
 * Also owns secret detection (looksLikeSecret / redactSecrets) used by
 * heuristics.ts (scan added lines) and agents.ts (sanitize LLM evidence).
 */
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type Severity = "low" | "medium" | "high" | "critical";
export type RiskTier = Severity;
export type GateDecision = "PASS" | "HUMAN_REVIEW" | "BLOCK";
export type FindingSource = "heuristic" | "agent";
export type AgentTrigger = "assurance.engineering" | "assurance.compliance";
/** Assumed unless someone attests the change was written by a person. Does not change the gate. */
export type AiInvolvement = "assumed" | "attested-human";

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export const DECISION_RANK: Record<GateDecision, number> = {
  PASS: 0,
  HUMAN_REVIEW: 1,
  BLOCK: 2,
};

/** One issue from heuristics.ts or an agents.ts sensor. Merged in index.ts, gated in policy.ts. */
export interface Finding {
  schemaVersion: 1;
  agent: string;
  category: string;
  severity: Severity;
  control_ids: string[];
  file: string;
  evidence: string;
  recommendation: string;
  confidence: number;
  source: FindingSource;
}

/** Output of heuristics.analyzeDiff — risk floor + deterministic findings. */
export interface Heuristics {
  changeId: string;
  diffHash: string;
  files: string[];
  addedLines: number;
  removedLines: number;
  riskTier: RiskTier;
  sensitivePaths: string[];
  hasTestChanges: boolean;
  aiInvolvement: AiInvolvement;
  possibleSubstantialModification: boolean;
  newPackages: string[];
  missingPackages: string[];
  controlIds: string[];
  findings: Finding[];
  requiresTestsPaths: string[];
}

export interface GateFlags {
  possibleSubstantialModification: boolean;
  aiInvolvement: AiInvolvement;
}

/** Output of policy.evaluate. Written to evidence/<id>/gate.json. */
export interface GateResult {
  decision: GateDecision;
  ruleIds: string[];
  flags: GateFlags;
}

export interface TokenUsage {
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  totalTokens?: number;
}

export interface ToolCallRecord {
  name: string;
  status: string;
  callId?: string;
  argsSummary: string;
}

/** One sensor's trail. Built in audit.ts, written to evidence/<id>/audit.json. */
export interface AuditRecord {
  trigger: AgentTrigger;
  agentName: string;
  agentVersion: string;
  agentId?: string;
  grantedTools: string[];
  model?: unknown;
  /** Model required by config/models.json. Set on the compliance sensor. */
  requestedModel?: unknown;
  optimizeFor?: string;
  requestId?: string;
  durationMs?: number;
  usage?: TokenUsage;
  billed?: {
    usage?: TokenUsage;
    cost?: { rawCostCents?: number; chargedCents?: number };
  };
  toolCalls: ToolCallRecord[];
  outsideGrantedToolset: boolean;
  skipped?: boolean;
  skipReason?: string;
}

export interface RouterSelection {
  model: { id: string; params?: Array<{ id: string; value: string }> };
  optimizeFor?: string;
  fallback: boolean;
}

/** Repo root (parent of src/). Config and fixtures are resolved from here. */
export function projectRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

const SECRET_PATTERNS: Array<{ re: RegExp }> = [
  { re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/g },
  { re: /AKIA[0-9A-Z]{16}/g },
  { re: /sk_live_[0-9a-zA-Z]{8,}/g },
  { re: /ghp_[0-9A-Za-z]{20,}/g },
  { re: /github_pat_[0-9A-Za-z_]{20,}/g },
  { re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { re: /(?:api[_-]?key|secret[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]/gi },
];

/** Pattern match used by heuristics.ts on added diff lines. */
export function looksLikeSecret(text: string): boolean {
  return SECRET_PATTERNS.some(({ re }) => {
    re.lastIndex = 0;
    return re.test(text);
  });
}

/** Mask matches before they land in findings.json or agent evidence. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const { re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (match) => {
      if (match.length <= 8) return "[REDACTED]";
      return `${match.slice(0, 4)}…[REDACTED]`;
    });
  }
  return out;
}

export function summarizeUnknown(value: unknown, max = 240): string {
  try {
    const raw =
      typeof value === "string"
        ? value
        : JSON.stringify(value, (_k, v) => {
            if (typeof v === "string" && v.length > 80) return `${v.slice(0, 80)}…`;
            return v;
          });
    const redacted = redactSecrets(raw ?? "null");
    return redacted.length > max ? `${redacted.slice(0, max)}…` : redacted;
  } catch {
    return "[unparseable]";
  }
}

export function maxSeverity(findings: Finding[]): Severity | null {
  if (findings.length === 0) return null;
  return findings.reduce<Severity>((acc, f) => {
    return SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc;
  }, "low");
}

export function raiseTier(current: RiskTier, floor: RiskTier): RiskTier {
  return SEVERITY_RANK[floor] > SEVERITY_RANK[current] ? floor : current;
}
