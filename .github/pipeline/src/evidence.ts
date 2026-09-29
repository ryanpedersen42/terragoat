/**
 * Writes the local evidence bundle for one change.
 *
 * Output: evidence/<changeId>/
 *   findings.json  — merged heuristic + agent findings
 *   gate.json      — policy.ts decision + firing rule IDs
 *   audit.json     — per-sensor trail from audit.ts
 *   manifest.json  — hashes of the above + policy/controls/models bytes from index.ts
 *   summary.md     — PR-comment markdown printed by the CLI
 *                    (decision, findings, per-agent cost, attestation)
 *
 * combinedHash is the attestation root. uploadEvidenceStore() is the
 * future WORM-store hook (still a no-op; called from index.ts).
 */
import fs from "node:fs";
import path from "node:path";
import { projectRoot, sha256, type AiInvolvement, type AuditRecord, type Finding, type GateResult, type Heuristics } from "./types.ts";

export interface EvidenceManifest {
  changeId: string;
  createdAt: string;
  pipelineVersion: string;
  diffHash: string;
  policyHash: string;
  controlsHash: string;
  modelsHash: string;
  aiInvolvement: AiInvolvement;
  models: unknown[];
  files: Record<string, string>;
  combinedHash: string;
}

export interface WriteEvidenceInput {
  changeId: string;
  findings: Finding[];
  gate: GateResult;
  audits: AuditRecord[];
  heuristics: Heuristics;
  pipelineVersion: string;
  policySource: string;
  controlsSource: string;
  modelsSource: string;
  outDir?: string;
}

export function combinedHashOf(files: Record<string, string>): string {
  const lines = Object.entries(files)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, hash]) => `${name}=${hash}`);
  return sha256(lines.join("\n"));
}

function formatCents(cents?: number): string {
  if (cents === undefined) return "n/a";
  return `$${(cents / 100).toFixed(4)}`;
}

/** Model pin, router selection, or skip reason for one sensor line in summary.md. */
function agentSelection(audit: AuditRecord): string {
  if (audit.skipped && audit.skipReason) return `skipped (${audit.skipReason})`;
  if (audit.optimizeFor) return audit.optimizeFor;
  const source = audit.requestedModel ?? audit.model;
  if (source && typeof source === "object" && "id" in source && typeof source.id === "string") return source.id;
  return "-";
}

function formatAgentLines(audits: AuditRecord[]): string {
  if (audits.length === 0) return "- None.";
  return audits
    .map((audit) => {
      const tokens = audit.usage?.totalTokens ?? audit.billed?.usage?.totalTokens ?? 0;
      const cost = formatCents(audit.billed?.cost?.chargedCents);
      const id = audit.agentId ? ` · \`${audit.agentId}\`` : "";
      return `- **${audit.agentName}** ${agentSelection(audit)} · ${tokens} tokens · ${cost}${id}`;
    })
    .join("\n");
}

/** Markdown printed to stdout by index.ts and saved as evidence/<id>/summary.md. */
export function formatPrComment(input: {
  changeId: string;
  gate: GateResult;
  findings: Finding[];
  heuristics: Heuristics;
  audits: AuditRecord[];
  attestation: string;
}): string {
  const top = [...input.findings]
    .sort((a, b) => {
      const rank = { critical: 3, high: 2, medium: 1, low: 0 };
      return rank[b.severity] - rank[a.severity];
    })
    .slice(0, 8);

  const findingLines =
    top.length === 0
      ? "- None."
      : top
          .map(
            (f) =>
              `- **${f.severity}** \`${f.category}\` (${f.source}/${f.agent}) in \`${f.file || "n/a"}\` — ${f.recommendation}`,
          )
          .join("\n");

  return [
    `## AI Change Assurance \`${input.gate.decision}\``,
    "",
    `Change \`${input.changeId}\` · risk floor **${input.heuristics.riskTier}** · AI involvement: ${input.heuristics.aiInvolvement}`,
    "",
    `Rules fired: ${input.gate.ruleIds.length ? input.gate.ruleIds.join(", ") : "(none)"}`,
    `Flags: substantial modification=${input.gate.flags.possibleSubstantialModification}`,
    "",
    "### Findings",
    findingLines,
    "",
    "### Agents",
    formatAgentLines(input.audits),
    "",
    `Attestation: \`${input.attestation}\``,
    "",
    "> This pipeline **reports and recommends only**. It does not merge, approve, push, or modify application code.",
  ].join("\n");
}

export function writeEvidenceBundle(input: WriteEvidenceInput): { dir: string; manifest: EvidenceManifest; markdown: string } {
  const dir = input.outDir ?? path.join(projectRoot(), "evidence", input.changeId);
  fs.mkdirSync(dir, { recursive: true });

  const findingsJson = `${JSON.stringify(input.findings, null, 2)}\n`;
  const gateJson = `${JSON.stringify(input.gate, null, 2)}\n`;
  const auditJson = `${JSON.stringify(input.audits, null, 2)}\n`;

  fs.writeFileSync(path.join(dir, "findings.json"), findingsJson);
  fs.writeFileSync(path.join(dir, "gate.json"), gateJson);
  fs.writeFileSync(path.join(dir, "audit.json"), auditJson);

  const files = {
    "findings.json": sha256(findingsJson),
    "gate.json": sha256(gateJson),
    "audit.json": sha256(auditJson),
  };

  const manifest: EvidenceManifest = {
    changeId: input.changeId,
    createdAt: new Date().toISOString(),
    pipelineVersion: input.pipelineVersion,
    diffHash: input.heuristics.diffHash,
    policyHash: sha256(input.policySource),
    controlsHash: sha256(input.controlsSource),
    modelsHash: sha256(input.modelsSource),
    aiInvolvement: input.heuristics.aiInvolvement,
    models: input.audits.map((a) => ({
      agent: a.agentName,
      model: a.model,
      requestedModel: a.requestedModel,
      optimizeFor: a.optimizeFor,
    })),
    files,
    combinedHash: combinedHashOf(files),
  };

  fs.writeFileSync(path.join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  const markdown = formatPrComment({
    changeId: input.changeId,
    gate: input.gate,
    findings: input.findings,
    heuristics: input.heuristics,
    audits: input.audits,
    attestation: manifest.combinedHash,
  });
  fs.writeFileSync(path.join(dir, "summary.md"), `${markdown}\n`);

  return { dir, manifest, markdown };
}

/**
 * TODO(evidence-store): upload `evidence/<change-id>/` to a WORM object store
 * (bucket + retention hold). The combinedHash is the attestation root to store
 * beside the objects. This prototype only writes to the local filesystem.
 */
export async function uploadEvidenceStore(_dir: string): Promise<void> {
  return;
}
