/**
 * Per-sensor audit trail written to evidence/<changeId>/audit.json.
 *
 * Built by agents.ts after each live run, transcript replay, or skip.
 * extractToolCalls() walks Cursor stream events; isToolGranted() compares
 * them to ENG_TOOLS / COMP_TOOLS. A mismatch sets outsideGrantedToolset,
 * which policy.ts maps to R-TOOL-ESCAPE → HUMAN_REVIEW.
 *
 * ingestHooksProvenance() is a stub for the *authoring* agent's Cursor
 * hooks — a different identity from these assurance sensors.
 */
import { summarizeUnknown, type AuditRecord, type AgentTrigger, type TokenUsage, type ToolCallRecord } from "./types.ts";

const CUSTOM_TOOL_ALIASES = new Set([
  "check_package_exists",
  "custom-user-tools",
  "mcp",
  "mcp:check_package_exists",
]);

/** Granted if the name is on the agent's tool list, or an mcp alias when "mcp" is granted. */
export function isToolGranted(name: string, grantedTools: string[]): boolean {
  const normalized = name.toLowerCase();
  if (grantedTools.some((t) => t.toLowerCase() === normalized)) return true;
  if (grantedTools.includes("mcp") && CUSTOM_TOOL_ALIASES.has(normalized)) return true;
  if (normalized.startsWith("mcp") && grantedTools.includes("mcp")) return true;
  return false;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return null;
}

export function extractToolCalls(events: unknown[]): ToolCallRecord[] {
  const calls: ToolCallRecord[] = [];
  for (const event of events) {
    const rec = asRecord(event);
    if (!rec) continue;
    if (rec.type !== "tool_call") continue;
    const name = typeof rec.name === "string" ? rec.name : "unknown";
    const status = typeof rec.status === "string" ? rec.status : "unknown";
    const callId = typeof rec.call_id === "string" ? rec.call_id : undefined;
    const args = "args" in rec ? rec.args : undefined;
    calls.push({
      name,
      status,
      callId,
      argsSummary: summarizeUnknown(args),
    });
  }
  return calls;
}

export interface BuildAuditInput {
  trigger: AgentTrigger;
  agentName: string;
  agentVersion: string;
  agentId?: string;
  grantedTools: string[];
  model?: unknown;
  requestedModel?: unknown;
  optimizeFor?: string;
  requestId?: string;
  durationMs?: number;
  usage?: TokenUsage;
  billed?: AuditRecord["billed"];
  events?: unknown[];
  skipped?: boolean;
  skipReason?: string;
}

export function buildAuditRecord(input: BuildAuditInput): AuditRecord {
  const toolCalls = extractToolCalls(input.events ?? []);
  const outsideGrantedToolset = toolCalls.some((c) => !isToolGranted(c.name, input.grantedTools));
  return {
    trigger: input.trigger,
    agentName: input.agentName,
    agentVersion: input.agentVersion,
    agentId: input.agentId,
    grantedTools: input.grantedTools,
    model: input.model,
    requestedModel: input.requestedModel,
    optimizeFor: input.optimizeFor,
    requestId: input.requestId,
    durationMs: input.durationMs,
    usage: input.usage,
    billed: input.billed,
    toolCalls,
    outsideGrantedToolset,
    skipped: input.skipped,
    skipReason: input.skipReason,
  };
}

/**
 * TODO(hooks-provenance): ingest `.cursor/hooks.json` / hook log files as
 * `trigger: "authoring.cursor"` records. That is the coding agent's trail,
 * distinct from these assurance agents. Slot in by appending AuditRecords
 * before the evidence bundle is written — do not mix identities.
 */
export async function ingestHooksProvenance(_logDir?: string): Promise<AuditRecord[]> {
  return [];
}
