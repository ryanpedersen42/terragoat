/**
 * Cursor SDK sensors — emit findings only; they never decide the gate.
 *
 * Wired from `src/index.ts` after `heuristics.ts` scores the diff:
 *   live     → runLiveAgents()     (needs CURSOR_API_KEY)
 *   offline  → replayTranscript()  (fixtures/transcripts/<id>.json, when present)
 *   skipped  → skippedAgent()      (low risk / no key / no transcript)
 *
 * Findings flow back to index.ts, merge with heuristic findings, then
 * `policy.ts` evaluates config/policy.json. control_ids are filtered
 * against the allowlist in config/controls.json.
 *
 * Engineering uses auto-smart/intelligence + check_package_exists (B010.3).
 * Compliance uses the model pinned in config/models.json. A missing catalog
 * entry or a resolved model that differs from the pin skips that sensor.
 */
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { Agent, Cursor, type Run, type SDKCustomTool } from "@cursor/sdk";
import { checkPackageExists, controlAllowlist, formatControlCatalog, type ControlsFile } from "./heuristics.ts";
import { projectRoot, redactSecrets, type Finding, type Heuristics, type RouterSelection, type TokenUsage } from "./types.ts";
import { buildAuditRecord } from "./audit.ts";
import type { AuditRecord } from "./types.ts";

export const PIPELINE_AGENT_VERSION = "0.1.0";

/** Engineering: repo read tools + mcp so the custom npm-registry tool is granted. */
export const ENG_TOOLS = ["read", "grep", "glob", "ls", "mcp"] as const;
/** Compliance: read-only repo tools; no custom tools, no mcp. */
export const COMP_TOOLS = ["read", "grep", "glob", "ls"] as const;

/** Shape every agent finding must match before it reaches policy.ts / evidence/. */
export const FindingSchema = z.object({
  schemaVersion: z.literal(1).optional().default(1),
  agent: z.string().min(1),
  category: z.string().min(1),
  severity: z.enum(["low", "medium", "high", "critical"]),
  control_ids: z.array(z.string()),
  file: z.string(),
  evidence: z.string(),
  recommendation: z.string(),
  confidence: z.number().min(0).max(1),
  source: z.enum(["heuristic", "agent"]).optional().default("agent"),
});

export type ValidatedFinding = z.infer<typeof FindingSchema>;

/** Synthetic finding so malformed LLM output still trips R-INVALID-OUTPUT in policy.json. */
function invalidOutputFinding(agent: string, reason: string): Finding {
  return {
    schemaVersion: 1,
    agent,
    category: "invalid_agent_output",
    severity: "high",
    control_ids: [],
    file: "",
    evidence: redactSecrets(reason).slice(0, 500),
    recommendation: "Treat this run as untrusted and send the change to human review.",
    confidence: 1,
    source: "agent",
  };
}

/** Pull the first JSON array out of model text (fenced or raw). Used by parseAgentFindings. */
export function extractJsonArray(text: string): unknown {
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = (fence?.[1] ?? text).trim();
  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("no JSON array in agent output");
  }
  return JSON.parse(candidate.slice(start, end + 1));
}

/**
 * Drop unknown control_ids (not in config/controls.json) and coerce the rest
 * onto Finding. Invalid items become invalid_agent_output findings.
 */
export function validateFindings(
  raw: unknown,
  agent: string,
  allowlist: Set<string>,
): Finding[] {
  if (!Array.isArray(raw)) {
    return [invalidOutputFinding(agent, "output was not a JSON array")];
  }

  const findings: Finding[] = [];
  let invalidCount = 0;
  let droppedIds = 0;

  for (const item of raw) {
    const parsed = FindingSchema.safeParse(item);
    if (!parsed.success) {
      invalidCount += 1;
      continue;
    }
    const data = parsed.data;
    const kept = data.control_ids.filter((id) => allowlist.has(id));
    droppedIds += data.control_ids.length - kept.length;
    findings.push({
      schemaVersion: 1,
      agent: data.agent || agent,
      category: data.category,
      severity: data.severity,
      control_ids: kept,
      file: data.file,
      evidence: redactSecrets(data.evidence),
      recommendation: data.recommendation,
      confidence: data.confidence,
      source: "agent",
    });
  }

  if (invalidCount > 0) {
    findings.push(invalidOutputFinding(agent, `${invalidCount} finding(s) failed schema validation`));
  }
  if (droppedIds > 0) {
    findings.push({
      schemaVersion: 1,
      agent,
      category: "invalid_agent_output",
      severity: "medium",
      control_ids: [],
      file: "",
      evidence: `Dropped ${droppedIds} control_id(s) not present in controls.json allowlist`,
      recommendation: "Drop unknown control IDs; only IDs in controls.json are valid.",
      confidence: 1,
      source: "agent",
    });
  }
  return findings;
}

/** Parse + validate LLM text. On any failure, return a single invalid_agent_output finding. */
export function parseAgentFindings(text: string, agent: string, allowlist: Set<string>): Finding[] {
  try {
    const raw = extractJsonArray(text);
    return validateFindings(raw, agent, allowlist);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return [invalidOutputFinding(agent, message)];
  }
}

/**
 * Rebuild assistant text from stream events.
 * Live runs emit one assistant event per token, so chunks must be concatenated.
 * Inserting a separator puts raw newlines inside JSON strings and JSON.parse
 * reports "Bad control character in string literal".
 */
function assistantTextFromEvents(events: unknown[]): string {
  const parts: string[] = [];
  for (const event of events) {
    if (!event || typeof event !== "object") continue;
    const rec = event as Record<string, unknown>;
    if (rec.type !== "assistant") continue;
    const message = rec.message as { content?: Array<{ type?: string; text?: string }> } | undefined;
    for (const block of message?.content ?? []) {
      if (block?.type === "text" && typeof block.text === "string") parts.push(block.text);
    }
  }
  return parts.join("");
}

/**
 * Pick Cursor's `auto-smart` router with optimize_for = cost | balanced | intelligence.
 * Falls back to `{ id: "auto" }` if the catalog has no auto-smart parameter.
 * Engineering asks for intelligence; compliance asks for cost (see runLiveAgents).
 */
export async function selectRouterModel(
  intent: "cost" | "balanced" | "intelligence",
  listModels: () => Promise<Array<{ id: string; parameters?: Array<{ id: string; values: Array<{ value: string }> }> }>> = () =>
    Cursor.models.list(),
): Promise<RouterSelection> {
  const models = await listModels();
  const router = models.find((m) => m.id === "auto-smart");
  const optimizeFor = router?.parameters?.find((p) => p.id === "optimize_for");
  if (!router || !optimizeFor) {
    return { model: { id: "auto" }, fallback: true };
  }

  const allowed = optimizeFor.values.map((v) => v.value);
  const allowedSet = new Set(allowed);
  let value = intent;
  if (!allowedSet.has(value)) {
    if (intent === "intelligence" && allowedSet.has("balanced")) value = "balanced";
    else if (allowedSet.has("cost")) value = "cost";
    else if (allowed[0]) value = allowed[0] as typeof intent;
    else return { model: { id: "auto" }, fallback: true };
  }

  return {
    model: { id: router.id, params: [{ id: optimizeFor.id, value }] },
    optimizeFor: value,
    fallback: false,
  };
}

/** Catalog shape used to validate a pinned model. Matches Cursor.models.list() entries. */
export interface CatalogModel {
  id: string;
  parameters?: Array<{ id: string; values: Array<{ value: string }> }>;
}

export const PinnedModelSchema = z.object({
  id: z.string().min(1),
  params: z
    .array(z.object({ id: z.string().min(1), value: z.string().min(1) }))
    .optional(),
});

export const ModelsFileSchema = z.object({
  version: z.literal(1),
  description: z.string().optional(),
  compliance: PinnedModelSchema,
});

export type ModelsFile = z.infer<typeof ModelsFileSchema>;
export type PinnedModelSpec = z.infer<typeof PinnedModelSchema>;

export type PinnedSelection =
  | { ok: true; model: { id: string; params?: Array<{ id: string; value: string }> } }
  | { ok: false; reason: string };

/** Load config/models.json. The raw bytes are hashed into the evidence manifest. */
export function loadModels(root = projectRoot()): { file: ModelsFile; source: string } {
  const source = fs.readFileSync(path.join(root, "config/models.json"), "utf8");
  const parsed = ModelsFileSchema.safeParse(JSON.parse(source));
  if (!parsed.success) {
    throw new Error(`config/models.json is invalid: ${parsed.error.message}`);
  }
  const ids = parsed.data.compliance.params?.map((p) => p.id) ?? [];
  if (new Set(ids).size !== ids.length) {
    throw new Error("config/models.json compliance.params lists a parameter more than once");
  }
  return { file: parsed.data, source };
}

function normalizeParams(
  params: Array<{ id: string; value: string }> | undefined,
): Array<{ id: string; value: string }> {
  return [...(params ?? [])].sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Resolve the compliance pin against one catalog snapshot.
 * Every advertised parameter must be set in config; unknown parameters are rejected.
 * There is no fallback to auto or auto-smart.
 */
export function selectPinnedModel(spec: PinnedModelSpec, catalog: CatalogModel[]): PinnedSelection {
  const entry = catalog.find((model) => model.id === spec.id);
  if (!entry) {
    return {
      ok: false,
      reason: `pinned_model_unavailable: compliance model "${spec.id}" is not in the Cursor catalog`,
    };
  }

  const advertised = entry.parameters ?? [];
  const requested = spec.params ?? [];
  const requestedIds = new Set(requested.map((param) => param.id));

  for (const param of requested) {
    const definition = advertised.find((item) => item.id === param.id);
    if (!definition) {
      return {
        ok: false,
        reason: `pinned_model_unavailable: compliance model "${spec.id}" does not advertise parameter "${param.id}"`,
      };
    }
    if (!definition.values.some((value) => value.value === param.value)) {
      return {
        ok: false,
        reason: `pinned_model_unavailable: compliance model "${spec.id}" parameter "${param.id}" does not allow "${param.value}"`,
      };
    }
  }

  for (const definition of advertised) {
    if (!requestedIds.has(definition.id)) {
      return {
        ok: false,
        reason: `pinned_model_unavailable: compliance model "${spec.id}" parameter "${definition.id}" is not pinned in config/models.json`,
      };
    }
  }

  const params = normalizeParams(requested);
  return {
    ok: true,
    model: params.length > 0 ? { id: entry.id, params } : { id: entry.id },
  };
}

function readModelSelection(value: unknown): { id: string; params: Array<{ id: string; value: string }> } | undefined {
  if (!value || typeof value !== "object") return undefined;
  const rec = value as Record<string, unknown>;
  if (typeof rec.id !== "string" || rec.id.length === 0) return undefined;
  const params: Array<{ id: string; value: string }> = [];
  if (rec.params !== undefined) {
    if (!Array.isArray(rec.params)) return undefined;
    for (const item of rec.params) {
      if (!item || typeof item !== "object") return undefined;
      const param = item as Record<string, unknown>;
      if (typeof param.id !== "string" || typeof param.value !== "string") return undefined;
      params.push({ id: param.id, value: param.value });
    }
  }
  return { id: rec.id, params };
}

function formatParams(params: Array<{ id: string; value: string }>): string {
  if (params.length === 0) return "none";
  return params.map((param) => `${param.id}=${param.value}`).join(",");
}

/**
 * Null when the run's resolved model matches the pin, including parameters.
 * A missing or unreadable resolved model is a mismatch.
 */
export function modelMismatchReason(
  requested: { id: string; params?: Array<{ id: string; value: string }> },
  resolved: unknown,
): string | null {
  const parsed = readModelSelection(resolved);
  if (!parsed) {
    return `pinned_model_mismatch: compliance model "${requested.id}" was requested but the run did not report a resolved model`;
  }
  if (parsed.id !== requested.id) {
    return `pinned_model_mismatch: compliance model "${requested.id}" was requested but the run resolved "${parsed.id}"`;
  }
  const want = normalizeParams(requested.params);
  const got = normalizeParams(parsed.params);
  if (JSON.stringify(want) !== JSON.stringify(got)) {
    return `pinned_model_mismatch: compliance model "${requested.id}" parameters differ (requested ${formatParams(want)}, resolved ${formatParams(got)})`;
  }
  return null;
}

/**
 * Custom tool handed only to the engineering agent (local.customTools).
 * Implementation lives in heuristics.ts → registry.npmjs.org.
 */
export function checkPackageExistsTool(packageExists = checkPackageExists): SDKCustomTool {
  return {
    description:
      "Check whether one npm package name exists on registry.npmjs.org. Use this before reporting B010.3 (hallucinated or typosquatted dependencies).",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Package name, e.g. lodash or @scope/name" },
      },
      required: ["name"],
    },
    annotations: {
      title: "Check npm package exists",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    async execute(args) {
      const name = typeof args.name === "string" ? args.name : "";
      if (!name) return { name: "", exists: false, status: 400, error: "name required" };
      const result = await packageExists(name);
      return {
        name: result.name,
        exists: result.exists,
        status: result.status,
        error: result.error ?? null,
      };
    },
  };
}

/** Prompt for the engineering sensor. Heuristic context is a floor — the model cannot lower it. */
export function engineeringPrompt(diff: string, heuristics: Heuristics, controls: ControlsFile): string {
  return `You are the Engineering & Security sensor in an AI Change Assurance pipeline.
You do NOT decide PASS/BLOCK. You only emit findings. The orchestrator enforces policy.

Inspect this git diff. Use read/grep/glob/ls if you need repo context. You have a custom tool check_package_exists — you MUST call it for every newly added npm package.

Look for:
- Secrets in the diff (AIUC-1 A008)
- Insecure auth/authz and common vuln patterns (B010.1, B010.2)
- Likely bugs: missing error handling, untested edge cases
- Hallucinated or typosquatted dependencies (B010.3)

Control catalog. Cite only these IDs. Each review line says what to look for in the diff. The review line does not decide the gate.
${formatControlCatalog(controls)}

Heuristic context (you cannot lower this risk floor):
${JSON.stringify(
    {
      riskTier: heuristics.riskTier,
      sensitivePaths: heuristics.sensitivePaths,
      newPackages: heuristics.newPackages,
      hasTestChanges: heuristics.hasTestChanges,
      controlIds: heuristics.controlIds,
    },
    null,
    2,
  )}

Return ONLY a JSON array of findings. Each object:
{
  "agent": "engineering",
  "category": "string",
  "severity": "low"|"medium"|"high"|"critical",
  "control_ids": ["A008"|"B010.1"|"B010.2"|"B010.3"|... allowlisted IDs only],
  "file": "path",
  "evidence": "short quote or observation",
  "recommendation": "what a human should do",
  "confidence": 0.0-1.0
}
Empty array if nothing to report.

DIFF:
\`\`\`diff
${diff}
\`\`\`
`;
}

/**
 * Prompt for the compliance sensor. Path→control IDs come from
 * heuristics.matchControlIds. Review guidance comes from controls.json.
 */
export function compliancePrompt(diff: string, heuristics: Heuristics, controls: ControlsFile): string {
  return `You are the Compliance sensor in an AI Change Assurance pipeline.
You do NOT decide PASS/BLOCK and you do NOT invent control IDs.

Classify the change (refactor, feature, auth, infra, dependency, ai-system) and write narrative findings.
If the change appears to touch an in-scope AI system, say so.

Control catalog. Cite only these IDs. Each review line says what to look for in the diff. The review line does not decide the gate.
${formatControlCatalog(controls)}

Path matching already attached these IDs: ${heuristics.controlIds.join(", ") || "(none)"}. You may cite other IDs from the catalog when the diff supports them.

AI involvement is "${heuristics.aiInvolvement}". Treat the diff as AI-assisted unless that value is "attested-human". That value is a person's attestation. Do not invent a different one.

Heuristic context:
${JSON.stringify(
    {
      riskTier: heuristics.riskTier,
      files: heuristics.files,
      possibleSubstantialModification: heuristics.possibleSubstantialModification,
      aiInvolvement: heuristics.aiInvolvement,
      controlIds: heuristics.controlIds,
    },
    null,
    2,
  )}

Return ONLY a JSON array of findings with the same schema as:
{
  "agent": "compliance",
  "category": "change_management"|"access_control"|"ai_act"|"other",
  "severity": "low"|"medium"|"high"|"critical",
  "control_ids": [],
  "file": "path or empty",
  "evidence": "narrative grounded in the diff",
  "recommendation": "process next step",
  "confidence": 0.0-1.0
}

DIFF:
\`\`\`diff
${diff}
\`\`\`
`;
}

/** One sensor's output: parsed findings + audit trail for evidence/audit.json. */
export interface AgentRunBundle {
  findings: Finding[];
  audit: AuditRecord;
  text: string;
}

export interface OfflineTranscript {
  events?: unknown[];
  resultText?: string;
  requestId?: string;
  durationMs?: number;
  usage?: TokenUsage;
  model?: unknown;
  optimizeFor?: string;
  agentId?: string;
}

/** Drain the Cursor stream (events go to audit.ts) and recover assistant text for parsing. */
async function collectRun(run: Run): Promise<{ events: unknown[]; result: Awaited<ReturnType<Run["wait"]>>; text: string }> {
  const events: unknown[] = [];
  for await (const event of run.stream()) events.push(event);
  const result = await run.wait();
  const streamed = assistantTextFromEvents(events);
  const text = streamed || (typeof result.result === "string" ? result.result : "");
  return { events, result, text };
}

/** Offline / fixture path: parse a saved transcript instead of calling Cursor. */
export async function replayTranscript(args: {
  trigger: "assurance.engineering" | "assurance.compliance";
  agentName: string;
  grantedTools: readonly string[];
  transcript: OfflineTranscript;
  allowlist: Set<string>;
  model?: unknown;
  optimizeFor?: string;
}): Promise<AgentRunBundle> {
  const text = args.transcript.resultText ?? assistantTextFromEvents(args.transcript.events ?? []);
  const findings = parseAgentFindings(text, args.agentName, args.allowlist);
  const audit = buildAuditRecord({
    trigger: args.trigger,
    agentName: args.agentName,
    agentVersion: PIPELINE_AGENT_VERSION,
    agentId: args.transcript.agentId,
    grantedTools: [...args.grantedTools],
    model: args.transcript.model ?? args.model,
    optimizeFor: args.transcript.optimizeFor ?? args.optimizeFor,
    requestId: args.transcript.requestId,
    durationMs: args.transcript.durationMs,
    usage: args.transcript.usage,
    events: args.transcript.events ?? [],
  });
  return { findings, audit, text };
}

/**
 * Live path from index.ts: two parallel Agent.create + send calls.
 * Engineering uses auto-smart. Compliance uses the config/models.json pin
 * and is skipped when that pin cannot be honored.
 */
export async function runLiveAgents(args: {
  diff: string;
  heuristics: Heuristics;
  controls: ControlsFile;
  models: ModelsFile;
  cwd: string;
  apiKey: string;
  packageExists?: typeof checkPackageExists;
}): Promise<{ engineering: AgentRunBundle; compliance: AgentRunBundle }> {
  const allowlist = controlAllowlist(args.controls);
  const catalog = await Cursor.models.list({ apiKey: args.apiKey });
  const engModel = await selectRouterModel("intelligence", async () => catalog);
  const pinned = selectPinnedModel(args.models.compliance, catalog);

  const customTool = checkPackageExistsTool(args.packageExists);

  const runOne = async (
    kind: "engineering" | "compliance",
    selection: RouterSelection,
  ): Promise<AgentRunBundle> => {
    const isEng = kind === "engineering";
    const tools = isEng ? [...ENG_TOOLS] : [...COMP_TOOLS];
    const prompt = isEng
      ? engineeringPrompt(args.diff, args.heuristics, args.controls)
      : compliancePrompt(args.diff, args.heuristics, args.controls);

    await using agent = await Agent.create({
      apiKey: args.apiKey,
      name: `assurance-${kind}`,
      model: selection.model,
      tools,
      local: {
        cwd: args.cwd,
        settingSources: [],
        ...(isEng ? { customTools: { check_package_exists: customTool } } : {}),
      },
    });

    const run = await agent.send(prompt);
    console.log(`Cursor SDK: ${kind} agent=${agent.agentId} run=${run.id}`);
    const { events, result, text } = await collectRun(run);

    let billed: AgentRunBundle["audit"]["billed"];
    try {
      const usage = await agent.getUsage();
      billed = {
        usage: usage.usage,
        cost: usage.cost
          ? { rawCostCents: usage.cost.rawCostCents, chargedCents: usage.cost.chargedCents }
          : undefined,
      };
    } catch {
      billed = undefined;
    }

    const mismatch = isEng ? null : modelMismatchReason(selection.model, result.model);
    const findings = mismatch ? [] : parseAgentFindings(text, kind, allowlist);
    const audit = buildAuditRecord({
      trigger: isEng ? "assurance.engineering" : "assurance.compliance",
      agentName: kind,
      agentVersion: PIPELINE_AGENT_VERSION,
      agentId: agent.agentId,
      grantedTools: tools,
      model: mismatch ? result.model : (result.model ?? selection.model),
      requestedModel: isEng ? undefined : selection.model,
      optimizeFor: selection.optimizeFor,
      requestId: result.requestId ?? run.requestId,
      durationMs: result.durationMs,
      usage: result.usage,
      billed,
      events,
      skipped: mismatch ? true : undefined,
      skipReason: mismatch ?? undefined,
    });
    return { findings, audit, text };
  };

  const requestedPin = {
    id: args.models.compliance.id,
    ...(args.models.compliance.params ? { params: args.models.compliance.params } : {}),
  };
  const [engineering, compliance] = await Promise.all([
    runOne("engineering", engModel),
    pinned.ok
      ? runOne("compliance", { model: pinned.model, fallback: false })
      : Promise.resolve(skippedAgent("compliance", pinned.reason, COMP_TOOLS, { requestedModel: requestedPin })),
  ]);
  return { engineering, compliance };
}

/** Placeholder bundle when a sensor is not invoked. skipReason is recorded in audit.json. */
export function skippedAgent(
  kind: "engineering" | "compliance",
  reason: string,
  tools: readonly string[],
  extras?: { model?: unknown; requestedModel?: unknown },
): AgentRunBundle {
  return {
    findings: [],
    text: "",
    audit: buildAuditRecord({
      trigger: kind === "engineering" ? "assurance.engineering" : "assurance.compliance",
      agentName: kind,
      agentVersion: PIPELINE_AGENT_VERSION,
      grantedTools: [...tools],
      model: extras?.model,
      requestedModel: extras?.requestedModel,
      skipped: true,
      skipReason: reason,
    }),
  };
}
