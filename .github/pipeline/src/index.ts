/**
 * AI Change Assurance orchestrator (CLI entry: `npx tsx src/index.ts`).
 *
 * Pipeline, left to right:
 *   1. loadDiff          — git, --diff file, or fixtures/<id>-*.diff
 *   2. heuristics.ts     — deterministic risk floor + secret/dep findings
 *                          (reads config/controls.json, config/ai-systems-in-scope.json)
 *   3. agents.ts         — engineering + compliance sensors (live / replay / skip)
 *   4. policy.ts         — PASS | HUMAN_REVIEW | BLOCK from config/policy.json
 *   5. evidence.ts       — writes evidence/<changeId>/{findings,gate,audit,manifest,summary}
 *
 * SAFETY BOUNDARY: report and recommend only. Never merge, approve, push, or
 * edit application code. Gate decisions live only in policy.ts — never an LLM.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PIPELINE_AGENT_VERSION, COMP_TOOLS, ENG_TOOLS, loadModels, replayTranscript, runLiveAgents, skippedAgent, type OfflineTranscript } from "./agents.ts";
import { analyzeDiff, loadControls, type ControlsFile, type PackageExistsFn } from "./heuristics.ts";
import { evaluate, loadPolicy, shouldInvokeAgents } from "./policy.ts";
import { writeEvidenceBundle } from "./evidence.ts";
import { projectRoot, type AuditRecord, type Finding, type GateDecision, type GateResult, type Heuristics } from "./types.ts";

export type FailOn = "block" | "review" | "never";

export interface CliOptions {
  diffPath?: string;
  git: boolean;
  /** Attestation that a person wrote the change. Default is assumed AI involvement. */
  humanAuthored: boolean;
  /** Id of fixtures/<id>-*.diff, for example a, b, or e. */
  fixture?: string;
  offline: boolean;
  changeId?: string;
  skipAgentsWhenLowRisk: boolean;
  cwd: string;
  /** Three-dot diff base (`git diff <base>...<head>`). */
  base?: string;
  /** Three-dot diff head. Defaults to HEAD when `--base` is set. */
  head?: string;
  /** Parent directory for the evidence bundle (`<dir>/<changeId>/`). */
  evidenceDir?: string;
  /** Which gate decisions exit 1. Default `block`. */
  failOn: FailOn;
}

export interface PipelineResult {
  heuristics: Heuristics;
  findings: Finding[];
  gate: GateResult;
  audits: AuditRecord[];
  evidenceDir: string;
  markdown: string;
  combinedHash: string;
}

const FIXTURE_ID = /^[a-z0-9]+$/;

/**
 * fixtures/<id>-*.diff. One match required.
 * a, b, and c ship with transcripts; later ids only need the diff file.
 */
export function resolveFixturePath(id: string, root = projectRoot()): string {
  if (!FIXTURE_ID.test(id)) {
    throw new Error(`--fixture must be a short id such as a or e. Got "${id}".`);
  }
  const dir = path.join(root, "fixtures");
  const matches = fs.readdirSync(dir).filter((name) => name.startsWith(`${id}-`) && name.endsWith(".diff"));
  if (matches.length === 0) {
    throw new Error(`No fixtures/${id}-*.diff file. Add one to use --fixture ${id}.`);
  }
  if (matches.length > 1) {
    throw new Error(`More than one diff for fixture ${id}: ${matches.sort().join(", ")}`);
  }
  return path.join(dir, matches[0] ?? "");
}

function flagValue(flag: string, value: string | undefined): string {
  if (!value || value.startsWith("-")) throw new Error(`${flag} requires a value`);
  return value;
}

export function parseArgs(argv: string[], cwd = process.cwd()): CliOptions {
  const opts: CliOptions = {
    git: true,
    humanAuthored: false,
    offline: false,
    skipAgentsWhenLowRisk: false,
    cwd,
    failOn: "block",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--diff") {
      opts.diffPath = flagValue(arg, argv[++i]);
      opts.git = false;
    } else if (arg === "--git") {
      opts.git = true;
    } else if (arg === "--human-authored") {
      opts.humanAuthored = true;
    } else if (arg === "--agent-authored") {
      throw new Error(
        "--agent-authored was removed. AI involvement is assumed. Pass --human-authored to attest a person wrote the change.",
      );
    } else if (arg === "--fixture") {
      const id = flagValue(arg, argv[++i]);
      if (!FIXTURE_ID.test(id)) throw new Error(`--fixture must be a short id such as a or e. Got "${id}".`);
      opts.fixture = id;
      opts.git = false;
    } else if (arg === "--offline") {
      opts.offline = true;
    } else if (arg === "--change-id") {
      opts.changeId = flagValue(arg, argv[++i]);
    } else if (arg === "--skip-agents-when-low-risk") {
      opts.skipAgentsWhenLowRisk = true;
    } else if (arg === "--cwd") {
      opts.cwd = flagValue(arg, argv[++i] ?? cwd);
    } else if (arg === "--base") {
      opts.base = flagValue(arg, argv[++i]);
    } else if (arg === "--head") {
      opts.head = flagValue(arg, argv[++i]);
    } else if (arg === "--evidence-dir") {
      opts.evidenceDir = flagValue(arg, argv[++i]);
    } else if (arg === "--fail-on") {
      const value = argv[++i];
      if (value !== "block" && value !== "review" && value !== "never") {
        throw new Error("--fail-on must be block, review, or never");
      }
      opts.failOn = value;
    } else if (arg === "--help" || arg === "-h") {
      opts.git = false;
      (opts as CliOptions & { help?: boolean }).help = true;
    }
  }
  if (opts.head && !opts.base) throw new Error("--head requires --base");
  return opts;
}

/** PASS always exits 0. `block` fails BLOCK. `review` also fails HUMAN_REVIEW. `never` always exits 0. */
export function exitCodeForDecision(decision: GateDecision, failOn: FailOn): number {
  if (failOn === "never") return 0;
  if (decision === "BLOCK") return 1;
  if (failOn === "review" && decision === "HUMAN_REVIEW") return 1;
  return 0;
}

/** Prefer the PR-shaped range (main/master...HEAD); fall back to unstaged `git diff`. */
function readGitDiff(cwd: string, base?: string, head?: string): string {
  if (base) {
    return execFileSync("git", ["diff", `${base}...${head ?? "HEAD"}`], { cwd, encoding: "utf8" });
  }
  try {
    return execFileSync("git", ["diff", "main...HEAD"], { cwd, encoding: "utf8" });
  } catch {
    try {
      return execFileSync("git", ["diff", "master...HEAD"], { cwd, encoding: "utf8" });
    } catch {
      return execFileSync("git", ["diff"], { cwd, encoding: "utf8" });
    }
  }
}

/** Resolve the diff: --fixture → fixtures/<id>-*.diff, --diff → file, else git. */
export function loadDiff(opts: CliOptions, root = projectRoot()): string {
  if (opts.fixture) {
    return fs.readFileSync(resolveFixturePath(opts.fixture, root), "utf8");
  }
  if (opts.diffPath) {
    return fs.readFileSync(path.resolve(opts.cwd, opts.diffPath), "utf8");
  }
  return readGitDiff(opts.cwd, opts.base, opts.head);
}

/** Offline agent output, when fixtures/transcripts/<id>.json exists. */
function loadTranscripts(fixture: string, root = projectRoot()): {
  engineering: OfflineTranscript;
  compliance: OfflineTranscript;
} | null {
  const file = path.join(root, "fixtures/transcripts", `${fixture}.json`);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8")) as { engineering: OfflineTranscript; compliance: OfflineTranscript };
}

export interface RunPipelineOptions extends CliOptions {
  apiKey?: string;
  root?: string;
  packageExists?: PackageExistsFn;
}

export async function runPipeline(opts: RunPipelineOptions): Promise<PipelineResult> {
  const root = opts.root ?? projectRoot();
  // Step 1 — input. Fixture / file / git, in that order (see loadDiff).
  const diff = loadDiff(opts, root);
  if (!diff.trim()) {
    throw new Error("Empty diff. Pass --diff, --fixture <id>, or run inside a git repo with changes.");
  }

  const controls: ControlsFile = loadControls(root);
  // Raw config bytes are hashed later in evidence.ts (policyHash / controlsHash / modelsHash).
  const policySource = fs.readFileSync(path.join(root, "config/policy.json"), "utf8");
  const controlsSource = fs.readFileSync(path.join(root, "config/controls.json"), "utf8");
  const { file: models, source: modelsSource } = loadModels(root);

  // Step 2 — deterministic floor. Agents may add findings; they cannot lower riskTier.
  const heuristics = await analyzeDiff(diff, {
    aiInvolvement: opts.humanAuthored ? "attested-human" : "assumed",
    changeId: opts.changeId,
    root,
    packageExists: opts.packageExists,
  });

  const apiKey = opts.apiKey ?? process.env.CURSOR_API_KEY;
  // --skip-agents-when-low-risk + shouldInvokeAgents() in policy.ts.
  const invoke = !(opts.skipAgentsWhenLowRisk && !shouldInvokeAgents(heuristics));
  const allowlist = new Set(controls.controls.map((c) => c.id));

  let engineering = skippedAgent("engineering", "not_started", ENG_TOOLS);
  let compliance = skippedAgent("compliance", "not_started", COMP_TOOLS);
  const transcripts = opts.fixture ? loadTranscripts(opts.fixture, root) : null;

  // Step 3 — sensors. First matching branch wins; each writes an AuditRecord.
  if (!invoke) {
    // Optional cheap path: heuristic floor is low and --skip-agents-when-low-risk.
    engineering = skippedAgent("engineering", "low_risk_skip", ENG_TOOLS);
    compliance = skippedAgent("compliance", "low_risk_skip", COMP_TOOLS);
  } else if (transcripts && (opts.offline || !apiKey)) {
    // Replay fixtures/transcripts/<id>.json when it exists. a/b/c ship with one; d/e do not.
    const [eng, comp] = await Promise.all([
      replayTranscript({
        trigger: "assurance.engineering",
        agentName: "engineering",
        grantedTools: ENG_TOOLS,
        transcript: transcripts.engineering,
        allowlist,
      }),
      replayTranscript({
        trigger: "assurance.compliance",
        agentName: "compliance",
        grantedTools: COMP_TOOLS,
        transcript: transcripts.compliance,
        allowlist,
      }),
    ]);
    engineering = eng;
    compliance = comp;
  } else if (opts.offline || !apiKey) {
    const reason = opts.offline ? "offline_no_transcript" : "no_api_key";
    if (!apiKey && !opts.offline) console.log("CURSOR_API_KEY is unset; Cursor SDK agents were not started.");
    engineering = skippedAgent("engineering", reason, ENG_TOOLS);
    compliance = skippedAgent("compliance", reason, COMP_TOOLS);
  } else {
    console.log("Cursor SDK: starting engineering and compliance agents.");
    const live = await runLiveAgents({
      diff,
      heuristics,
      controls,
      models,
      cwd: opts.cwd,
      apiKey,
      packageExists: opts.packageExists,
    });
    engineering = live.engineering;
    compliance = live.compliance;
  }

  // Step 4 — merge findings, then the only decision point (policy.ts / config/policy.json).
  const findings = [...heuristics.findings, ...engineering.findings, ...compliance.findings];
  const audits = [engineering.audit, compliance.audit];
  const gate = evaluate(findings, heuristics, {
    outsideGrantedToolset: audits.some((a) => a.outsideGrantedToolset),
  }, loadPolicy(root));

  // Step 5 — durable local bundle under evidence/<changeId>/, or --evidence-dir/<changeId>/.
  const evidenceParent = opts.evidenceDir
    ? path.resolve(opts.cwd, opts.evidenceDir)
    : path.join(root, "evidence");
  const evidence = writeEvidenceBundle({
    changeId: heuristics.changeId,
    findings,
    gate,
    audits,
    heuristics,
    pipelineVersion: PIPELINE_AGENT_VERSION,
    policySource,
    controlsSource,
    modelsSource,
    outDir: path.join(evidenceParent, heuristics.changeId),
  });

  await maybeRemediate({ gate, findings, humanApproved: false });
  await ingestHooksStub();
  await uploadStub(evidence.dir);

  return {
    heuristics,
    findings,
    gate,
    audits,
    evidenceDir: evidence.dir,
    markdown: evidence.markdown,
    combinedHash: evidence.manifest.combinedHash,
  };
}

/**
 * TODO(remediation): A *different* cloud agent identity with a write grant.
 * Slot in as Agent.create({ cloud: { repos, autoCreatePR: true } }) only when
 * gate.decision === "PASS" && max severity is low && humanApproved === true.
 * Never reuse an assurance agentId. Currently disabled — always a no-op.
 */
export async function maybeRemediate(_ctx: {
  gate: GateResult;
  findings: Finding[];
  humanApproved?: boolean;
}): Promise<void> {
  return;
}

/** TODO(hooks-provenance): see audit.ingestHooksProvenance */
async function ingestHooksStub(): Promise<void> {
  return;
}

/** TODO(evidence-store): see evidence.uploadEvidenceStore */
async function uploadStub(_dir: string): Promise<void> {
  return;
}

function printHelp(): void {
  console.log(`AI Change Assurance — report-only release gate

Usage:
  ai-change-assurance [--fixture id] [--offline] [--human-authored]
                       [--diff path] [--git] [--base sha] [--head sha]
                       [--change-id id] [--evidence-dir dir]
                       [--fail-on block|review|never]
                       [--skip-agents-when-low-risk]

Default input is git diff main...HEAD. --fixture id loads fixtures/<id>-*.diff.
--offline replays fixtures/transcripts/<id>.json when that file exists.
--base/--head uses git diff <base>...<head>.
--fail-on defaults to block (BLOCK exits 1; review also fails HUMAN_REVIEW; never always exits 0).
AI involvement is assumed. --human-authored records an attestation that a person wrote the change. It does not change the gate.
Live Cursor agents run when CURSOR_API_KEY is set and --offline is not passed.
This tool never merges, approves, pushes, or edits application code.
`);
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const opts = parseArgs(argv);
  if ((opts as CliOptions & { help?: boolean }).help) {
    printHelp();
    return;
  }
  const result = await runPipeline(opts);
  console.log(result.markdown);
  console.log("");
  console.log(`Evidence: ${result.evidenceDir}`);
  process.exitCode = exitCodeForDecision(result.gate.decision, opts.failOn);
}

const invoked = process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
const tsxInvoked = process.argv[1]?.endsWith("src/index.ts") === true;

if (invoked || tsxInvoked) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
