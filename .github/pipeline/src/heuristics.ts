/**
 * Deterministic first pass over the unified diff. Runs before any LLM.
 *
 * Reads:
 *   config/controls.json            — path/category → control ID allowlist.
 *                                     `match` is deterministic. `review` is
 *                                     the diff guidance copied into agent prompts.
 *   config/ai-systems-in-scope.json — prefixes that flag EU AI Act review
 *
 * Writes a Heuristics object consumed by:
 *   index.ts   — decide whether to invoke agents, merge findings
 *   agents.ts  — inject risk floor into prompts (cannot be lowered)
 *   policy.ts  — sensitivePathWithoutTests, possibleSubstantialModification, …
 *
 * Also owns checkPackageExists (registry.npmjs.org), which agents.ts wraps
 * as the engineering custom tool for B010.3.
 */
import fs from "node:fs";
import path from "node:path";
import {
  looksLikeSecret,
  projectRoot,
  raiseTier,
  redactSecrets,
  sha256,
  type AiInvolvement,
  type Finding,
  type Heuristics,
  type RiskTier,
} from "./types.ts";

export interface ControlMatch {
  id: string;
  framework: string;
  label?: string;
  /** What the sensor should look for in a diff. Not read by the gate. */
  review: string;
  match: {
    anyPath?: boolean;
    pathIncludes?: string[];
    categories?: string[];
  };
}

export interface ControlsFile {
  version: number;
  controls: ControlMatch[];
}

export interface InScopeFile {
  paths: string[];
}

export interface PackageExistsResult {
  name: string;
  exists: boolean;
  status: number;
  error?: string;
}

export type PackageExistsFn = (name: string) => Promise<PackageExistsResult>;

export interface AnalyzeDiffOptions {
  /** Defaults to assumed AI involvement. */
  aiInvolvement?: AiInvolvement;
  changeId?: string;
  checkPackages?: boolean;
  packageExists?: PackageExistsFn;
  controls?: ControlsFile;
  inScopePaths?: string[];
  root?: string;
}

const PACKAGE_JSON_META = new Set([
  "name",
  "version",
  "description",
  "main",
  "module",
  "types",
  "license",
  "private",
  "type",
  "author",
  "repository",
  "homepage",
  "engines",
  "packageManager",
  "sideEffects",
  "exports",
  "scripts",
  "bin",
  "files",
  "os",
  "cpu",
  "workspaces",
]);

const VERSIONISH = /^[~^>=<\s]*\d+\.\d+|workspace:|latest|catalog:|\*|file:|link:|npm:|http/;

function isTestPath(file: string): boolean {
  const normalized = file.replaceAll("\\", "/");
  return (
    /(^|\/)(__tests__|tests?|spec)(\/|$)/i.test(normalized) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/i.test(normalized)
  );
}

function pathIncludesToken(file: string, token: string): boolean {
  const normalized = file.replaceAll("\\", "/").toLowerCase();
  const needle = token.toLowerCase().replaceAll("\\", "/");
  if (needle.includes("*")) {
    const escaped = needle.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("\\*", ".*");
    return new RegExp(`(^|/)${escaped}$`).test(normalized) || new RegExp(escaped).test(normalized);
  }
  if (needle.includes(".")) {
    return normalized === needle || normalized.endsWith(`/${needle}`) || normalized.includes(needle);
  }
  return (
    normalized.split("/").includes(needle) ||
    normalized.includes(`/${needle}/`) ||
    normalized.startsWith(`${needle}/`) ||
    normalized.endsWith(`/${needle}`)
  );
}

/**
 * Path-based risk floor. Auth/IAM/payments require tests
 * (policy rule R-SENSITIVE-NO-TESTS). Terraform stays high risk; plan and
 * policy scans cover it, so a missing test file does not fire that rule.
 * Lockfiles are medium, no test requirement.
 */
export function isSensitivePath(file: string): { sensitive: boolean; floor: RiskTier; requiresTests: boolean } {
  const normalized = file.replaceAll("\\", "/").toLowerCase();
  const basename = path.posix.basename(normalized);

  if (
    basename === "package.json" ||
    basename === "package-lock.json" ||
    basename === "yarn.lock" ||
    basename === "pnpm-lock.yaml" ||
    basename === "bun.lock" ||
    basename === "bun.lockb"
  ) {
    return { sensitive: true, floor: "medium", requiresTests: false };
  }
  if (normalized.endsWith(".tf") || normalized.endsWith(".tfvars")) {
    return { sensitive: true, floor: "high", requiresTests: false };
  }
  if (
    pathIncludesToken(normalized, "auth") ||
    pathIncludesToken(normalized, "iam") ||
    pathIncludesToken(normalized, "payments")
  ) {
    return { sensitive: true, floor: "high", requiresTests: true };
  }
  return { sensitive: false, floor: "low", requiresTests: false };
}

export function parseUnifiedDiff(diff: string): Array<{
  path: string;
  added: string[];
  removed: string[];
}> {
  const files: Array<{ path: string; added: string[]; removed: string[] }> = [];
  let current: { path: string; added: string[]; removed: string[] } | null = null;

  for (const line of diff.split(/\r?\n/)) {
    const gitHeader = line.match(/^diff --git a\/(.+) b\/(.+)$/);
    if (gitHeader) {
      current = { path: gitHeader[2] ?? gitHeader[1] ?? "", added: [], removed: [] };
      files.push(current);
      continue;
    }
    const plusPlus = line.match(/^\+\+\+ (?:b\/)?(.+)$/);
    if (plusPlus && current && plusPlus[1] && plusPlus[1] !== "/dev/null") {
      current.path = plusPlus[1];
      continue;
    }
    if (!current) continue;
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) continue;
    if (line.startsWith("+")) current.added.push(line.slice(1));
    else if (line.startsWith("-")) current.removed.push(line.slice(1));
  }
  return files.filter((f) => f.path && f.path !== "/dev/null");
}

/** New dependency names from added package.json / lockfile lines — fed to checkPackageExists. */
export function extractNewPackages(files: ReturnType<typeof parseUnifiedDiff>): string[] {
  const names = new Set<string>();
  for (const file of files) {
    const base = path.posix.basename(file.path);
    if (base === "package.json") {
      for (const line of file.added) {
        const m = line.match(/^\s*"([^"]+)":\s*"([^"]+)"/);
        if (!m) continue;
        const [, name, version] = m;
        if (!name || !version) continue;
        if (PACKAGE_JSON_META.has(name)) continue;
        if (!VERSIONISH.test(version)) continue;
        names.add(name);
      }
    }
    if (base === "package-lock.json" || base === "yarn.lock" || base === "pnpm-lock.yaml") {
      for (const line of file.added) {
        const lock = line.match(/^\s*"([^"]+)@[^"]+"\s*:/) || line.match(/^"?([^"@\s]+)@\d/);
        if (lock?.[1] && !lock[1].startsWith("node_modules")) names.add(lock[1]);
      }
    }
  }
  return [...names];
}

export async function checkPackageExists(name: string): Promise<PackageExistsResult> {
  const encoded = encodeURIComponent(name).replace("%40", "@").replace("%2F", "%2f");
  const url = `https://registry.npmjs.org/${encoded}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json", "user-agent": "ai-change-assurance/0.1" },
      signal: AbortSignal.timeout(8000),
    });
    if (res.status === 404) return { name, exists: false, status: 404 };
    if (res.ok) return { name, exists: true, status: res.status };
    return { name, exists: false, status: res.status, error: `unexpected_status_${res.status}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { name, exists: false, status: 0, error: message };
  }
}

/** config/controls.json — allowlisted IDs that agents may attach to findings. */
export function loadControls(root = projectRoot()): ControlsFile {
  const raw = fs.readFileSync(path.join(root, "config/controls.json"), "utf8");
  return JSON.parse(raw) as ControlsFile;
}

/** config/ai-systems-in-scope.json — if a changed path matches, policy fires R-EU-AI-ACT. */
export function loadInScopePaths(root = projectRoot()): string[] {
  const raw = fs.readFileSync(path.join(root, "config/ai-systems-in-scope.json"), "utf8");
  const parsed = JSON.parse(raw) as InScopeFile;
  return parsed.paths ?? [];
}

export function controlAllowlist(controls: ControlsFile): Set<string> {
  return new Set(controls.controls.map((c) => c.id));
}

/** Catalog text for agent prompts. `match` stays in code and is not included. */
export function formatControlCatalog(controls: ControlsFile): string {
  return controls.controls
    .map((control) => {
      const name = [control.framework, control.label].filter(Boolean).join(": ");
      return `- ${control.id} (${name}). ${control.review}`;
    })
    .join("\n");
}

/** Map changed paths + finding categories onto control IDs (SOC 2 / ISO / NIST / AIUC-1). */
export function matchControlIds(files: string[], controls: ControlsFile, categories: string[] = []): string[] {
  const ids: string[] = [];
  for (const control of controls.controls) {
    if (control.match.categories?.some((c) => categories.includes(c))) {
      ids.push(control.id);
      continue;
    }
    if (control.match.anyPath && files.length > 0) {
      ids.push(control.id);
      continue;
    }
    if (control.match.pathIncludes?.some((token) => files.some((f) => pathIncludesToken(f, token)))) {
      ids.push(control.id);
    }
  }
  return [...new Set(ids)];
}

function sizeTier(added: number, removed: number): RiskTier {
  const churn = added + removed;
  if (churn >= 800) return "high";
  if (churn >= 200) return "medium";
  return "low";
}

function heuristicFinding(partial: Omit<Finding, "schemaVersion" | "source">): Finding {
  return { schemaVersion: 1, source: "heuristic", ...partial };
}

/** Score the diff: risk tier, control IDs, and heuristic findings (secrets + missing packages). */
export async function analyzeDiff(diff: string, options: AnalyzeDiffOptions = {}): Promise<Heuristics> {
  const root = options.root ?? projectRoot();
  const controls = options.controls ?? loadControls(root);
  const inScope = options.inScopePaths ?? loadInScopePaths(root);
  const files = parseUnifiedDiff(diff);
  const paths = files.map((f) => f.path);
  const addedLines = files.reduce((n, f) => n + f.added.length, 0);
  const removedLines = files.reduce((n, f) => n + f.removed.length, 0);
  const hasTestChanges = paths.some(isTestPath);

  const sensitivePaths: string[] = [];
  const requiresTestsPaths: string[] = [];
  let riskTier: RiskTier = sizeTier(addedLines, removedLines);
  for (const file of paths) {
    const { sensitive, floor, requiresTests } = isSensitivePath(file);
    if (sensitive) {
      sensitivePaths.push(file);
      riskTier = raiseTier(riskTier, floor);
    }
    if (requiresTests) requiresTestsPaths.push(file);
  }

  const findings: Finding[] = [];
  const categories: string[] = [];

  // A008: secret-shaped added lines → critical finding + R-A008-HEURISTIC BLOCK.
  for (const file of files) {
    for (const line of file.added) {
      if (!looksLikeSecret(line)) continue;
      categories.push("secrets");
      riskTier = raiseTier(riskTier, "critical");
      findings.push(
        heuristicFinding({
          agent: "heuristic",
          category: "secrets",
          severity: "critical",
          control_ids: ["A008"],
          file: file.path,
          evidence: redactSecrets(line.trim()),
          recommendation: "Remove the credential from the diff, rotate it, and load it from a secret manager.",
          confidence: 0.9,
        }),
      );
    }
  }

  // B010.3: new deps that 404 on npm → critical finding + R-B010.3-HEURISTIC BLOCK.
  const newPackages = extractNewPackages(files);
  const missingPackages: string[] = [];
  const check = options.checkPackages !== false && newPackages.length > 0;
  const existsFn = options.packageExists ?? checkPackageExists;
  if (check) {
    for (const name of newPackages) {
      const result = await existsFn(name);
      if (result.error && result.status === 0) {
        findings.push(
          heuristicFinding({
            agent: "heuristic",
            category: "registry_unavailable",
            severity: "medium",
            control_ids: ["B010.3"],
            file: paths.find((p) => p.endsWith("package.json")) ?? "package.json",
            evidence: `Could not query npm for ${name}: ${result.error}`,
            recommendation: "Retry the registry check before shipping a new dependency.",
            confidence: 0.4,
          }),
        );
        continue;
      }
      if (!result.exists) {
        missingPackages.push(name);
        riskTier = raiseTier(riskTier, "high");
        findings.push(
          heuristicFinding({
            agent: "heuristic",
            category: "hallucinated_dependency",
            severity: "critical",
            control_ids: ["B010.3"],
            file: paths.find((p) => p.endsWith("package.json")) ?? "package.json",
            evidence: `npm registry returned ${result.status} for ${name}`,
            recommendation: `Do not add ${name}; it does not exist on the npm registry (AIUC-1 B010.3).`,
            confidence: 1,
          }),
        );
      }
    }
  }

  // Flag only — policy maps this to R-EU-AI-ACT (HUMAN_REVIEW), not a linter error.
  const possibleSubstantialModification = paths.some((file) =>
    inScope.some((prefix) => pathIncludesToken(file, prefix.replace(/\/$/, "")) || file.replaceAll("\\", "/").startsWith(prefix)),
  );
  if (possibleSubstantialModification) {
    riskTier = raiseTier(riskTier, "medium");
  }

  const findingCategories = [...new Set(findings.map((f) => f.category))];
  const controlIds = matchControlIds(paths, controls, findingCategories.includes("secrets") ? ["secrets"] : []);

  const diffHash = sha256(diff);
  const changeId = options.changeId ?? diffHash.slice(0, 12);

  return {
    changeId,
    diffHash,
    files: paths,
    addedLines,
    removedLines,
    riskTier,
    sensitivePaths,
    hasTestChanges,
    aiInvolvement: options.aiInvolvement ?? "assumed",
    possibleSubstantialModification,
    newPackages,
    missingPackages,
    controlIds,
    findings,
    requiresTestsPaths,
  };
}
