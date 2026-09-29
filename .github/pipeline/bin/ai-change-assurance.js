#!/usr/bin/env node
/**
 * CLI entry. `npm ci` links this as `ai-change-assurance`.
 * It runs src/index.ts, which calls @cursor/sdk Agent.create for the
 * engineering and compliance agents and writes the evidence bundle.
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");
const child = spawn(
  process.execPath,
  [tsxCli, path.join(root, "src/index.ts"), ...process.argv.slice(2)],
  { stdio: "inherit", env: process.env },
);

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
