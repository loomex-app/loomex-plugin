#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, lstat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { TARGETS } from "./launch-mcp.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const release = process.argv.includes("--release");
const failures = [];

async function json(relative) {
  try {
    return JSON.parse(await readFile(path.join(root, relative), "utf8"));
  } catch (error) {
    failures.push(`${relative}: ${error.message}`);
    return null;
  }
}

async function text(relative) {
  try {
    return await readFile(path.join(root, relative), "utf8");
  } catch (error) {
    failures.push(`${relative}: ${error.message}`);
    return "";
  }
}

const plugin = await json(".codex-plugin/plugin.json");
const mcp = await json(".mcp.json");
const targets = await json("packaging/targets.json");
const template = await json("packaging/runtime-manifest.template.json");
const agentRunGuide = await text("skills/loomex/references/workflows-and-runs.md");
const setupGuide = await text("skills/loomex/references/setup-and-auth.md");
const architectureGuide = await text("skills/loomex/references/architecture.md");

if (plugin?.name !== "loomex" || plugin?.mcpServers !== "./.mcp.json") {
  failures.push("plugin.json must identify loomex and reference ./.mcp.json");
}
if (
  !plugin?.interface?.capabilities?.includes("Local AI agent runtimes") ||
  !plugin?.interface?.longDescription?.includes("Codex, Claude, or agy CLI") ||
  plugin?.interface?.longDescription?.includes("Gemini CLI")
) {
  failures.push("plugin.json must advertise the canonical Codex, Claude, and agy local agent runtimes");
}
if (
  !agentRunGuide.includes("`executor_version_unverified`") ||
  !agentRunGuide.includes("`upgrade_executor`, then `refresh_executor_discovery`") ||
  !agentRunGuide.includes("genuine workflow feature mismatch") ||
  !setupGuide.includes("Do not skip directly to refresh") ||
  !setupGuide.includes("safe local probe")
) {
  failures.push("agent runtime guidance must preserve the ordered local upgrade, refresh, probe, and heartbeat remediation");
}
if (
  !agentRunGuide.includes("For a Backend-owned `runner_job`, do not call an MCP tool to spawn or stop") ||
  !agentRunGuide.includes("`operationIdempotencyKey` identifies one user-authorized resume or cancel") ||
  !agentRunGuide.includes("`resume_exact_session`") ||
  !agentRunGuide.includes("`fresh_after_remediation`") ||
  !agentRunGuide.includes("job remains `deferred`, cancellation `completed`") ||
  !agentRunGuide.includes("`redispatch_via_runner_job`") ||
  !agentRunGuide.includes("atomic lease reclaim")
) {
  failures.push("agent control guidance must preserve Backend authorization, separate operation idempotency, successor modes, and daemon cancellation recovery");
}
if (
  !setupGuide.includes("configVersion = 3") ||
  !setupGuide.includes("agentRuntimeV2Enabled = true") ||
  !setupGuide.includes('legacyAgentTaskMode = "drain_only"') ||
  !setupGuide.includes("restart_runner_service") ||
  !agentRunGuide.includes("`legacy_drain`") ||
  !agentRunGuide.includes("`AGENT_V2_EXECUTION_OWNED`") ||
  !agentRunGuide.includes("`AGENT_TASK_SCHEMA_UNSUPPORTED`") ||
  !architectureGuide.includes("loomex.runner-agent-advertisement/v1") ||
  !architectureGuide.includes("`agent.task.v1.drain`") ||
  !architectureGuide.includes("`agentRuntimes` field is not JSON `null`")
) {
  failures.push("agent cutover guidance must preserve config v3 defaults, restart activation, advertisement omission rules, and fail-closed legacy draining");
}
if (
  mcp?.mcpServers?.loomex?.command !== "/bin/sh" ||
  mcp?.mcpServers?.loomex?.args?.[0] !== "./scripts/launch-mcp.sh" ||
  mcp?.mcpServers?.loomex?.cwd !== "."
) {
  failures.push(".mcp.json must launch the dependency-free POSIX adapter from plugin root");
}
if (JSON.stringify(targets?.artifacts ?? {}) !== JSON.stringify(TARGETS)) {
  failures.push("packaging/targets.json must exactly match the launcher target matrix");
}
if (
  template?.schemaVersion !== 1 ||
  template?.pluginVersion !== null ||
  template?.runtimeVersion !== plugin?.version?.split("+", 1)[0] ||
  !["stable", "beta"].includes(template?.channel) ||
  template?.distributionKind !== null ||
  template?.developmentOverridesAllowed !== false ||
  template?.linuxRuntimeContract?.libc !== "glibc" ||
  template?.linuxRuntimeContract?.minimumVersion !== "2.35"
) {
  failures.push("runtime manifest template must declare the base runtime version and packaged-release policy");
}
if (JSON.stringify(Object.keys(template?.artifacts ?? {}).sort()) !== JSON.stringify(Object.keys(TARGETS).sort())) {
  failures.push("runtime manifest template must exactly match the supported target matrix");
}

for (const [target, mcpPath] of Object.entries(TARGETS)) {
  const entry = template?.artifacts?.[target];
  const runtimePath = `bin/${target}/loomex`;
  if (
    entry?.path !== mcpPath ||
    entry?.sha256 !== null ||
    entry?.size !== null ||
    entry?.platformSignature !== null ||
    entry?.runtime?.path !== runtimePath ||
    entry?.runtime?.sha256 !== null ||
    entry?.runtime?.size !== null
  ) {
    failures.push(`runtime manifest template entry ${target} must describe both unsigned source artifacts`);
  }
}

for (const field of ["composerIcon", "logo", "logoDark"]) {
  const relative = plugin?.interface?.[field];
  if (typeof relative !== "string") {
    failures.push(`plugin.json interface.${field} is missing`);
    continue;
  }
  try {
    const bytes = await readFile(path.join(root, relative));
    if (!bytes.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex"))) {
      failures.push(`${relative} is not a PNG file`);
    }
  } catch (error) {
    failures.push(`${relative}: ${error.message}`);
  }
}

if (release) {
  const manifest = await json("packaging/runtime-manifest.json");
  if (manifest?.schemaVersion !== 1) failures.push("runtime manifest schemaVersion must be 1");
  if (manifest?.pluginVersion !== plugin?.version) failures.push("runtime manifest pluginVersion must match plugin.json");
  if (manifest?.runtimeVersion !== plugin?.version?.split("+", 1)[0]) failures.push("runtime manifest runtimeVersion must match plugin base version");
  const expectedDistribution = manifest?.packageSigningState === "unsigned-release" ? "release" : "validation";
  if (!["unsigned-validation", "unsigned-release"].includes(manifest?.packageSigningState)) {
    failures.push("runtime manifest packageSigningState must describe an unsigned validation or release package");
  }
  if (manifest?.distributionKind !== expectedDistribution || manifest?.developmentOverridesAllowed !== false) {
    failures.push("package distribution kind/signing state must agree and development overrides must be disabled");
  }
  if (manifest?.linuxRuntimeContract?.libc !== "glibc" || manifest?.linuxRuntimeContract?.minimumVersion !== "2.35") {
    failures.push("runtime manifest must declare the GLIBC 2.35 contract");
  }
  if (JSON.stringify(Object.keys(manifest?.artifacts ?? {}).sort()) !== JSON.stringify(Object.keys(TARGETS).sort())) {
    failures.push("runtime manifest must contain exactly the supported targets");
  }
  for (const [target, relative] of Object.entries(TARGETS)) {
    const entry = manifest?.artifacts?.[target];
    if (entry?.path !== relative || !/^[a-f0-9]{64}$/.test(entry?.sha256 ?? "")) {
      failures.push(`runtime manifest entry ${target} is incomplete`);
      continue;
    }
    const absolute = path.join(root, ...relative.split("/"));
    try {
      const info = await lstat(absolute);
      if (!info.isFile() || info.isSymbolicLink()) failures.push(`${relative} must be a regular non-link file`);
      if ((info.mode & 0o111) === 0) failures.push(`${relative} is not executable`);
      if (entry.size !== info.size) failures.push(`${relative} does not match its runtime manifest size`);
      const actual = createHash("sha256").update(await readFile(absolute)).digest("hex");
      if (actual !== entry.sha256) failures.push(`${relative} does not match its runtime manifest digest`);
      const sidecar = (await readFile(`${absolute}.sha256`, "ascii")).trim();
      if (sidecar !== entry.sha256) failures.push(`${relative}.sha256 does not match the runtime manifest`);
    } catch (error) {
      failures.push(`${relative}: ${error.message}`);
    }

    const runtimeRelative = `bin/${target}/loomex`;
    const runtimeEntry = entry?.runtime;
    if (runtimeEntry?.path !== runtimeRelative || !/^[a-f0-9]{64}$/.test(runtimeEntry?.sha256 ?? "")) {
      failures.push(`runtime manifest Runner entry ${target} is incomplete`);
      continue;
    }
    const runtimeAbsolute = path.join(root, ...runtimeRelative.split("/"));
    try {
      const info = await lstat(runtimeAbsolute);
      if (!info.isFile() || info.isSymbolicLink()) failures.push(`${runtimeRelative} must be a regular non-link file`);
      if ((info.mode & 0o111) === 0) failures.push(`${runtimeRelative} is not executable`);
      if (runtimeEntry.size !== info.size) failures.push(`${runtimeRelative} does not match its runtime manifest size`);
      const actual = createHash("sha256").update(await readFile(runtimeAbsolute)).digest("hex");
      if (actual !== runtimeEntry.sha256) failures.push(`${runtimeRelative} does not match its runtime manifest digest`);
      const sidecar = (await readFile(`${runtimeAbsolute}.sha256`, "ascii")).trim();
      if (sidecar !== runtimeEntry.sha256) failures.push(`${runtimeRelative}.sha256 does not match the runtime manifest`);
    } catch (error) {
      failures.push(`${runtimeRelative}: ${error.message}`);
    }
  }
}

if (failures.length) {
  process.stderr.write(`Loomex plugin package validation failed:\n- ${failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Loomex plugin package validation passed (${release ? "release" : "source"} mode).\n`);
}
