#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, realpath, lstat } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const TARGETS = Object.freeze({
  "darwin-arm64": "bin/darwin-arm64/loomex-mcp",
  "darwin-x64": "bin/darwin-x64/loomex-mcp",
  "linux-arm64": "bin/linux-arm64/loomex-mcp",
  "linux-x64": "bin/linux-x64/loomex-mcp",
});

export function targetKey(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  if (!(key in TARGETS)) {
    throw new Error(
      `Loomex does not yet provide loomex-mcp for ${platform}/${arch}. ` +
        `Supported targets: ${Object.keys(TARGETS).join(", ")}.`,
    );
  }
  return key;
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative);
}

async function assertExecutableFile(candidate, root, { allowOutsideRoot = false } = {}) {
  const info = await lstat(candidate);
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error(`Refusing to execute a non-regular or symbolic-link file: ${candidate}`);
  }

  const resolvedCandidate = await realpath(candidate);
  if (!allowOutsideRoot) {
    const resolvedRoot = await realpath(root);
    if (!isInside(resolvedRoot, resolvedCandidate)) {
      throw new Error(`Refusing to execute a binary outside the plugin root: ${candidate}`);
    }
  }

  if ((info.mode & 0o111) === 0) {
    throw new Error(`Bundled Loomex executable is not executable: ${candidate}`);
  }
  return resolvedCandidate;
}

async function sha256(file) {
  const bytes = await readFile(file);
  return createHash("sha256").update(bytes).digest("hex");
}

async function verifyArtifact(candidate, root, entry, expectedPath, label) {
  if (
    entry?.path !== expectedPath ||
    !Number.isSafeInteger(entry?.size) ||
    entry.size < 0 ||
    !/^[a-f0-9]{64}$/.test(entry?.sha256 ?? "")
  ) {
    throw new Error(`The Loomex runtime manifest has no valid ${label} entry.`);
  }

  let executable;
  try {
    executable = await assertExecutableFile(candidate, root);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `The Loomex plugin package does not contain ${expectedPath}. ` +
          "Reinstall the packaged plugin release. Source checkouts require explicit development binaries.",
        { cause: error },
      );
    }
    throw error;
  }

  const info = await lstat(executable);
  if (info.size !== entry.size) {
    throw new Error(`Integrity check failed for bundled ${expectedPath}; refusing to execute it.`);
  }
  const actual = await sha256(executable);
  if (actual !== entry.sha256) {
    throw new Error(`Integrity check failed for bundled ${expectedPath}; refusing to execute it.`);
  }
  return executable;
}

async function loadRuntimeManifest(root) {
  const manifestPath = path.join(root, "packaging", "runtime-manifest.json");
  let payload;
  try {
    payload = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(
      `The Loomex release integrity manifest is missing or invalid at ${manifestPath}. ` +
        "Reinstall the Loomex plugin from its packaged release.",
      { cause: error },
    );
  }
  if (payload?.schemaVersion !== 1 || typeof payload?.artifacts !== "object") {
    throw new Error(`Unsupported Loomex runtime manifest: ${manifestPath}`);
  }
  return payload;
}

export async function resolveBundledBinary(
  root,
  { platform = process.platform, arch = process.arch } = {},
) {
  return (await resolveBundledArtifacts(root, { platform, arch })).mcp;
}

export async function resolveBundledArtifacts(
  root,
  { platform = process.platform, arch = process.arch } = {},
) {
  const key = targetKey(platform, arch);
  const relativePath = TARGETS[key];
  const candidate = path.join(root, ...relativePath.split("/"));
  const runtimePath = `bin/${key}/loomex`;
  const runtimeCandidate = path.join(root, ...runtimePath.split("/"));
  const manifest = await loadRuntimeManifest(root);
  const artifact = manifest.artifacts[key];
  return {
    mcp: await verifyArtifact(candidate, root, artifact, relativePath, `${key} MCP`),
    runtime: await verifyArtifact(
      runtimeCandidate,
      root,
      artifact?.runtime,
      runtimePath,
      `${key} Runner runtime`,
    ),
  };
}

export async function resolveDevelopmentBinary(root, env = process.env) {
  const override = env.LOOMEX_MCP_BINARY;
  if (!override) return null;
  try {
    const manifest = JSON.parse(
      await readFile(path.join(root, "packaging", "runtime-manifest.json"), "utf8"),
    );
    if (manifest?.distributionKind === "release" || manifest?.developmentOverridesAllowed === false) {
      throw new Error("Development binary overrides are disabled in packaged Loomex releases.");
    }
    throw new Error("A packaged Loomex runtime manifest may not enable development overrides.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (env.LOOMEX_ALLOW_DEVELOPMENT_BINARY !== "1") {
    throw new Error(
      "LOOMEX_MCP_BINARY is set, but development overrides require LOOMEX_ALLOW_DEVELOPMENT_BINARY=1.",
    );
  }
  if (!path.isAbsolute(override)) {
    throw new Error("LOOMEX_MCP_BINARY must be an absolute path.");
  }
  return assertExecutableFile(override, root, { allowOutsideRoot: true });
}

export async function main() {
  const scriptPath = fileURLToPath(import.meta.url);
  const pluginRoot = path.resolve(path.dirname(scriptPath), "..");
  const development = await resolveDevelopmentBinary(pluginRoot);
  const bundled = development ? null : await resolveBundledArtifacts(pluginRoot);
  const executable = development ?? bundled?.mcp;

  const child = spawn(executable, process.argv.slice(2), {
    cwd: pluginRoot,
    env: {
      ...process.env,
      LOOMEX_PLUGIN_ROOT: pluginRoot,
      ...(bundled ? { LOOMEX_RUNNER_BINARY: bundled.runtime } : {}),
    },
    stdio: "inherit",
    windowsHide: true,
  });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  }

  child.once("error", (error) => {
    process.stderr.write(`Unable to start Loomex MCP: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.once("exit", (code, signal) => {
    if (signal) {
      process.stderr.write(`Loomex MCP exited after ${signal}.\n`);
      process.exitCode = 1;
    } else {
      process.exitCode = code ?? 1;
    }
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`Unable to start Loomex MCP: ${error.message}\n`);
    process.exitCode = 1;
  });
}
