import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, mkdir, readFile, writeFile, chmod, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  TARGETS,
  resolveBundledArtifacts,
  resolveBundledBinary,
  resolveDevelopmentBinary,
  targetKey,
} from "../scripts/launch-mcp.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("target matrix is explicit and rejects unsupported systems", () => {
  assert.equal(targetKey("darwin", "arm64"), "darwin-arm64");
  assert.equal(targetKey("linux", "x64"), "linux-x64");
  assert.throws(() => targetKey("win32", "x64"), /does not yet provide/);
  assert.throws(() => targetKey("freebsd", "x64"), /does not yet provide/);
  assert.equal(Object.keys(TARGETS).length, 4);
});

test("development override is explicit, absolute, regular, and executable", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "loomex-launcher-"));
  const binary = path.join(directory, "loomex-mcp-dev");
  await writeFile(binary, "#!/bin/sh\nexit 0\n");
  await chmod(binary, 0o700);

  await assert.rejects(
    resolveDevelopmentBinary(root, { LOOMEX_MCP_BINARY: binary }),
    /require LOOMEX_ALLOW_DEVELOPMENT_BINARY=1/,
  );
  await assert.rejects(
    resolveDevelopmentBinary(root, {
      LOOMEX_MCP_BINARY: "relative/loomex-mcp",
      LOOMEX_ALLOW_DEVELOPMENT_BINARY: "1",
    }),
    /must be an absolute path/,
  );
  assert.equal(
    await resolveDevelopmentBinary(root, {
      LOOMEX_MCP_BINARY: binary,
      LOOMEX_ALLOW_DEVELOPMENT_BINARY: "1",
    }),
    await realpath(binary),
  );
});

test("bundled binary must match its release digest", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "loomex-bundle-"));
  const binary = path.join(directory, "bin", "darwin-arm64", "loomex-mcp");
  const runtime = path.join(directory, "bin", "darwin-arm64", "loomex");
  await mkdir(path.dirname(binary), { recursive: true });
  await mkdir(path.join(directory, "packaging"));
  await writeFile(binary, "real-test-bytes");
  await writeFile(runtime, "real-runtime-bytes");
  await chmod(binary, 0o700);
  await chmod(runtime, 0o700);
  await writeFile(
    path.join(directory, "packaging", "runtime-manifest.json"),
    JSON.stringify({
      schemaVersion: 1,
      artifacts: {
        "darwin-arm64": {
          path: TARGETS["darwin-arm64"],
          size: 15,
          sha256: "0".repeat(64),
          runtime: {
            path: "bin/darwin-arm64/loomex",
            size: 18,
            sha256: createHash("sha256").update("real-runtime-bytes").digest("hex"),
          },
        },
      },
    }),
  );

  await assert.rejects(
    resolveBundledBinary(directory, { platform: "darwin", arch: "arm64" }),
    /Integrity check failed/,
  );
});

test("bundled Runner must also match its release digest", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "loomex-runtime-bundle-"));
  const targetDirectory = path.join(directory, "bin", "linux-x64");
  const binary = path.join(targetDirectory, "loomex-mcp");
  const runtime = path.join(targetDirectory, "loomex");
  await mkdir(targetDirectory, { recursive: true });
  await mkdir(path.join(directory, "packaging"));
  const mcpBytes = "mcp-test-bytes";
  const runtimeBytes = "runtime-test-bytes";
  await writeFile(binary, mcpBytes);
  await writeFile(runtime, runtimeBytes);
  await chmod(binary, 0o700);
  await chmod(runtime, 0o700);
  await writeFile(
    path.join(directory, "packaging", "runtime-manifest.json"),
    JSON.stringify({
      schemaVersion: 1,
      artifacts: {
        "linux-x64": {
          path: TARGETS["linux-x64"],
          size: Buffer.byteLength(mcpBytes),
          sha256: createHash("sha256").update(mcpBytes).digest("hex"),
          runtime: {
            path: "bin/linux-x64/loomex",
            size: Buffer.byteLength(runtimeBytes),
            sha256: "0".repeat(64),
          },
        },
      },
    }),
  );

  await assert.rejects(
    resolveBundledArtifacts(directory, { platform: "linux", arch: "x64" }),
    /Integrity check failed for bundled bin\/linux-x64\/loomex/,
  );
});

test("launcher propagates a development binary exit code", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "loomex-exit-"));
  const binary = path.join(directory, "loomex-mcp-dev");
  await writeFile(binary, "#!/bin/sh\nexit 23\n");
  await chmod(binary, 0o700);
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "launch-mcp.mjs")], {
    env: {
      ...process.env,
      LOOMEX_MCP_BINARY: binary,
      LOOMEX_ALLOW_DEVELOPMENT_BINARY: "1",
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 23, result.stderr);
});

test("release shell launcher ignores development overrides", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "loomex-release-launcher-"));
  await mkdir(path.join(directory, "scripts"));
  await mkdir(path.join(directory, "packaging"));
  const key = targetKey();
  const targetDirectory = path.join(directory, "bin", key);
  await mkdir(targetDirectory, { recursive: true });
  const launcher = path.join(directory, "scripts", "launch-mcp.sh");
  await copyFile(path.join(root, "scripts", "launch-mcp.sh"), launcher);
  await chmod(launcher, 0o755);
  await writeFile(path.join(directory, "packaging", "runtime-manifest.json"), "{}\n");
  const mcp = path.join(targetDirectory, "loomex-mcp");
  const runtime = path.join(targetDirectory, "loomex");
  const override = path.join(directory, "override");
  await writeFile(mcp, "#!/bin/sh\nexit 17\n");
  await writeFile(runtime, "#!/bin/sh\nexit 0\n");
  await writeFile(override, "#!/bin/sh\nexit 99\n");
  for (const binary of [mcp, runtime, override]) await chmod(binary, 0o755);
  for (const binary of [mcp, runtime]) {
    const bytes = await readFile(binary);
    await writeFile(`${binary}.sha256`, `${createHash("sha256").update(bytes).digest("hex")}\n`);
  }
  await writeFile(
    path.join(directory, "packaging", "runtime-manifest.json"),
    JSON.stringify({ distributionKind: "release", developmentOverridesAllowed: false }),
  );
  await assert.rejects(
    resolveDevelopmentBinary(directory, {
      LOOMEX_MCP_BINARY: override,
      LOOMEX_ALLOW_DEVELOPMENT_BINARY: "1",
    }),
    /disabled in packaged Loomex releases/,
  );
  const result = spawnSync("/bin/sh", [launcher], {
    env: {
      ...process.env,
      LOOMEX_MCP_BINARY: override,
      LOOMEX_ALLOW_DEVELOPMENT_BINARY: "1",
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 17, result.stderr);
});
