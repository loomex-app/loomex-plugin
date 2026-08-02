import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(root, "../..");

test("browser runtime metadata is fixed and covers all supported launcher platforms", () => {
  const output = execFileSync(process.execPath, [
    path.join(root, "scripts", "validate-browser-runtime.mjs"),
  ], { encoding: "utf8" });
  assert.match(output, /passed \(source mode\)/);
});

test("browser capability contains no mutable package downloader", async () => {
  const source = await readFile(
    path.join(repositoryRoot, "crates", "loomex-core", "src", "local_capabilities.rs"),
    "utf8",
  );
  assert.doesNotMatch(source, /\bnpx\b/);
  assert.match(source, /BROWSER_RUNTIME_CHECKSUM_MISMATCH/);
  assert.match(source, /playwrightVersion/);
});

test("release browser validation fails closed when artifacts are absent", () => {
  const result = spawnSync(process.execPath, [
    path.join(root, "scripts", "validate-browser-runtime.mjs"), "--release",
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Browser runtime validation failed/);
});
