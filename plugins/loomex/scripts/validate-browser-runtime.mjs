#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const release = process.argv.includes("--release");
const expectedTargets = [
  "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "windows-arm64", "windows-x64",
];
const failures = [];

async function load(relative) {
  try {
    return JSON.parse(await readFile(path.join(root, relative), "utf8"));
  } catch (error) {
    failures.push(`${relative}: ${error.message}`);
    return null;
  }
}

const template = await load("packaging/browser-runtime.template.json");
if (
  template?.schemaVersion !== 1 ||
  template?.playwrightVersion !== "1.51.1" ||
  template?.provenance?.package !== "playwright" ||
  template?.provenance?.version !== template?.playwrightVersion ||
  template?.provenance?.browser !== "chromium"
) {
  failures.push("browser runtime must pin Playwright version 1.51.1");
}
if (JSON.stringify(Object.keys(template?.artifacts ?? {}).sort()) !== JSON.stringify(expectedTargets)) {
  failures.push("browser runtime must cover macOS, Windows, and Linux arm64/x64 targets");
}
for (const target of expectedTargets) {
  const entry = template?.artifacts?.[target];
  const extension = target.startsWith("windows-") ? ".exe" : "";
  if (entry?.launcher?.path !== `browser/${target}/playwright${extension}`) {
    failures.push(`${target} launcher path is not deterministic`);
  }
  for (const browser of ["chromium", "firefox", "webkit"]) {
    if (entry?.browsers?.[browser]?.path !== `browser/${target}/${browser}${extension}`) {
      failures.push(`${target} ${browser} path is not deterministic`);
    }
  }
  for (const artifact of [
    entry?.launcher,
    entry?.browsers?.chromium,
    entry?.browsers?.firefox,
    entry?.browsers?.webkit,
  ]) {
    if (artifact?.sha256 !== null || artifact?.size !== null) {
      failures.push(`${target} source template must leave release checksums unset`);
    }
  }
}

if (release) {
  const manifest = await load("packaging/browser-runtime.json");
  if (
    manifest?.schemaVersion !== 1 ||
    manifest?.playwrightVersion !== template?.playwrightVersion ||
    JSON.stringify(manifest?.provenance) !== JSON.stringify(template?.provenance)
  ) {
    failures.push("browser runtime release manifest must preserve the pinned Playwright version");
  }
  for (const target of expectedTargets) {
    const entry = manifest?.artifacts?.[target];
    for (const [label, artifact] of [
      ["launcher", entry?.launcher],
      ["chromium", entry?.browsers?.chromium],
      ["firefox", entry?.browsers?.firefox],
      ["webkit", entry?.browsers?.webkit],
    ]) {
      if (!artifact?.path || !/^[a-f0-9]{64}$/.test(artifact.sha256 ?? "") || !Number.isSafeInteger(artifact.size)) {
        failures.push(`${target} ${label} release artifact metadata is incomplete`);
        continue;
      }
      const absolute = path.join(root, artifact.path);
      try {
        const info = await lstat(absolute);
        if (!info.isFile() || info.isSymbolicLink() || info.size !== artifact.size) {
          failures.push(`${artifact.path} must be a regular file with the manifest size`);
          continue;
        }
        const actual = createHash("sha256").update(await readFile(absolute)).digest("hex");
        if (actual !== artifact.sha256) failures.push(`${artifact.path} checksum mismatch`);
      } catch (error) {
        failures.push(`${artifact.path}: ${error.message}`);
      }
    }
  }
}

if (failures.length) {
  process.stderr.write(`Browser runtime validation failed:\n- ${failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Browser runtime validation passed (${release ? "release" : "source"} mode).\n`);
}
