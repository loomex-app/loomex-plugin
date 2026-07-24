import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const tools = [
  "loomex_setup_status", "loomex_setup_plan", "loomex_setup_apply", "loomex_setup_rollback",
  "loomex_auth_status", "loomex_auth_start", "loomex_auth_wait", "loomex_auth_logout",
  "loomex_org_list", "loomex_org_select", "loomex_project_list", "loomex_project_select",
  "loomex_binding_list", "loomex_binding_create", "loomex_binding_revoke",
  "loomex_workflow_list", "loomex_workflow_show", "loomex_workflow_run",
  "loomex_run_list", "loomex_run_get", "loomex_run_wait", "loomex_run_cancel",
  "loomex_human_list", "loomex_human_open", "loomex_human_respond",
  "loomex_agent_task_list", "loomex_agent_task_respond",
  "loomex_approval_list", "loomex_approval_decide",
  "loomex_runner_status", "loomex_runner_control", "loomex_runner_doctor", "loomex_runner_logs",
];

test("skill exposes the settled MCP tool contract exactly", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  assert.equal(tools.length, 33);
  for (const name of tools) assert.match(skill, new RegExp(`\\b${name}\\b`), name);
  assert.doesNotMatch(skill, /loomex_organization_|loomex_human_request_/);
});

test("plugin exposes focused child skills for the main Loomex task areas", async () => {
  const childSkills = ["setup", "scope", "workflow", "runs", "human"];
  for (const name of childSkills) {
    const child = await readFile(path.join(root, "skills", name, "SKILL.md"), "utf8");
    assert.match(child, new RegExp(`^name: ${name}$`, "m"));
    assert.doesNotMatch(child, /\[TODO:/);
  }
  const router = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  for (const name of childSkills) assert.match(router, new RegExp(`\\b${name}\\b`));
});

test("documentation states durable execution and the closed-Codex limitation", async () => {
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const architecture = await readFile(
    path.join(root, "skills", "loomex", "references", "architecture.md"),
    "utf8",
  );
  assert.match(readme, /Closing or\s+restarting Codex therefore does not cancel/);
  assert.match(readme, /cannot display a new question while the Codex application is closed/);
  assert.match(architecture, /Tauri client is another\s+supported surface/);
  assert.match(architecture, /adapter uses two local routes/);
  assert.match(architecture, /Workflow\/run\/HITL\/approval calls use the authenticated durable-service\s+socket/);
});

test("references use the implemented public MCP argument contract", async () => {
  const setup = await readFile(
    path.join(root, "skills", "loomex", "references", "setup-and-auth.md"),
    "utf8",
  );
  const binding = await readFile(
    path.join(root, "skills", "loomex", "references", "workspace-binding.md"),
    "utf8",
  );
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const human = await readFile(
    path.join(root, "skills", "loomex", "references", "human-and-approvals.md"),
    "utf8",
  );
  const runner = await readFile(
    path.join(root, "skills", "loomex", "references", "runner-operations.md"),
    "utf8",
  );

  assert.match(setup, /returned `planId`, exact returned `channel` and `installService`/);
  assert.match(setup, /exact `targetVersion` and `confirm: true`/);
  assert.match(setup, /returned `loginId`/);
  assert.match(setup, /state-changing operation/);
  assert.doesNotMatch(setup, /recovery token|flow ID/);
  assert.match(binding, /`workspacePath`/);
  assert.match(binding, /`projectId`, exact `bindingId`, and `confirm: true`/);
  assert.match(runs, /`loomex_run_list` currently requires `workflowId`/);
  assert.match(runs, /send it back as `afterSequence`/);
  assert.match(runs, /optional `version`/);
  assert.match(runs, /required `workflowId`, `bindingId`, and `idempotencyKey`/);
  assert.match(runs, /required `executionId`,\s+a non-empty audit `reason`, and `idempotencyKey`/);
  assert.match(human, /public `response` field/);
  assert.match(human, /filtered by `workflowId`, `executionId`/);
  assert.match(human, /returned `nextCursor`/);
  assert.match(human, /public `approvalId`/);
  assert.doesNotMatch(human, /answer in the public `payload`/);
  assert.match(runner, /optional `level`/);
  assert.match(runner, /does not accept time-range or run-ID filters/);
});

test("retryable management failures recover state before considering restart", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const runner = await readFile(
    path.join(root, "skills", "loomex", "references", "runner-operations.md"),
    "utf8",
  );
  const human = await readFile(
    path.join(root, "skills", "loomex", "references", "human-and-approvals.md"),
    "utf8",
  );
  const architecture = await readFile(
    path.join(root, "skills", "loomex", "references", "architecture.md"),
    "utf8",
  );

  assert.match(skill, /retryable management or wait transport failures as unknown state/);
  assert.match(skill, /`loomex_run_get` using the authoritative execution ID/);
  assert.match(skill, /Do not recommend restarting the Runner unless\s+`loomex_runner_status` or `loomex_runner_doctor`/);
  assert.match(runs, /`MANAGEMENT_HTTP_FAILED`[\s\S]*latest run state is unknown/);
  assert.match(runs, /small bounded\s+number of status attempts/);
  assert.match(runs, /Do not restart the Runner merely because a management request failed three\s+times/);
  assert.match(runs, /dispatch timeout is a terminal backend result/);
  assert.match(runs, /Restarting the Runner cannot continue that same terminal execution/);
  assert.match(runner, /Recommend restart only\s+when status or doctor identifies an unhealthy local service/);
  assert.match(runner, /`RUNNER_IDENTITY_MISMATCH`/);
  assert.match(runner, /Never silently re-register, rebind, delete\s+credentials, or replace identity state/);
  assert.match(human, /`resolved` response confirms the human request, not the\s+workflow's later state/);
  assert.match(human, /follow the `loomex_run_get` recovery flow/);
  assert.match(architecture, /does not restart a healthy Runner to force a\s+reconnect/);
});

test("source package contains no fake bundled executable", async () => {
  await assert.rejects(readdir(path.join(root, "bin")), /ENOENT/);
  const template = JSON.parse(
    await readFile(path.join(root, "packaging", "runtime-manifest.template.json"), "utf8"),
  );
  assert.deepEqual(Object.keys(template.artifacts).sort(), [
    "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64",
  ]);
  for (const [target, entry] of Object.entries(template.artifacts)) {
    assert.equal(entry.sha256, null);
    assert.equal(entry.size, null);
    assert.equal(entry.platformSignature, null);
    assert.equal(entry.runtime.path, `bin/${target}/loomex`);
    assert.equal(entry.runtime.sha256, null);
    assert.equal(entry.runtime.size, null);
  }
});

test("MCP startup has no host Node dependency", async () => {
  const mcp = JSON.parse(await readFile(path.join(root, ".mcp.json"), "utf8"));
  assert.equal(mcp.mcpServers.loomex.command, "/bin/sh");
  assert.deepEqual(mcp.mcpServers.loomex.args, ["./scripts/launch-mcp.sh"]);
});

test("one-install documentation requires both bundled native artifacts", async () => {
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const packaging = await readFile(path.join(root, "packaging", "README.md"), "utf8");
  assert.match(readme, /both the `loomex-mcp` adapter\s+and the matching, verified Loomex Runner runtime/);
  assert.match(packaging, /includes every supported\s+macOS\/Linux MCP adapter and Runner pair/);
  assert.match(packaging, /does not ask the user to obtain a second installer/);
  assert.doesNotMatch(readme, /Windows/);
});

test("natural Loomex requests automatically enter first-use onboarding", async () => {
  const manifest = JSON.parse(
    await readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8"),
  );
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  const setup = await readFile(
    path.join(root, "skills", "loomex", "references", "setup-and-auth.md"),
    "utf8",
  );
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const installer = await readFile(path.join(root, "scripts", "install-codex.sh"), "utf8");

  assert.equal(manifest.version, "0.1.21");
  assert.match(manifest.interface.longDescription, /automatically checks first-use readiness/);
  assert.match(manifest.interface.defaultPrompt.join("\n"), /setup should start automatically/);
  assert.match(skill, /For every natural-language Loomex request/);
  assert.match(skill, /immediately call the read-only\s+`loomex_setup_plan`/);
  assert.match(skill, /ask for approval\s+only before `loomex_setup_apply`/i);
  assert.match(skill, /resume the user's\s+original request/);
  assert.match(setup, /Never tell the user to type a setup phrase/);
  assert.match(readme, /No special setup prompt is\s+needed/);
  assert.match(installer, /ask for any Loomex workflow naturally/);
});

test("plugin has no default SessionStart hook and authenticates on first use", async () => {
  const manifest = JSON.parse(
    await readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8"),
  );
  const marketplace = JSON.parse(
    await readFile(path.join(root, "packaging", "marketplace.template.json"), "utf8"),
  );
  assert.equal(Object.hasOwn(manifest, "hooks"), false);
  await assert.rejects(readdir(path.join(root, "hooks")), /ENOENT/);
  assert.equal(marketplace.plugins[0].policy.authentication, "ON_USE");
});
