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
  "loomex_agent_runtime_status", "loomex_agent_task_execute",
  "loomex_agent_task_resume", "loomex_agent_task_cancel",
  "loomex_agent_task_checkpoint",
  "loomex_approval_list", "loomex_approval_decide",
  "loomex_runner_status", "loomex_runner_control", "loomex_runner_doctor", "loomex_runner_logs",
];

test("skill exposes the settled MCP tool contract exactly", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  assert.equal(tools.length, 38);
  for (const name of tools) assert.match(skill, new RegExp(`\\b${name}\\b`), name);
  assert.doesNotMatch(skill, /loomex_organization_|loomex_human_request_/);
});

test("local agent runtime documentation is exact, safe, and migration compatible", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const architecture = await readFile(
    path.join(root, "skills", "loomex", "references", "architecture.md"),
    "utf8",
  );
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const packaging = await readFile(path.join(root, "packaging", "README.md"), "utf8");
  const manifest = JSON.parse(
    await readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8"),
  );

  assert.match(skill, /`loomex\.plugin-agent-task\/v2`/);
  assert.match(skill, /legacy v1 tasks/);
  assert.match(runs, /`open_ai` \/ `codex_cli`/);
  assert.match(runs, /`anthropic` \/ `claude_cli`/);
  assert.match(runs, /`google` \/ `agy_cli`/);
  assert.match(runs, /Gemini-compatible models must be launched through `agy`/);
  assert.match(runs, /`exact`[\s\S]*`auto`[\s\S]*ordered fallback/);
  assert.match(runs, /`provider_not_installed`/);
  assert.match(runs, /`provider_not_authenticated`/);
  assert.match(runs, /`model_unknown` or `model_not_available`/);
  assert.match(runs, /`executor_version_unverified`/);
  assert.match(runs, /`upgrade_executor`, then `refresh_executor_discovery`/);
  assert.match(runs, /genuine workflow feature mismatch[\s\S]*`reconfigure_workflow`/);
  assert.match(runs, /`execution_indeterminate`/);
  assert.match(runs, /`session_not_found` or `session_mismatch`/);
  assert.match(runs, /Continue to list and respond to v1 tasks/);
  assert.match(architecture, /passes `requestId` plus an\s+idempotency key/);
  assert.doesNotMatch(`${skill}\n${runs}\n${architecture}\n${readme}`, /`gemini_cli` as supported/);
  assert.ok(manifest.interface.capabilities.includes("Local AI agent runtimes"));
  assert.match(manifest.interface.longDescription, /Codex, Claude, or agy CLI/);
  assert.match(readme, /Codex sees exactly 38 tools/);
  assert.match(readme, /`runner\.v1` transport/);
  assert.match(packaging, /publication is blocked until that authoritative source\s+is merged and tagged `v0\.2\.0`/);
});

test("runner-owned agent successor and cancellation guidance matches the durable control boundary", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  const child = await readFile(path.join(root, "skills", "workflow", "SKILL.md"), "utf8");
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const architecture = await readFile(
    path.join(root, "skills", "loomex", "references", "architecture.md"),
    "utf8",
  );
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const combined = `${skill}\n${child}\n${runs}\n${architecture}\n${readme}`;

  assert.match(runs, /For a Backend-owned `runner_job`, do not call an MCP tool to spawn or stop/);
  assert.match(runs, /`AGENT_RUNNER_JOB_OWNED`/);
  assert.match(runs, /`operationIdempotencyKey` identifies one user-authorized resume or cancel/);
  assert.match(runs, /Never copy, derive, or reuse a task or delivery key as an\s+`operationIdempotencyKey`/);
  assert.match(runs, /`taskIdempotencyKey`[\s\S]*`deliveryIdempotencyKey`[\s\S]*`operationIdempotencyKey`/);
  assert.match(runs, /`resume_exact_session`[\s\S]*`retry_same_selection`[\s\S]*`retry_unresolved_selection`/);
  assert.match(runs, /`fresh_after_remediation`/);
  assert.match(runs, /`resume_from_checkpoint`/);
  assert.match(runs, /successful resume receipt has `controlState: queued`/);
  assert.match(runs, /job remains `deferred`, cancellation `completed`/);
  assert.match(runs, /may become `cancelled`[\s\S]*may already have `completed`[\s\S]*may become `indeterminate`/);
  assert.match(runs, /`PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED`[\s\S]*`redispatch_via_runner_job`/);
  assert.match(runs, /durably reserves it before signaling[\s\S]*runner\s+authentication/);
  assert.match(runs, /atomic lease reclaim[\s\S]*incremented lease fence/);
  assert.match(combined, /authenticated user/);
  assert.match(combined, /MCP (?:never|does not|must not) spawn/);
  assert.doesNotMatch(combined, /MCP (?:kills|signals) Backend-owned/);
});

test("agent cutover documentation pins config v3, advertisement, and legacy drain semantics", async () => {
  const skill = await readFile(path.join(root, "skills", "loomex", "SKILL.md"), "utf8");
  const child = await readFile(path.join(root, "skills", "workflow", "SKILL.md"), "utf8");
  const setupChild = await readFile(path.join(root, "skills", "setup", "SKILL.md"), "utf8");
  const setup = await readFile(
    path.join(root, "skills", "loomex", "references", "setup-and-auth.md"),
    "utf8",
  );
  const runner = await readFile(
    path.join(root, "skills", "loomex", "references", "runner-operations.md"),
    "utf8",
  );
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const architecture = await readFile(
    path.join(root, "skills", "loomex", "references", "architecture.md"),
    "utf8",
  );
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const combined = `${skill}\n${child}\n${setupChild}\n${setup}\n${runner}\n${runs}\n${architecture}\n${readme}`;

  assert.match(setup, /configVersion = 3/);
  assert.match(setup, /agentRuntimeV2Enabled = true/);
  assert.match(setup, /legacyAgentTaskMode = "drain_only"/);
  assert.match(setup, /defaults to `true`/);
  assert.match(setup, /defaults\s+to `"drain_only"`/);
  assert.match(setup, /loomex config set agentRuntimeV2Enabled false/);
  assert.match(setup, /loomex config set legacyAgentTaskMode disabled/);
  assert.match(setup, /`serviceRestartRequired: true`/);
  assert.match(setup, /`nextAction: "restart_runner_service"`/);
  assert.match(setup, /`action: "restart"` and `confirm: true`/);
  assert.match(setup, /new Runner\s+session\/heartbeat/);
  assert.match(architecture, /loomex\.runner-agent-advertisement\/v1/);
  assert.match(architecture, /`true` \| `drain_only`[\s\S]*`true` \| `disabled`[\s\S]*`false` \| `drain_only`[\s\S]*`false` \| `disabled`/);
  assert.match(architecture, /`agent\.runtime\.v2`/);
  assert.match(architecture, /`agent\.task\.v1\.drain`/);
  assert.match(architecture, /`agentRuntimes` field is not JSON `null`/);
  assert.match(architecture, /remains inside `runner\.v1`/);
  assert.match(runs, /v1 with `legacyAgentTaskMode: "drain_only"` is `legacy_drain`/);
  assert.match(runs, /v1 with legacy mode `disabled` is `disabled`/);
  assert.match(runs, /missing or unknown schema is `unsupported`/);
  assert.match(runs, /`AGENT_LEGACY_TASKS_DISABLED`/);
  assert.match(runs, /`AGENT_V2_EXECUTION_OWNED`/);
  assert.match(runs, /`AGENT_LEGACY_RESPONSE_FORBIDDEN`/);
  assert.match(runs, /`AGENT_TASK_SCHEMA_UNSUPPORTED`/);
  assert.match(runs, /`AGENT_RUNTIME_V2_DISABLED`/);
  assert.match(combined, /Drain mode never authorizes\s+new v1 emission|`drain_only` never permits Backend to create new v1 tasks/);
  assert.match(combined, /Executable refresh remains\s+restart-free|executable discovery[\s\S]*does not\s+require a restart/);
});

test("plugin exposes only the supported focused child skills", async () => {
  const childSkills = ["setup", "workflow"];
  for (const name of childSkills) {
    const child = await readFile(path.join(root, "skills", name, "SKILL.md"), "utf8");
    assert.match(child, new RegExp(`^name: ${name}$`, "m"));
    assert.doesNotMatch(child, /\[TODO:/);
  }
  const skillDirectories = (await readdir(path.join(root, "skills"), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(skillDirectories, ["loomex", "setup", "workflow"]);
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

test("agent executable refresh is local, approved, canonical, and PATH-safe", async () => {
  const setup = await readFile(
    path.join(root, "skills", "loomex", "references", "setup-and-auth.md"),
    "utf8",
  );
  const runs = await readFile(
    path.join(root, "skills", "loomex", "references", "workflows-and-runs.md"),
    "utf8",
  );
  const runner = await readFile(
    path.join(root, "skills", "loomex", "references", "runner-operations.md"),
    "utf8",
  );
  const child = await readFile(path.join(root, "skills", "setup", "SKILL.md"), "utf8");
  const readme = await readFile(path.join(root, "README.md"), "utf8");
  const combined = `${setup}\n${runs}\n${runner}\n${child}\n${readme}`;

  assert.match(setup, /loomex setup agents refresh --confirm/);
  assert.match(setup, /--provider codex\|claude\|agy/);
  assert.match(setup, /--path ABSOLUTE_CANONICAL_PATH/);
  assert.match(setup, /`--provider` and `--path` must appear together/);
  assert.match(setup, /`AGENT_EXECUTABLE_REFRESH_PATH_PAIR_REQUIRED`/);
  assert.match(setup, /creates an initial executable snapshot only when\s+`agent-executables\.json` does not exist/);
  assert.match(setup, /repeated setup\/apply, repair, or\s+plugin-control call preserves the existing file/);
  assert.match(setup, /only the\s+local interactive refresh command below may change executable discovery/);
  assert.match(setup, /Do not use\s+`--non-interactive`/);
  assert.match(setup, /~\/\.loomex\/agent-executables\.json/);
  assert.match(setup, /No Runner restart is required/);
  assert.match(setup, /call `loomex_agent_runtime_status`[\s\S]*next Runner heartbeat/);
  assert.match(runs, /`refresh_executor_discovery`/);
  assert.match(setup, /`executor_version_unverified`/);
  assert.match(setup, /`upgrade_executor`, then\s+`refresh_executor_discovery`/);
  assert.match(setup, /Do not skip directly to refresh/);
  assert.match(setup, /installer exit\s+alone[\s\S]*safe local probe/);
  assert.match(combined, /never accepts an upgrade command or executable path from Backend, MCP/);
  assert.match(combined, /GUI[\s\S]*`PATH`/);
  assert.match(combined, /Runner never searches its daemon `PATH`/);
  assert.match(combined, /Backend\/MCP requests cannot provide\s+executable paths/);
  assert.doesNotMatch(combined, /Backend-supplied executable path|daemon PATH discovery/);
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
  assert.match(packaging, /users do not obtain\s+a second installer/);
  assert.doesNotMatch(readme, /Windows/);
});

test("the verified installer updates the durable Runner from the bundled artifact", async () => {
  const installer = await readFile(
    path.join(root, "scripts", "install-marketplace.sh"),
    "utf8",
  );
  assert.match(installer, /update_durable_runner\(local_source, sys\.argv\[1\]\)/);
  assert.match(installer, /"setup",\s*"install",\s*"--version"/);
  assert.match(installer, /LOOMEX_PLUGIN_ROOT/);
  assert.match(installer, /loomex\.cli\.setupInstall\/v1/);
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

  assert.equal(manifest.version, "0.2.0");
  assert.match(manifest.interface.longDescription, /automatically checks first-use readiness/);
  assert.match(manifest.interface.defaultPrompt.join("\n"), /setup should start automatically/);
  assert.match(skill, /For every natural-language Loomex request/);
  assert.match(skill, /immediately call the read-only\s+`loomex_setup_plan`/);
  assert.match(skill, /ask for approval\s+only before `loomex_setup_apply`/i);
  assert.match(skill, /resume the user's\s+original request/);
  assert.match(setup, /Never tell the user to type a setup phrase/);
  assert.match(readme, /No special setup prompt is\s+needed/);
  assert.match(installer, /matching durable Runner are installed/);
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
