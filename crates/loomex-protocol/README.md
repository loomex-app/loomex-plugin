# loomex-protocol

Versioned, transport-neutral contracts shared by Loomex runtimes.

This crate owns runner identity, surface (`desktop` or `plugin`), platform
metadata, protocol versioning, and compatibility checks. It intentionally does
not contain Tauri, MCP, filesystem, process, or authentication code.

Runner handshakes continue to advertise `runner.v1`. Agent task schema
versioning is independent of the transport handshake, so introducing agent v2
does not claim that a new REST, gRPC, MCP, or runner transport exists.
Consumers should depend on an explicit released crate version and use the
compatibility helpers during handshake.

This crate does **not** define an `agent-task/v1` payload. The historical v1
agent task is owned by its legacy producer and consumer, while this crate keeps
the existing `RunnerIdentity` and `runner.v1` transport contract intact. The
v2 agent task is an additive capability negotiated with the stable capability
identifier `agent.runtime.v2`.

## Local agent runtime v2

`agent_runtime_v2` defines the transport-neutral contract used when a Loomex
workflow delegates an AI step to software already available to the user. Its
task schema identifier is `loomex.plugin-agent-task/v2`:

- OpenAI models through `codex_cli`
- Anthropic models through `claude_cli`
- Google/Gemini-compatible models through `agy_cli`

There is intentionally no `gemini_cli` executor. The supported command identity
for that runtime is `agy_cli`.

The contract makes model behavior reproducible:

- `exact` requires both a stable Loomex model key and the provider-facing model
  ID, and never silently substitutes another model.
- `auto` explicitly delegates only the model ID to the selected executor while
  keeping both executor and provider fixed.
- fallback is either `none` or an explicit ordered list of exact model targets.

The v2 types also cover structured capability snapshots, installation and
authentication readiness, model availability, typed/redacted errors, explicit
execution and attempt states, and session checkpoints bound to the executor,
provider, and resolved model. Each task targets an exact runner/workspace
binding generation, preventing a queued task from being replayed after the
workspace has been rebound. Session continuity persists only allowlisted,
non-secret identifiers; credentials and arbitrary resume tokens are excluded.
Session checkpoint and continuation model identity is an optional pair:
`modelKey` and `providerModelId` are either both absent for an unresolved
`auto` selection or both present. Exact resume requires both fields and an
exact match; once an auto selection resolves, the pair pins that model for
resume.

Error context follows the same atomic rule for resolved identity:
`resolvedModelKey` and `resolvedProviderModelId` are both absent before model
resolution or both present afterward. Both values use the provider-facing CLI
identifier grammar and their respective 192-byte limits. A one-sided, empty,
unsafe, or oversized resolved identity is invalid; consumers must not infer the
missing half from requested-model fields.

Executor version gates use a distinct remediation contract. An
`unsupported_capability` error with safe reason
`executor_version_unverified` must be `user_action_required` and carry exactly
`upgrade_executor`, then `refresh_executor_discovery`. It must not collapse to
the generic `reconfigure_workflow` action: the user upgrades the local CLI,
then explicitly refreshes the persisted executor discovery snapshot.

### Candidate pinning and fallback

The task's primary and ordered fallback targets form an immutable candidate
list. `selectionIndex` is the durable slot identity: `0` is the primary and
`n >= 1` is `fallback.targets[n - 1]`. A runner may select a fallback locally
only when that exact target is present in the task. Cross-provider fallback is
therefore permitted only when the workflow explicitly lists the corresponding
executor, provider, model key, and provider model ID.

Each logical execution acquires exactly one candidate pin. The pin contains
`selectionIndex`, executor, provider, and the paired model identity. After
pinning, replay and resume cannot move to another slot, executor, provider, or
model. The only permitted refinement is an unresolved `auto` primary becoming
resolved once; a resolved model cannot be changed or cleared. Checkpoints and
continuations carry the same pin, making replay deterministic even when the
runner's discovery snapshot changes later.

### Logical executions and process attempts

`AgentExecutionV2` is the persistent logical workflow execution identified by
`executionId`, `requestId`, `idempotencyKey`, and binding. `AgentAttemptV2` is
one bounded process-start attempt; it may terminate during preflight before an
OS process or provider session exists. A blocked attempt is terminal and
records both `finishedAt` and `finishedSequence`, while the logical execution
remains nonterminal in `blocked` state with no active process.

`executionId` is unique per logical agent-node execution (for example, the
Backend `PluginAgentAttempt` UUID). It is not the parent workflow execution ID:
two agent nodes in one workflow must have different `executionId` values.
`requestId` identifies the corresponding HumanRequest.

After remediation, retry appends a new attempt under the same logical identity.
Attempt numbers are contiguous from one, at most one attempt may be appended
per accepted successor snapshot, and a logical execution is limited to eight
attempts. `retryKind` makes continuity explicit:

- `initial` is valid only for dispatch attempt one and carries neither
  `fromAttemptId` nor continuation.
- `fresh_after_remediation` follows only a `blocked` attempt that has no
  session checkpoint. It names the immediate predecessor, forbids a
  continuation, and performs a fresh launch after installation,
  authentication, model-availability, or other pre-session remediation.
- `resume_from_checkpoint` follows a `blocked` or `indeterminate` attempt that
  has a checkpoint. It names the immediate predecessor and carries a
  continuation that exactly matches that checkpoint.

Both retry modes inherit the predecessor's candidate pin. A fresh retry never
fabricates a session. A checkpoint may not be discarded to force a fresh
retry, and an `indeterminate` attempt without a checkpoint cannot be retried
inside the same logical execution because continuity cannot be proven.

A valid leased dispatch rejected by the runner's local v2 kill switch is a
single terminal lifecycle event, not a fake provider run. Its execution is
`failed` at global `sequence: 1` with one `dispatch_rejected` attempt whose
`startedSequence` and `finishedSequence` both equal the execution sequence
(`1`). The attempt has equal
start/finish timestamps, no active-attempt reference, retry, session, or
checkpoint, and carries the original runner-job delivery and idempotency
identity. Both attempt and execution errors use
`agent_runtime_v2_disabled`, `retry: never`, and no remediation. Equal
start/finish sequence is valid only for the pre-provider terminal states
`dispatch_rejected` and `dispatch_cancelled`; encoding either result as a
sequence-2 gap or ordinary failed/running provider attempt is invalid. The
authoritative rejection example is
`agent_execution_v2_dispatch_rejected.json`.

Malformed dispatch is the only other error allowed on a `dispatch_rejected`
attempt. When the plugin reports a bare `invalid_request` because the dispatch
cannot be decoded or validated, Backend must synthesize the terminal snapshot
from its persisted execution, process-attempt, runner-job delivery, digest, and
candidate-pin identity. It must not persist or display the plugin's raw
message, context, path, stderr, or arbitrary safe details. The canonical error
is exactly `invalid_request` / `validation`, message
`The process dispatch payload was malformed.`, `retry: never`, no delay or
remediation, and the singleton safe detail
`reasonCode: malformed_dispatch`. Executor, provider, requested model,
execution, and attempt context are reconstructed from trusted records;
provider-resolution and session context remain absent because no provider was
spawned. Attempt and execution errors must be identical. The lifecycle remains
the same strict pre-provider terminal form: failed execution at sequence `1`,
one `dispatch_rejected` attempt with equal start/finish sequence and timestamp,
no active attempt, retry, session, or checkpoint. Any other
`invalid_request` reason, extra detail, raw message/context, or sequence-2
encoding is invalid. The authoritative examples are
`agent_error_malformed_dispatch.json` and
`agent_execution_v2_malformed_dispatch_rejected.json`.

Cancellation wins the prestart race when Backend accepts cancellation before
the pending local rejection is acknowledged. The plugin must replace only its
unacknowledged rejection envelope; it must not submit the stale
`dispatch_rejected` result. The authoritative replacement is execution
`cancelled` at global `sequence: 1`, with no active attempt and exactly one
`dispatch_cancelled` attempt. Its start and finish sequences both equal `1`,
its timestamps are equal at cancellation linearization, and it preserves the
original delivery route, task and delivery idempotency keys, payload digest,
and exact candidate pin. It has no retry, session, checkpoint, or provider
spawn. Both errors are identical `cancelled` envelopes with `retry: never`, no
remediation, and safe `reasonCode: prestart_cancellation_won`. This
same-sequence replacement is not a normal execution successor: it is allowed
only through `validate_prestart_cancellation_replacement` before terminal
acknowledgement. After acknowledgement, only exact replay is valid and a later
cancellation is too late/not applied. The authoritative example is
`agent_execution_v2_dispatch_cancelled.json`.

Delivery ownership is immutable and digest-bound. `delivery.route` is either:

- `runner_job`, which requires both `runnerJobId` and
  `leaseTargetRunnerId`; the lease target must equal the task binding's
  `runnerId`; or
- `direct_control`, which forbids both runner-job fields.

Backend workflow tasks use `runner_job`. Direct MCP/control execution uses
`direct_control` only for explicitly direct-owned tasks. Consumers must call
the route-specific validator before claiming work: a direct-control handler
must reject `runner_job`, and a leased-job handler must match the exact job and
lease target. Changing the route or route identity changes `payloadDigest`;
accepted attempt history cannot rewrite it.

Logical and process idempotency are deliberately separate. The execution-level
`idempotencyKey` never changes. Each process attempt has three immutable
identities:

- `taskIdempotencyKey` is
  `loomex-agent-attempt-v2:<lowercase SHA-256 hex>`;
- `deliveryIdempotencyKey` is
  `loomex-agent-delivery-v2:<lowercase SHA-256 hex>`; and
- `payloadDigest` is `sha256:<lowercase SHA-256 hex>` of the canonical,
  immutable process invocation envelope.

The task and delivery hashes use separate domain tags. Their common identity
preimage is the UTF-8, NUL-separated tuple
`(domain tag, executionId, decimal attemptNumber)`, with domain tags
`loomex.agent-attempt/v2` and `loomex.agent-delivery/v2`, respectively.
`payloadDigest` covers the frozen logical task snapshot, process attempt
number, delivery route and ownership IDs, selected candidate
slot/executor/provider, requested model identity, and exact retry
kind/continuation when present; it excludes mutable lifecycle state and runtime
results.

Canonicalization is strictly RFC 8785/JCS, not recursive key sorting plus a
platform's default float formatter. The protocol implementation normalizes
`-0.0` to `0`, `1.0` to `1`, uses ECMAScript number formatting at exponent
boundaries, preserves Unicode, orders object keys by UTF-16 code units, and
rejects non-finite numbers. The
`agent_process_dispatch_v2_jcs_edge.{json,canonical}` fixtures pin exact UTF-8
canonical bytes and SHA-256 output across Python and Rust.

The plugin journal claims `(taskIdempotencyKey, payloadDigest)`. Replaying the
same tuple returns the existing process attempt. Reusing a task key with a
different digest is a conflict. A retried process therefore gets new task and
delivery keys and a new digest; the blocked predecessor's task payload and
attempt record are never rewritten.

`sequence`, `startedSequence`, checkpoint `sequence`, and `finishedSequence`
share one execution-wide monotonic lifecycle domain. Reusing an identical
snapshot is an idempotent replay; advancing requires a strictly larger
execution sequence. Terminal attempts are immutable, prior attempt history
cannot be removed or renumbered, and a terminal logical execution cannot be
advanced.

Provider-facing model and resume-session identifiers are validated before they
can be used as CLI arguments. Model keys and provider model IDs are limited to
192 ASCII bytes; provider session IDs are limited to 256 ASCII bytes. Their
grammar is `[A-Za-z0-9][A-Za-z0-9._:/@+-]*`, with empty, `.` and `..`
slash-delimited segments rejected. Internal UUID, request, execution, attempt,
session, and checkpoint identifiers are not reinterpreted as CLI identifiers.
Task `idempotencyKey` uses the same ASCII-safe domain grammar and is limited to
1–160 bytes, matching the Backend persistence limit.

## Terminal payload limits

`loomex.agent-terminal-payload-limits/v1` separates runtime process capture
from durable wire delivery. Stdout/stderr capture limits are executor-local and
do not authorize an equally large Backend submission.

The authoritative serialized JSON limits are:

- parsed `AgentOutput`: 7,000,000 bytes;
- complete `AgentExecutionV2`: 7,750,000 bytes;
- complete HTTP terminal submission including wrapper: 7,900,000 bytes;
- Backend terminal request ceiling: 8,000,000 bytes.

This reserves 750,000 bytes for the execution envelope, 150,000 bytes for the
HTTP wrapper, and a final 100,000-byte Backend safety margin. Consumers must
validate the exact serialized submission immediately before enqueue/send;
reserve arithmetic alone is not a substitute for that final check.

## Structured output root

The structured-output shape contract is
`loomex.agent-structured-output-shape/v1`. Workflow reducers consume objects,
so structured tasks must carry an explicit root schema of at least
`{"type":"object"}`. Missing schemas, permissive `{}`, scalar roots, and array
roots are invalid. `default_agent_structured_output_schema()` returns the
canonical default. Terminal JSON `AgentOutput.structured` must likewise be an
object; no implicit scalar/array wrapper is introduced.

JSON compatibility fixtures live in `fixtures/`. The v1 runner fixture protects
the migration path; the v2 task, capability, execution, error, and session data
exercise the new wire contract.

This crate remains data-only. Executable discovery, process management,
filesystem access, MCP transport, Tauri integration, credentials, and provider
authentication belong to consuming runtimes.

## Compatibility and rollback

Agent schema selection is capability-based and independent from the runner
transport version:

`loomex.runner-agent-advertisement/v1` is the fail-closed projection of the
agent-related manifest fields. `agentAdvertisementSchemaVersion`,
`agentRuntimeV2Enabled`, `legacyAgentTasks`, and `capabilities` are required.
`legacyAgentTasks.mode` is always explicitly `drain_only` or `disabled`.

| v2 enabled | Legacy mode | Required advertisement | Meaning |
| --- | --- | --- | --- |
| true | `drain_only` | `agent.runtime.v2`, `agent.task.v1.drain`, and valid `agentRuntimes` | Accept new v2 work and drain already-issued v1 work |
| true | `disabled` | `agent.runtime.v2` and valid `agentRuntimes`; drain capability omitted | v2-only cutover |
| false | `drain_only` | only `agent.task.v1.drain`; `agent.runtime.v2` and `agentRuntimes` omitted | v2 disabled, but already-issued v1 work may drain |
| false | `disabled` | both agent capabilities and `agentRuntimes` omitted | agent dispatch disabled |

Capability entries with value `false` do not count as omission and are invalid
for disabled modes. A JSON `null` `agentRuntimes` is also invalid; the field
must be absent when v2 is disabled. Unknown advertisement/snapshot schemas,
unknown legacy modes, missing `legacyAgentTasks`, inconsistent capability
presence, or invalid snapshots fail closed. `drain_only` never authorizes
emission of new v1 tasks.

This cutover contract keeps the transport at `runner.v1`; it does not require
inventing `runner.v2` or rewriting stored v1 data. Consumers must reject
unknown executor identities. In particular, `agy_cli` is valid and
`gemini_cli` is not.

## Offline compatibility guards

`tests/public_surface.rs` compiles as an external crate consumer and pins the
public v1 identity helpers, v2 schema constants, capability identifier, and
core public types. `tests/fixture_contract.rs` round-trips every checked-in
wire fixture and rejects the retired `gemini_cli` identity. These guards are
intentionally dependency-free and run offline in CI. They complement semantic
version review; publishing still requires the normal release comparison
against the previously released crate.
