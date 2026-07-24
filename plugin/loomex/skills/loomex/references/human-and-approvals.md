# Human requests and approvals

Human input and policy approval are distinct. Never answer either one from an
assumption, a previous run, or the model's preference.

## Human requests

Use `loomex_human_list`, scoped with optional `executionId` or `workflowId` when
known; optional `status` is `pending`, `resolved`, or `all`, and `limit` bounds
the result. Preserve returned `nextCursor` and pass it as `cursor` to fetch the
next page. A request with `inputSpec.schemaVersion` uses one of the four typed
contracts: `multi_select`, `single_select`, `text`, or `boolean`. Immediately
call `loomex_human_open` with that exact returned request and tell the user to
complete the rendered side-panel form. Do not ask for the same values again in
chat. An `inputSpec.collectionMode` of `batch` contains an ordered `questions`
array; render it as one form and preserve that order in the submitted
`answers[]`. The app submits the exact request ID through
`loomex_human_respond`.

For a legacy request without `inputSpec`, present the exact prompt, allowed
response shape or choices, request ID, run/workflow context, and deadline if
present. If free-form text is allowed, preserve the user's meaning and show any
consequential normalization before sending it.

Call `loomex_human_respond` only with the selected request ID as `requestId` and
the user's answer in the public `response` field; optional `idempotencyKey` may
be used for a safely retried submission. `response` may be a scalar, object, or
other value allowed by the request schema; do not wrap it in the Runner's
internal `payload` field. If the request is already answered or expired, report
that state and refresh the run rather than sending to another pending request.
An authoritative `resolved` response confirms the human request, not the
workflow's later state. If the subsequent wait has a retryable management
failure, keep the execution ID and follow the `loomex_run_get` recovery flow in
[workflows-and-runs.md](workflows-and-runs.md); do not infer that the run was
preserved or recommend a Runner restart from that transport error alone.

## Approvals

Use `loomex_approval_list`, optionally filtered by `workflowId`, `executionId`,
or both; optional `status` is `pending`, `approved`, `rejected`, or `all`, and
`limit` bounds the result. Preserve returned `nextCursor` and pass it as
`cursor` for the next page. Prefer `executionId` for the current run and use
`workflowId` to inspect several executions of one workflow. Explain the action,
target workspace, command/files or external side effect, policy reason, and
consequences of approve and reject. Ask for an explicit decision.

Call `loomex_approval_decide` with the exact public `approvalId` and a supported
`decision` of `approve` or `reject`; include `reason` and `idempotencyKey` only
when appropriate. Do not send a generic `requestId`, auto-approve, infer
approval from the initial request to run a workflow, or treat Codex's own tool
approval as Loomex policy approval.

## When Codex is closed

The durable backend retains pending requests but cannot make a closed Codex UI
display them. On reconnect, query both inboxes and the run state. The Tauri app
may answer the same request while Codex is unavailable; always refresh before
submitting to avoid a stale response.
