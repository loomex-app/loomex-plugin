# Runner operations

Use `loomex_runner_status` for version, service state, connectivity, queue,
active execution, and update health. Do not claim a durable run is healthy from
MCP connectivity alone.

Use `loomex_runner_doctor` for read-only diagnosis; optional `verbose` requests
more detail. Summarize failed checks and recommended actions; do not turn a
diagnosis request into repair or restart.

A retryable `MANAGEMENT_HTTP_FAILED` from run follow-up is not by itself proof
that the service is unhealthy. Check `loomex_runner_status`; if that result is
unavailable or ambiguous, check `loomex_runner_doctor`. When the service is
active and healthy, do not recommend `loomex_runner_control restart`; return to
the execution ID with `loomex_run_get` and bounded waits. Recommend restart only
when status or doctor identifies an unhealthy local service.

If doctor reports `RUNNER_IDENTITY_MISMATCH`, show the expected and observed
identities when the tool safely returns them and explain which authenticated
profile and binding are selected. Never silently re-register, rebind, delete
credentials, or replace identity state. Use read-only setup, auth, binding, and
doctor results to determine whether the mismatch is stale local state or the
wrong selected scope; any repair or selection change follows its normal preview
and explicit-confirmation flow.

`loomex_runner_control` changes the durable service. Before the selected `action`
of `start`, `stop`, or `restart`, show active local executions and expected
impact. After explicit confirmation, pass `confirm: true`. Never stop the Runner
as a substitute for cancelling one run. Prefer a graceful operation and report
whether the service reached the requested state.

Use `loomex_runner_logs` with a narrow optional `level` (`error`, `warn`, `info`,
or `debug`) and bounded `limit`; continue with the returned `cursor`. The tool
does not accept time-range or run-ID filters, so do not invent them. Request
redacted output by default. Do not expose access tokens, environment secrets,
full command output unrelated to the failure, or contents of local files. State
when logs were truncated and provide the next cursor when further inspection is
needed.

Service lifecycle entries can be intentionally uncorrelated; those entries carry
an empty `correlation_id`. Workflow, approval, and other correlated entries keep
their non-empty correlation identifier.

For broken installation, use the setup plan/apply/rollback flow rather than
manually altering runtime directories or OS service registration.
