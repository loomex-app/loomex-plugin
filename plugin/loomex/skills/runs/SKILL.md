---
name: runs
description: Use when a user asks to inspect, follow, recover, wait for, or cancel a durable Loomex workflow run.
---

# Runs

Track durable execution state by authoritative execution ID. Read [workflows-and-runs.md](../loomex/references/workflows-and-runs.md) before recovery, agent-task handling, or cancellation.

## Workflow

- Call `loomex_setup_status` first. For a known execution ID, use `loomex_run_get`; use `loomex_run_list` only with its required `workflowId`.
- Use bounded `loomex_run_wait` calls and return its sequence as `afterSequence`; preserve execution ID across reconnects.
- Treat retryable management/transport failures as unknown state: call `loomex_run_get`, make only bounded status attempts, and do not infer success, failure, cancellation, or durability.
- Route pending human requests and approvals to the `human` skill. Route plugin agent tasks through `loomex_agent_task_list` and `loomex_agent_task_respond` without fabricating output or replacing a required session.
- Before cancellation, explain exact run and local impact. Call `loomex_run_cancel` with a non-empty audit reason and idempotency key; distinguish cancellation requested from terminal `cancelled`.
- Recommend Runner restart only when `loomex_runner_status` or `loomex_runner_doctor` shows the local service is unhealthy.

Do not restart a healthy Runner to force reconnect, and do not imitate workflow execution in the shell.
