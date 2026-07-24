use serde::Serialize;
use serde_json::{json, Map, Value};

pub const HUMAN_INPUT_APP_URI: &str = "ui://loomex/human-input/v1/form.html";
pub const LIST_TABLE_APP_URI: &str = "ui://loomex/list/v1/table.html";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub output_schema: Value,
    pub annotations: ToolAnnotations,
    #[serde(skip_serializing_if = "Option::is_none", rename = "_meta")]
    pub meta: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    pub title: &'static str,
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    Default,
    Setup,
    Wait,
}

#[derive(Debug, Clone, Copy)]
pub struct ToolRoute {
    pub method: &'static str,
    pub deadline: DeadlineKind,
}

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            "loomex_setup_status",
            "Setup status",
            "First step for every Loomex request. Read setupRequired and recommendedNextAction; this call never changes the system.",
            "setup.status",
            obj(&[], &[]),
            ro(),
        ),
        tool(
            "loomex_setup_plan",
            "Plan setup",
            "Immediately prepare a read-only setup plan when setup status recommends setup.plan; no preliminary user question is needed.",
            "setup.plan",
            obj(
                &[
                    ("version", string()),
                    ("channel", enum_string(&["stable", "beta"])),
                    ("installService", boolean()),
                ],
                &[],
            ),
            ro(),
        ),
        tool(
            "loomex_setup_apply",
            "Apply setup",
            "Apply a previously reviewed setup plan and health-check the service.",
            "setup.apply",
            obj(
                &[
                    ("planId", string()),
                    ("channel", enum_string(&["stable", "beta"])),
                    ("installService", boolean()),
                    ("confirm", const_true()),
                ],
                &["planId", "channel", "installService", "confirm"],
            ),
            mutating(false, false, true),
        ),
        tool(
            "loomex_setup_rollback",
            "Rollback setup",
            "Atomically switch the runner service to an installed previous version.",
            "setup.rollback",
            obj(
                &[("targetVersion", string()), ("confirm", const_true())],
                &["targetVersion", "confirm"],
            ),
            mutating(true, false, true),
        ),
        tool(
            "loomex_auth_status",
            "Authentication status",
            "Show the current Loomex authentication and device-binding status.",
            "auth.status",
            obj(&[], &[]),
            ro(),
        ),
        tool(
            "loomex_auth_start",
            "Start authentication",
            "Start device authentication and return the verification URL and user code.",
            "auth.start",
            obj(&[("serverUrl", uri_string())], &[]),
            mutating(false, false, true),
        ),
        tool(
            "loomex_auth_wait",
            "Wait for authentication",
            "Wait up to 45 seconds for a device authentication attempt.",
            "auth.wait",
            obj(
                &[("loginId", string()), ("timeoutSeconds", timeout_seconds())],
                &["loginId"],
            ),
            mutating(false, false, true),
        ),
        tool(
            "loomex_auth_logout",
            "Log out",
            "Delete local Loomex credentials for this runner.",
            "auth.logout",
            obj(&[("confirm", const_true())], &["confirm"]),
            mutating(true, true, true),
        ),
        tool_with_meta(
            "loomex_org_list",
            "List organizations",
            "List organizations available to the authenticated Loomex account.",
            obj(&[], &[]),
            open_ro(),
            list_table_meta(),
        ),
        tool(
            "loomex_org_select",
            "Select organization",
            "Set the runner's active organization.",
            "org.select",
            obj(&[("organizationId", identifier())], &["organizationId"]),
            mutating(false, true, true),
        ),
        tool_with_meta(
            "loomex_project_list",
            "List projects",
            "List Loomex projects, optionally within an organization.",
            obj(&[("organizationId", identifier())], &[]),
            open_ro(),
            list_table_meta(),
        ),
        tool(
            "loomex_project_select",
            "Select project",
            "Set the runner's active project.",
            "project.select",
            obj(&[("projectId", identifier())], &["projectId"]),
            mutating(false, true, true),
        ),
        tool(
            "loomex_binding_list",
            "List workspace bindings",
            "List local-workspace bindings visible to this runner.",
            "binding.list",
            obj(
                &[
                    ("projectId", identifier()),
                    ("status", enum_string(&["active", "revoked", "all"])),
                ],
                &[],
            ),
            open_ro(),
        ),
        tool(
            "loomex_binding_create",
            "Bind workspace",
            "Bind an explicit local workspace path to a Loomex project.",
            "binding.create",
            obj(
                &[
                    ("projectId", identifier()),
                    ("workspacePath", path_string()),
                ],
                &["projectId", "workspacePath"],
            ),
            mutating(false, false, true),
        ),
        tool(
            "loomex_binding_revoke",
            "Revoke workspace binding",
            "Revoke a local-workspace binding. Existing workflow audit data is retained.",
            "binding.revoke",
            obj(
                &[
                    ("projectId", identifier()),
                    ("bindingId", identifier()),
                    ("confirm", const_true()),
                ],
                &["projectId", "bindingId", "confirm"],
            ),
            mutating(true, true, true),
        ),
        tool_with_meta(
            "loomex_workflow_list",
            "List workflows",
            "List workflows in the selected or supplied project.",
            list_schema(&[("projectId", identifier()), ("query", short_string())]),
            open_ro(),
            list_table_meta(),
        ),
        tool(
            "loomex_workflow_show",
            "Show workflow",
            "Get a workflow's definition, inputs, local capabilities, and HITL steps.",
            "workflow.show",
            obj(
                &[("workflowId", identifier()), ("version", string())],
                &["workflowId"],
            ),
            open_ro(),
        ),
        tool(
            "loomex_workflow_run",
            "Run workflow",
            "Start a durable workflow against an explicitly bound local workspace.",
            "workflow.run",
            obj(
                &[
                    ("workflowId", identifier()),
                    ("bindingId", identifier()),
                    ("inputs", json_object()),
                    ("version", string()),
                    ("sessionId", identifier()),
                    ("idempotencyKey", idempotency_key()),
                ],
                &["workflowId", "bindingId", "idempotencyKey"],
            ),
            mutating(false, true, true),
        ),
        tool(
            "loomex_run_list",
            "List runs",
            "List durable workflow executions and their current state.",
            "run.list",
            obj(
                &[
                    ("workflowId", identifier()),
                    (
                        "status",
                        enum_string(&[
                            "queued",
                            "running",
                            "waiting_for_human",
                            "succeeded",
                            "failed",
                            "cancelled",
                        ]),
                    ),
                    ("cursor", string()),
                    ("limit", limit()),
                ],
                &["workflowId"],
            ),
            open_ro(),
        ),
        tool(
            "loomex_run_get",
            "Get run",
            "Get current state and recent events for a durable workflow execution.",
            "run.get",
            obj(&[("executionId", identifier())], &["executionId"]),
            open_ro(),
        ),
        tool(
            "loomex_run_wait",
            "Wait for run event",
            "Wait up to 45 seconds for a run state change, output, or human request.",
            "run.wait",
            obj(
                &[
                    ("executionId", identifier()),
                    ("afterSequence", nonnegative_integer()),
                    ("timeoutSeconds", timeout_seconds()),
                ],
                &["executionId"],
            ),
            wait_ro(),
        ),
        tool(
            "loomex_run_cancel",
            "Cancel run",
            "Request cancellation of a durable workflow execution.",
            "run.cancel",
            obj(
                &[
                    ("executionId", identifier()),
                    ("reason", short_string()),
                    ("idempotencyKey", idempotency_key()),
                ],
                &["executionId", "reason", "idempotencyKey"],
            ),
            mutating(true, true, true),
        ),
        tool(
            "loomex_human_list",
            "List human requests",
            "List pending or resolved human-in-the-loop requests.",
            "human.list",
            obj(
                &[
                    ("status", enum_string(&["pending", "resolved", "all"])),
                    ("executionId", identifier()),
                    ("workflowId", identifier()),
                    ("cursor", string()),
                    ("limit", limit()),
                ],
                &[],
            ),
            open_ro(),
        ),
        tool_with_meta(
            "loomex_human_respond",
            "Respond to human request",
            "Submit a durable response to a workflow human-in-the-loop request.",
            obj(
                &[
                    ("requestId", identifier()),
                    ("response", any_value()),
                    ("idempotencyKey", idempotency_key()),
                ],
                &["requestId", "response"],
            ),
            mutating(false, true, true),
            json!({
                "ui": {
                    "visibility": ["model", "app"]
                },
                "openai/widgetAccessible": true
            }),
        ),
        tool_with_meta(
            "loomex_human_open",
            "Open human input",
            "Open a Loomex human input request as an interactive side-panel form.",
            obj(&[("humanRequest", any_value())], &["humanRequest"]),
            open_ro(),
            json!({
                "ui": {
                    "resourceUri": HUMAN_INPUT_APP_URI,
                    "visibility": ["model"]
                },
                "openai/outputTemplate": HUMAN_INPUT_APP_URI,
                "openai/widgetAccessible": true
            }),
        ),
        tool(
            "loomex_agent_task_list",
            "List plugin agent tasks",
            "List pending AI/person node tasks that must be executed by the local plugin host.",
            "agent.list",
            obj(
                &[
                    ("status", enum_string(&["pending", "resolved", "all"])),
                    ("workflowId", identifier()),
                    ("executionId", identifier()),
                    ("cursor", string()),
                    ("limit", limit()),
                ],
                &[],
            ),
            open_ro(),
        ),
        tool(
            "loomex_agent_task_respond",
            "Submit plugin agent result",
            "Submit the structured result or unavailable error for a plugin-executed AI/person node task.",
            "agent.respond",
            obj(
                &[
                    ("requestId", identifier()),
                    ("response", plugin_agent_response()),
                    ("idempotencyKey", idempotency_key()),
                ],
                &["requestId", "response"],
            ),
            mutating(false, true, true),
        ),
        tool(
            "loomex_approval_list",
            "List approvals",
            "List pending or decided Loomex policy approvals.",
            "approval.list",
            obj(
                &[
                    (
                        "status",
                        enum_string(&["pending", "approved", "rejected", "all"]),
                    ),
                    ("workflowId", identifier()),
                    ("executionId", identifier()),
                    ("cursor", string()),
                    ("limit", limit()),
                ],
                &[],
            ),
            open_ro(),
        ),
        tool(
            "loomex_approval_decide",
            "Decide approval",
            "Approve or reject a Loomex policy approval with an auditable reason.",
            "approval.decide",
            obj(
                &[
                    ("approvalId", identifier()),
                    ("decision", enum_string(&["approve", "reject"])),
                    ("reason", short_string()),
                    ("idempotencyKey", idempotency_key()),
                ],
                &["approvalId", "decision"],
            ),
            mutating(false, true, true),
        ),
        tool(
            "loomex_runner_status",
            "Runner status",
            "Inspect the long-lived local runner, version, health, and connection state.",
            "status",
            obj(&[], &[]),
            ro(),
        ),
        tool(
            "loomex_runner_control",
            "Control runner",
            "Start, stop, or restart the per-user Loomex runner service.",
            "runner.control",
            obj(
                &[
                    ("action", enum_string(&["start", "stop", "restart"])),
                    ("confirm", const_true()),
                ],
                &["action", "confirm"],
            ),
            mutating(true, false, true),
        ),
        tool(
            "loomex_runner_doctor",
            "Diagnose runner",
            "Run local runner, authentication, connectivity, and workspace checks.",
            "doctor",
            obj(&[("verbose", boolean())], &[]),
            open_ro(),
        ),
        tool(
            "loomex_runner_logs",
            "Read runner logs",
            "Read a bounded, redacted page of local runner logs.",
            "logs.tail",
            obj(
                &[
                    ("limit", limit()),
                    ("cursor", string()),
                    ("level", enum_string(&["error", "warn", "info", "debug"])),
                ],
                &[],
            ),
            ro(),
        ),
    ]
}

pub fn route(name: &str) -> Option<ToolRoute> {
    definitions()
        .into_iter()
        .find(|tool| tool.name == name)
        .map(|tool| ToolRoute {
            method: match tool.name {
                "loomex_setup_status" => "setup.status",
                "loomex_setup_plan" => "setup.plan",
                "loomex_setup_apply" => "setup.apply",
                "loomex_setup_rollback" => "setup.rollback",
                "loomex_auth_status" => "auth.status",
                "loomex_auth_start" => "auth.start",
                "loomex_auth_wait" => "auth.wait",
                "loomex_auth_logout" => "auth.logout",
                "loomex_org_list" => "org.list",
                "loomex_org_select" => "org.select",
                "loomex_project_list" => "project.list",
                "loomex_project_select" => "project.select",
                "loomex_binding_list" => "binding.list",
                "loomex_binding_create" => "binding.create",
                "loomex_binding_revoke" => "binding.revoke",
                "loomex_workflow_list" => "workflow.list",
                "loomex_workflow_show" => "workflow.show",
                "loomex_workflow_run" => "workflow.run",
                "loomex_run_list" => "run.list",
                "loomex_run_get" => "run.get",
                "loomex_run_wait" => "run.wait",
                "loomex_run_cancel" => "run.cancel",
                "loomex_human_list" => "human.list",
                "loomex_human_respond" => "human.respond",
                "loomex_human_open" => "human.open",
                "loomex_agent_task_list" => "agent.list",
                "loomex_agent_task_respond" => "agent.respond",
                "loomex_approval_list" => "approval.list",
                "loomex_approval_decide" => "approval.decide",
                "loomex_runner_status" => "status",
                "loomex_runner_control" => "runner.control",
                "loomex_runner_doctor" => "doctor",
                "loomex_runner_logs" => "logs.tail",
                _ => unreachable!(),
            },
            deadline: if matches!(tool.name, "loomex_setup_apply" | "loomex_setup_rollback") {
                DeadlineKind::Setup
            } else if matches!(tool.name, "loomex_auth_wait" | "loomex_run_wait") {
                DeadlineKind::Wait
            } else {
                DeadlineKind::Default
            },
        })
}

pub fn definition(name: &str) -> Option<ToolDefinition> {
    definitions().into_iter().find(|tool| tool.name == name)
}

pub fn validate_arguments(schema: &Value, arguments: &Value) -> Result<(), String> {
    validate_value(schema, arguments, "arguments")
}

pub fn validate_output(schema: &Value, output: &Value) -> Result<(), String> {
    validate_value(schema, output, "output")
}

fn validate_value(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    if let Some(variants) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = variants
            .iter()
            .filter(|variant| validate_value(variant, value, path).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "{path} must match exactly one schema variant (matched {matches})"
            ));
        }
    }
    if let Some(variants) = schema.get("anyOf").and_then(Value::as_array) {
        if !variants
            .iter()
            .any(|variant| validate_value(variant, value, path).is_ok())
        {
            return Err(format!("{path} must match at least one schema variant"));
        }
    }
    if schema
        .get("const")
        .is_some_and(|expected| expected != value)
    {
        return Err(format!("{path} must equal {}", schema["const"]));
    }
    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let valid = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "number" => value.is_number(),
            "null" => value.is_null(),
            _ => true,
        };
        if !valid {
            return Err(format!("{path} must be a {expected}"));
        }
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array) {
        if !choices.contains(value) {
            return Err(format!("{path} has an unsupported value"));
        }
    }
    if let Some(text) = value.as_str() {
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
            if text.len() < min as usize {
                return Err(format!("{path} is too short"));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            if text.len() > max as usize {
                return Err(format!("{path} is too long"));
            }
        }
    }
    if value.is_number() {
        let number = value.as_f64().unwrap_or(f64::NAN);
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
            if number < min {
                return Err(format!("{path} must be at least {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
            if number > max {
                return Err(format!("{path} must be at most {max}"));
            }
        }
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for required in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(required) {
                    return Err(format!("{path}.{required} is required"));
                }
            }
        }
        for (key, child) in object {
            match properties.and_then(|properties| properties.get(key)) {
                Some(child_schema) => {
                    validate_value(child_schema, child, &format!("{path}.{key}"))?
                }
                None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    return Err(format!("{path}.{key} is not allowed"))
                }
                None => {}
            }
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        for (index, child) in values.iter().enumerate() {
            validate_value(items, child, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

fn tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    _method: &'static str,
    input_schema: Value,
    annotations: ToolAnnotations,
) -> ToolDefinition {
    ToolDefinition {
        name,
        title,
        description,
        input_schema,
        output_schema: output_schema(name),
        annotations,
        meta: None,
    }
}

fn tool_with_meta(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input_schema: Value,
    annotations: ToolAnnotations,
    meta: Value,
) -> ToolDefinition {
    ToolDefinition {
        name,
        title,
        description,
        input_schema,
        output_schema: output_schema(name),
        annotations,
        meta: Some(meta),
    }
}

fn list_table_meta() -> Value {
    json!({
        "ui": {
            "resourceUri": LIST_TABLE_APP_URI,
            "visibility": ["model", "app"],
            "prefersBorder": true
        },
        "openai/outputTemplate": LIST_TABLE_APP_URI,
        "openai/widgetAccessible": true
    })
}

fn obj(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let properties = properties
        .iter()
        .map(|(name, schema)| ((*name).to_string(), schema.clone()))
        .collect::<Map<_, _>>();
    json!({"type":"object", "properties":properties, "required":required, "additionalProperties":false})
}

fn list_schema(extra: &[(&str, Value)]) -> Value {
    let mut fields = extra.to_vec();
    fields.extend([("cursor", string()), ("limit", limit())]);
    obj(&fields, &[])
}

fn output_schema(tool_name: &str) -> Value {
    let common = [
        ("schemaVersion", json!({"const":"loomex.mcp/v1"})),
        ("tool", json!({"const":tool_name})),
        ("meta", output_meta_schema()),
    ];
    let mut success = common.to_vec();
    success.extend([
        ("ok", json!({"const":true})),
        ("data", output_data_schema(tool_name)),
    ]);
    let mut failure = common.to_vec();
    failure.extend([
        ("ok", json!({"const":false})),
        ("error", output_error_schema()),
    ]);
    json!({
        "title": format!("{tool_name} result"),
        "description": "Discriminated Loomex MCP result envelope. ok=true contains tool-specific data; ok=false contains a stable error.",
        "oneOf": [
            strict_object(&success, &["schemaVersion", "ok", "tool", "data", "meta"]),
            strict_object(&failure, &["schemaVersion", "ok", "tool", "error", "meta"]),
        ]
    })
}

fn output_meta_schema() -> Value {
    strict_object(
        &[
            ("requestId", identifier()),
            ("timestampMs", nonnegative_integer()),
        ],
        &["requestId", "timestampMs"],
    )
}

fn output_error_schema() -> Value {
    strict_object(
        &[
            ("code", identifier()),
            ("message", json!({"type":"string","minLength":1})),
            ("retryable", boolean()),
        ],
        &["code", "message", "retryable"],
    )
}

fn output_data_schema(tool_name: &str) -> Value {
    match tool_name {
        "loomex_setup_status" => evolvable_object(
            &[
                ("installed", boolean()),
                ("runtime", nullable(evolvable_object(&[], &[]))),
                ("runtimeRoot", path_string()),
                ("service", evolvable_object(&[], &[])),
                ("supported", boolean()),
                ("setupRequired", boolean()),
                (
                    "recommendedNextAction",
                    enum_string(&[
                        "setup.plan",
                        "auth.status",
                        "binding.create",
                        "package.error",
                        "unsupported",
                    ]),
                ),
                ("recommendationReason", identifier()),
                ("bundledRuntime", evolvable_object(&[], &[])),
                ("durableRuntime", evolvable_object(&[], &[])),
            ],
            &[
                "installed",
                "runtime",
                "runtimeRoot",
                "service",
                "supported",
            ],
        ),
        "loomex_setup_plan" => evolvable_object(
            &[
                ("planId", identifier()),
                ("action", enum_string(&["install", "repair", "update"])),
                ("version", string()),
                ("pluginVersion", string()),
                ("channel", enum_string(&["stable", "beta"])),
                ("target", string()),
                ("installService", boolean()),
                ("requiresConfirmation", json!({"const":true})),
                ("actions", array_of(string())),
            ],
            &[
                "planId",
                "action",
                "version",
                "pluginVersion",
                "channel",
                "target",
                "installService",
                "requiresConfirmation",
                "actions",
            ],
        ),
        "loomex_setup_apply" => evolvable_object(
            &[
                ("installed", json!({"const":true})),
                ("version", string()),
                ("runtimePath", path_string()),
                ("channel", enum_string(&["stable", "beta"])),
                ("installService", boolean()),
                ("service", evolvable_object(&[], &[])),
            ],
            &[
                "installed",
                "version",
                "runtimePath",
                "channel",
                "installService",
                "service",
            ],
        ),
        "loomex_setup_rollback" => evolvable_object(
            &[("rolledBack", json!({"const":true})), ("version", string())],
            &["rolledBack", "version"],
        ),
        "loomex_auth_status" => auth_status_schema(),
        "loomex_auth_start" => evolvable_object(
            &[
                ("loginId", identifier()),
                ("verificationUri", uri_string()),
                ("userCode", identifier()),
                ("expiresInSeconds", nonnegative_integer()),
                ("intervalSeconds", nonnegative_integer()),
            ],
            &[
                "loginId",
                "verificationUri",
                "userCode",
                "expiresInSeconds",
                "intervalSeconds",
            ],
        ),
        "loomex_auth_wait" => json!({"anyOf":[
            evolvable_object(
                &[("authenticated", json!({"const":false})), ("pending", json!({"const":true})), ("loginId", identifier())],
                &["authenticated", "pending", "loginId"],
            ),
            evolvable_object(
                &[("authenticated", json!({"const":true})), ("pending", json!({"const":false})), ("profile", identifier()), ("serverUrl", uri_string())],
                &["authenticated", "pending", "profile", "serverUrl"],
            )
        ]}),
        "loomex_auth_logout" => evolvable_object(
            &[
                ("profile", identifier()),
                ("localCredentialRemoved", json!({"const":true})),
                ("serverRevokeAttempted", boolean()),
                ("serverRevokeSucceeded", boolean()),
            ],
            &[
                "profile",
                "localCredentialRemoved",
                "serverRevokeAttempted",
                "serverRevokeSucceeded",
            ],
        ),
        "loomex_org_list" => {
            evolvable_object(&[("items", array_of(organization_schema()))], &["items"])
        }
        "loomex_org_select" => evolvable_object(
            &[
                ("profile", identifier()),
                ("organization", organization_schema()),
                ("changed", boolean()),
            ],
            &["profile", "organization", "changed"],
        ),
        "loomex_project_list" => evolvable_object(
            &[
                ("items", array_of(project_schema())),
                ("organizationId", identifier()),
            ],
            &["items", "organizationId"],
        ),
        "loomex_project_select" => evolvable_object(
            &[
                ("profile", identifier()),
                ("project", project_schema()),
                ("changed", boolean()),
            ],
            &["profile", "project", "changed"],
        ),
        "loomex_binding_list" => evolvable_object(
            &[
                ("bindings", array_of(binding_schema())),
                ("projectId", identifier()),
                ("notBootstrapped", boolean()),
            ],
            &["bindings", "projectId", "notBootstrapped"],
        ),
        "loomex_binding_create" => evolvable_object(
            &[
                ("profile", identifier()),
                ("projectId", identifier()),
                ("organizationId", identifier()),
                ("runnerId", identifier()),
                ("binding", binding_schema()),
                ("workspace", workspace_schema()),
                ("bootstrapped", boolean()),
                ("reused", boolean()),
            ],
            &[
                "profile",
                "projectId",
                "organizationId",
                "runnerId",
                "binding",
                "workspace",
                "bootstrapped",
                "reused",
            ],
        ),
        "loomex_binding_revoke" => evolvable_object(
            &[
                ("revoked", json!({"const":true})),
                ("bindingId", identifier()),
                ("projectId", identifier()),
                ("selectedBindingCleared", boolean()),
            ],
            &[
                "revoked",
                "bindingId",
                "projectId",
                "selectedBindingCleared",
            ],
        ),
        "loomex_workflow_list" => evolvable_object(
            &[
                ("workflows", array_of(workflow_schema())),
                ("nextCursor", nullable(string())),
            ],
            &["workflows", "nextCursor"],
        ),
        "loomex_workflow_show" => evolvable_object(
            &[
                ("workflow", nullable(workflow_schema())),
                ("inputSchema", nullable(json_object())),
                ("activeVersion", nullable(evolvable_object(&[], &[]))),
                ("selectedVersion", nullable(evolvable_object(&[], &[]))),
            ],
            &[
                "workflow",
                "inputSchema",
                "activeVersion",
                "selectedVersion",
            ],
        ),
        "loomex_workflow_run" | "loomex_run_get" | "loomex_run_wait" => run_detail_schema(),
        "loomex_run_list" => evolvable_object(
            &[
                ("executions", array_of(execution_schema())),
                ("nextCursor", nullable(string())),
            ],
            &["executions", "nextCursor"],
        ),
        "loomex_run_cancel" => {
            evolvable_object(&[("execution", execution_schema())], &["execution"])
        }
        "loomex_human_list" | "loomex_approval_list" | "loomex_agent_task_list" => {
            evolvable_object(
                &[
                    ("humanRequests", array_of(human_request_schema())),
                    ("nextCursor", nullable(string())),
                ],
                &["humanRequests", "nextCursor"],
            )
        }
        "loomex_human_respond" | "loomex_approval_decide" | "loomex_agent_task_respond" => {
            evolvable_object(
                &[
                    ("requestId", identifier()),
                    ("requestStatus", string()),
                    ("executionId", nullable(identifier())),
                    ("executionStatus", nullable(string())),
                ],
                &[
                    "requestId",
                    "requestStatus",
                    "executionId",
                    "executionStatus",
                ],
            )
        }
        "loomex_human_open" => evolvable_object(
            &[("humanRequest", evolvable_object(&[], &[]))],
            &["humanRequest"],
        ),
        "loomex_runner_status" => evolvable_object(
            &[
                ("running", boolean()),
                ("connection", availability_schema()),
                ("queue", availability_schema()),
                ("activeExecutions", availability_schema()),
                ("updateHealth", availability_schema()),
            ],
            &[
                "running",
                "connection",
                "queue",
                "activeExecutions",
                "updateHealth",
            ],
        ),
        "loomex_runner_control" => evolvable_object(
            &[
                ("action", enum_string(&["start", "stop", "restart"])),
                ("success", boolean()),
                ("results", array_of(evolvable_object(&[], &[]))),
                ("health", evolvable_object(&[], &[])),
            ],
            &["action", "success", "results", "health"],
        ),
        "loomex_runner_doctor" => evolvable_object(
            &[
                (
                    "schemaVersion",
                    json!({"const":"loomex.cli.runnerDoctor/v1"}),
                ),
                ("status", enum_string(&["ok", "warning", "failed"])),
                ("checks", array_of(doctor_check_schema())),
            ],
            &["status", "checks"],
        ),
        "loomex_runner_logs" => evolvable_object(
            &[
                ("entries", array_of(log_entry_schema())),
                ("nextCursor", nullable(string())),
            ],
            &["entries", "nextCursor"],
        ),
        _ => unreachable!("every advertised tool must have a data schema"),
    }
}

fn strict_object(properties: &[(&str, Value)], required: &[&str]) -> Value {
    object_with_additional(properties, required, false)
}

fn evolvable_object(properties: &[(&str, Value)], required: &[&str]) -> Value {
    object_with_additional(properties, required, true)
}

fn object_with_additional(
    properties: &[(&str, Value)],
    required: &[&str],
    additional_properties: bool,
) -> Value {
    let properties = properties
        .iter()
        .map(|(name, schema)| ((*name).to_string(), schema.clone()))
        .collect::<Map<_, _>>();
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":additional_properties,
    })
}

fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}

fn array_of(items: Value) -> Value {
    json!({"type":"array","items":items})
}

fn organization_schema() -> Value {
    evolvable_object(&[("id", identifier()), ("name", string())], &["id", "name"])
}

fn project_schema() -> Value {
    evolvable_object(
        &[
            ("id", identifier()),
            ("organizationId", identifier()),
            ("name", string()),
            ("status", string()),
        ],
        &["id", "organizationId", "name", "status"],
    )
}

fn binding_schema() -> Value {
    evolvable_object(
        &[
            ("id", identifier()),
            ("organizationId", identifier()),
            ("projectId", identifier()),
            ("runnerId", identifier()),
            ("localRootPath", path_string()),
            ("status", string()),
        ],
        &[
            "id",
            "organizationId",
            "projectId",
            "runnerId",
            "localRootPath",
            "status",
        ],
    )
}

fn workspace_schema() -> Value {
    evolvable_object(
        &[("path", path_string()), ("fingerprint", string())],
        &["path", "fingerprint"],
    )
}

fn workflow_schema() -> Value {
    evolvable_object(
        &[
            ("id", identifier()),
            ("name", string()),
            ("nodeCount", nonnegative_integer()),
            ("executionCount", nonnegative_integer()),
        ],
        &["id"],
    )
}

fn execution_schema() -> Value {
    evolvable_object(
        &[("id", identifier()), ("status", string())],
        &["id", "status"],
    )
}

fn run_detail_schema() -> Value {
    evolvable_object(
        &[
            ("execution", execution_schema()),
            ("humanRequest", nullable(evolvable_object(&[], &[]))),
            ("runner", nullable(evolvable_object(&[], &[]))),
            ("events", array_of(evolvable_object(&[], &[]))),
            ("aiTrace", nullable(evolvable_object(&[], &[]))),
            ("latestSequence", nonnegative_integer()),
            ("timedOut", boolean()),
        ],
        &[
            "execution",
            "humanRequest",
            "runner",
            "events",
            "aiTrace",
            "latestSequence",
            "timedOut",
        ],
    )
}

fn human_request_schema() -> Value {
    evolvable_object(
        &[
            ("id", identifier()),
            ("status", string()),
            ("title", string()),
            ("description", json!({"type":"string"})),
            ("blocking", boolean()),
        ],
        &["id", "status", "title", "description", "blocking"],
    )
}

fn auth_status_schema() -> Value {
    evolvable_object(
        &[
            ("authenticated", boolean()),
            ("userAuthenticated", boolean()),
            ("runnerAuthenticated", boolean()),
            ("profile", identifier()),
        ],
        &[
            "authenticated",
            "userAuthenticated",
            "runnerAuthenticated",
            "profile",
        ],
    )
}

fn availability_schema() -> Value {
    evolvable_object(&[("available", boolean())], &["available"])
}

fn doctor_check_schema() -> Value {
    evolvable_object(
        &[
            ("name", identifier()),
            ("status", enum_string(&["ok", "warning", "failed"])),
            ("message", json!({"type":"string"})),
        ],
        &["name", "status", "message"],
    )
}

fn log_entry_schema() -> Value {
    evolvable_object(
        &[
            ("timestamp_epoch_ms", nonnegative_integer()),
            ("level", string()),
            ("event_type", string()),
            ("message", json!({"type":"string"})),
            // Service lifecycle entries are intentionally uncorrelated and the
            // persisted LogEntry contract serializes those as an empty string.
            ("correlation_id", json!({"type":"string","maxLength":1024})),
        ],
        &[
            "timestamp_epoch_ms",
            "level",
            "event_type",
            "message",
            "correlation_id",
        ],
    )
}

fn string() -> Value {
    json!({"type":"string","minLength":1,"maxLength":1024})
}
fn short_string() -> Value {
    json!({"type":"string","minLength":1,"maxLength":500})
}
fn uri_string() -> Value {
    json!({"type":"string","format":"uri","minLength":1,"maxLength":2048})
}
fn path_string() -> Value {
    json!({"type":"string","minLength":1,"maxLength":4096})
}
fn identifier() -> Value {
    json!({"type":"string","minLength":1,"maxLength":200})
}
fn idempotency_key() -> Value {
    json!({"type":"string","minLength":8,"maxLength":160})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn const_true() -> Value {
    json!({"type":"boolean","const":true})
}
fn any_value() -> Value {
    json!({})
}
fn plugin_agent_response() -> Value {
    evolvable_object(
        &[
            (
                "status",
                enum_string(&["completed", "failed", "unavailable"]),
            ),
            ("output", json_object()),
            (
                "error",
                evolvable_object(
                    &[
                        ("code", string()),
                        ("message", string()),
                        ("provider", string()),
                        ("model", string()),
                    ],
                    &["message"],
                ),
            ),
            ("provider", string()),
            ("model", string()),
            (
                "agentSession",
                evolvable_object(
                    &[
                        ("id", json!({"type":"string","minLength":1,"maxLength":512})),
                        (
                            "host",
                            json!({"type":"string","minLength":1,"maxLength":120}),
                        ),
                        ("action", enum_string(&["spawned", "resumed"])),
                        ("provider", string()),
                        ("model", string()),
                    ],
                    &["id", "host", "action"],
                ),
            ),
        ],
        &["status"],
    )
}
fn json_object() -> Value {
    json!({"type":"object"})
}
fn nonnegative_integer() -> Value {
    json!({"type":"integer","minimum":0})
}
fn timeout_seconds() -> Value {
    json!({"type":"integer","minimum":1,"maximum":45,"default":30})
}
fn limit() -> Value {
    json!({"type":"integer","minimum":1,"maximum":200,"default":50})
}
fn enum_string(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}

fn ro() -> ToolAnnotations {
    ToolAnnotations {
        title: "Read Loomex local state",
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    }
}
fn open_ro() -> ToolAnnotations {
    ToolAnnotations {
        title: "Read Loomex service state",
        open_world_hint: true,
        ..ro()
    }
}
fn wait_ro() -> ToolAnnotations {
    ToolAnnotations {
        title: "Wait for Loomex state",
        open_world_hint: true,
        ..ro()
    }
}
fn mutating(destructive: bool, idempotent: bool, open_world: bool) -> ToolAnnotations {
    ToolAnnotations {
        title: "Change Loomex state",
        read_only_hint: false,
        destructive_hint: destructive,
        idempotent_hint: idempotent,
        open_world_hint: open_world,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn output_fixture(name: &str) -> Value {
        let organization = json!({"id":"org-1","name":"Loomex"});
        let project =
            json!({"id":"project-1","organizationId":"org-1","name":"Demo","status":"active"});
        let binding = json!({
            "id":"binding-1", "organizationId":"org-1", "projectId":"project-1",
            "runnerId":"runner-1", "localRootPath":"/workspace", "status":"active"
        });
        let run = || {
            json!({
                "execution":{"id":"run-1","status":"running"},
                "humanRequest":null, "runner":null, "events":[], "aiTrace":null,
                "latestSequence":0, "timedOut":false
            })
        };
        match name {
            "loomex_setup_status" => {
                json!({
                    "installed":false,"runtime":null,"runtimeRoot":"/runtime","service":{},"supported":true,
                    "setupRequired":true,"recommendedNextAction":"setup.plan",
                    "recommendationReason":"runtime_mismatch",
                    "bundledRuntime":{"available":true,"version":"1.0.0","pluginVersion":"1.0.0","channel":"stable","target":"aarch64-apple-darwin"},
                    "durableRuntime":{"installed":false,"runtime":null,"runtimeRoot":"/runtime","runtimeMatchesBundle":false,"serviceRegistered":false,"serviceActive":false}
                })
            }
            "loomex_setup_plan" => json!({
                "planId":"plan-1","action":"install","version":"1.0.0","pluginVersion":"1.0.0",
                "channel":"stable","target":"aarch64-apple-darwin","installService":true,
                "requiresConfirmation":true,"actions":["verify"]
            }),
            "loomex_setup_apply" => {
                json!({"installed":true,"version":"1.0.0","runtimePath":"/runtime/loomex","channel":"stable","installService":true,"service":{}})
            }
            "loomex_setup_rollback" => json!({"rolledBack":true,"version":"0.9.0"}),
            "loomex_auth_status" => {
                json!({"authenticated":false,"userAuthenticated":false,"runnerAuthenticated":false,"profile":"default"})
            }
            "loomex_auth_start" => {
                json!({"loginId":"login-1","verificationUri":"https://loomex.app/device","userCode":"ABCD","expiresInSeconds":600,"intervalSeconds":5})
            }
            "loomex_auth_wait" => json!({"authenticated":false,"pending":true,"loginId":"login-1"}),
            "loomex_auth_logout" => {
                json!({"profile":"default","localCredentialRemoved":true,"serverRevokeAttempted":true,"serverRevokeSucceeded":true})
            }
            "loomex_org_list" => json!({"items":[organization]}),
            "loomex_org_select" => {
                json!({"profile":"default","organization":organization,"changed":true})
            }
            "loomex_project_list" => json!({"items":[project],"organizationId":"org-1"}),
            "loomex_project_select" => {
                json!({"profile":"default","project":project,"changed":true})
            }
            "loomex_binding_list" => {
                json!({"bindings":[binding],"projectId":"project-1","notBootstrapped":false})
            }
            "loomex_binding_create" => json!({
                "profile":"default","projectId":"project-1","organizationId":"org-1","runnerId":"runner-1",
                "binding":binding,"workspace":{"path":"/workspace","fingerprint":"sha256:abc"},
                "bootstrapped":true,"reused":false
            }),
            "loomex_binding_revoke" => {
                json!({"revoked":true,"bindingId":"binding-1","projectId":"project-1","selectedBindingCleared":true})
            }
            "loomex_workflow_list" => {
                json!({"workflows":[{"id":"workflow-1","name":"Review"}],"nextCursor":null})
            }
            "loomex_workflow_show" => {
                json!({"workflow":{"id":"workflow-1","name":"Review"},"inputSchema":{},"activeVersion":null,"selectedVersion":null})
            }
            "loomex_workflow_run" | "loomex_run_get" | "loomex_run_wait" => run(),
            "loomex_run_list" => {
                json!({"executions":[{"id":"run-1","status":"running"}],"nextCursor":null})
            }
            "loomex_run_cancel" => json!({"execution":{"id":"run-1","status":"cancelled"}}),
            "loomex_human_list" => {
                json!({"humanRequests":[{"id":"human-1","status":"pending","title":"Review","description":"Please review","blocking":true}],"nextCursor":null})
            }
            "loomex_human_respond" => {
                json!({"requestId":"human-1","requestStatus":"resolved","executionId":"run-1","executionStatus":"running"})
            }
            "loomex_human_open" => {
                json!({"humanRequest":{"id":"human-1","status":"pending","title":"Review","description":"Please review","blocking":true}})
            }
            "loomex_agent_task_list" => {
                json!({"humanRequests":[{"id":"agent-1","status":"pending","title":"Run plugin agent task","description":"Execute in the current plugin host","blocking":true,"agentTask":{"schemaVersion":"loomex.plugin-agent-task/v1","executionStrategy":"plugin_host_sub_agent","provider":"plugin_host","model":"inherit","requestedProvider":"codex","requestedModel":"auto","prompt":"Summarize","input":{},"schemas":{},"instructions":{"strategy":"sub_agent","host":"current_plugin_host"}}}],"nextCursor":null})
            }
            "loomex_agent_task_respond" => {
                json!({"requestId":"agent-1","requestStatus":"resolved","executionId":"run-1","executionStatus":"running"})
            }
            "loomex_approval_list" => {
                json!({"humanRequests":[{"id":"approval-1","status":"pending","title":"Approve","description":"Please approve","blocking":true}],"nextCursor":null})
            }
            "loomex_approval_decide" => {
                json!({"requestId":"approval-1","requestStatus":"resolved","executionId":"run-1","executionStatus":"running"})
            }
            "loomex_runner_status" => json!({
                "running":true,"connection":{"available":true},"queue":{"available":false},
                "activeExecutions":{"available":false},"updateHealth":{"available":false}
            }),
            "loomex_runner_control" => {
                json!({"action":"restart","success":true,"results":[],"health":{}})
            }
            "loomex_runner_doctor" => {
                json!({"schemaVersion":"loomex.cli.runnerDoctor/v1","status":"ok","checks":[{"name":"config","status":"ok","message":"valid"}]})
            }
            "loomex_runner_logs" => {
                json!({"entries":[{"timestamp_epoch_ms":1,"level":"info","event_type":"runner","message":"ready","correlation_id":"corr-1"}],"nextCursor":null})
            }
            _ => panic!("fixture missing for {name}"),
        }
    }

    fn envelope(name: &str, data: Value) -> Value {
        json!({
            "schemaVersion":"loomex.mcp/v1", "ok":true, "tool":name, "data":data,
            "meta":{"requestId":"request-1","timestampMs":1}
        })
    }

    fn failure(name: &str) -> Value {
        json!({
            "schemaVersion":"loomex.mcp/v1", "ok":false, "tool":name,
            "error":{"code":"RUNNER_UNAVAILABLE","message":"runner unavailable","retryable":true},
            "meta":{"requestId":"request-1","timestampMs":1}
        })
    }

    #[test]
    fn every_tool_has_a_unique_route_and_strict_top_level_schema() {
        let definitions = definitions();
        assert_eq!(definitions.len(), 33);
        let mut names = HashSet::new();
        for tool in definitions {
            assert!(names.insert(tool.name));
            assert_eq!(tool.input_schema["additionalProperties"], false);
            assert!(route(tool.name).is_some());
        }
    }

    #[test]
    fn human_input_tools_publish_app_visibility_metadata() {
        let definitions = definitions();
        let open = definitions
            .iter()
            .find(|definition| definition.name == "loomex_human_open")
            .unwrap();
        let respond = definitions
            .iter()
            .find(|definition| definition.name == "loomex_human_respond")
            .unwrap();

        assert_eq!(
            open.meta.as_ref().unwrap()["ui"]["resourceUri"],
            HUMAN_INPUT_APP_URI
        );
        assert_eq!(
            open.meta.as_ref().unwrap()["ui"]["visibility"],
            json!(["model"])
        );
        assert_eq!(
            respond.meta.as_ref().unwrap()["ui"]["visibility"],
            json!(["model", "app"])
        );
    }

    #[test]
    fn list_tools_publish_table_template_metadata() {
        for name in [
            "loomex_org_list",
            "loomex_project_list",
            "loomex_workflow_list",
        ] {
            let definition = definitions()
                .into_iter()
                .find(|definition| definition.name == name)
                .unwrap();
            assert_eq!(
                definition.meta.as_ref().unwrap()["ui"]["resourceUri"],
                LIST_TABLE_APP_URI
            );
            assert_eq!(
                definition.meta.as_ref().unwrap()["openai/outputTemplate"],
                LIST_TABLE_APP_URI
            );
            assert_eq!(
                definition.meta.as_ref().unwrap()["ui"]["visibility"],
                json!(["model", "app"])
            );
        }
    }

    #[test]
    fn every_tool_has_a_tool_specific_output_schema_and_valid_success_fixture() {
        for definition in definitions() {
            let variants = definition.output_schema["oneOf"]
                .as_array()
                .expect("output envelope must be discriminated");
            assert_eq!(variants.len(), 2, "{}", definition.name);
            let success_data = &variants[0]["properties"]["data"];
            assert_ne!(
                success_data,
                &json!({}),
                "{} has generic data",
                definition.name
            );
            validate_output(
                &definition.output_schema,
                &envelope(definition.name, output_fixture(definition.name)),
            )
            .unwrap_or_else(|error| panic!("{} success fixture: {error}", definition.name));
        }
    }

    #[test]
    fn every_tool_failure_uses_the_same_valid_discriminated_envelope() {
        for definition in definitions() {
            validate_output(&definition.output_schema, &failure(definition.name))
                .unwrap_or_else(|error| panic!("{} failure fixture: {error}", definition.name));
        }
    }

    #[test]
    fn setup_status_contract_accepts_legacy_additive_and_future_shapes() {
        let definition = definition("loomex_setup_status").unwrap();
        let legacy = json!({
            "installed":false,"runtime":null,"runtimeRoot":"/runtime","service":{},"supported":true
        });
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, legacy.clone()),
        )
        .unwrap();

        let mut additive = legacy;
        additive["setupRequired"] = json!(true);
        additive["recommendedNextAction"] = json!("setup.plan");
        additive["recommendationReason"] = json!("runtime_mismatch");
        additive["bundledRuntime"] = json!({
            "available":true,"version":"1.0.0","pluginVersion":"1.0.0",
            "channel":"stable","target":"aarch64-apple-darwin"
        });
        additive["durableRuntime"] = json!({
            "installed":false,"runtime":null,"runtimeRoot":"/runtime",
            "runtimeMatchesBundle":false,"serviceRegistered":false,"serviceActive":false
        });
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, additive.clone()),
        )
        .unwrap();

        additive["setupRequired"] = json!(false);
        additive["recommendedNextAction"] = json!("binding.create");
        additive["recommendationReason"] = json!("runner_identity_mismatch");
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, additive.clone()),
        )
        .unwrap();

        additive["futureExtra"] = json!({"allowed": true});
        additive["bundledRuntime"]["futurePackageField"] = json!(1);
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, additive),
        )
        .unwrap();
    }

    #[test]
    fn output_envelopes_reject_wrong_tools_and_mixed_success_failure_payloads() {
        let definition = definition("loomex_runner_logs").unwrap();
        let mut wrong_tool = envelope("loomex_runner_status", output_fixture("loomex_runner_logs"));
        assert!(validate_output(&definition.output_schema, &wrong_tool).is_err());
        wrong_tool["tool"] = json!("loomex_runner_logs");
        wrong_tool["error"] = json!({"code":"NOPE","message":"mixed","retryable":false});
        assert!(validate_output(&definition.output_schema, &wrong_tool).is_err());
    }

    #[test]
    fn runner_logs_structured_content_accepts_serialized_service_log_entries() {
        let definition = definition("loomex_runner_logs").unwrap();
        // Exact serde_json shapes emitted by LogEntry::new, before and after
        // with_correlation_id. Unknown future fields remain evolvable.
        let service_entry = json!({
            "timestamp_epoch_ms": 1,
            "level": "info",
            "event_type": "runner.connected",
            "message": "runner service connected",
            "correlation_id": "",
            "workflow_run_id": null,
            "tool_call_id": null,
            "metadata": {},
        });
        let correlated_entry = json!({
            "timestamp_epoch_ms": 2,
            "level": "info",
            "event_type": "workflow.started",
            "message": "workflow started",
            "correlation_id": "run-123",
            "workflow_run_id": null,
            "tool_call_id": null,
            "metadata": {},
        });
        let structured_content = envelope(
            definition.name,
            json!({
                "entries": [service_entry, correlated_entry],
                "nextCursor": null,
            }),
        );

        assert_eq!(
            structured_content["data"]["entries"][0]["correlation_id"],
            ""
        );
        assert_eq!(
            structured_content["data"]["entries"][1]["correlation_id"],
            "run-123"
        );
        validate_output(&definition.output_schema, &structured_content).unwrap();
    }

    #[test]
    fn doctor_output_accepts_daemon_and_bootstrap_shapes() {
        let definition = definition("loomex_runner_doctor").unwrap();
        let daemon = json!({
            "status":"warning",
            "checks":[{"name":"workspace","status":"warning","message":"not bound"}]
        });
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, daemon),
        )
        .unwrap();
        validate_output(
            &definition.output_schema,
            &envelope(definition.name, output_fixture(definition.name)),
        )
        .unwrap();
    }

    #[test]
    fn wait_timeout_is_bounded_and_unknown_arguments_are_rejected() {
        let schema = definition("loomex_run_wait").unwrap().input_schema;
        assert!(
            validate_arguments(&schema, &json!({"executionId":"run-1","timeoutSeconds":45}))
                .is_ok()
        );
        assert!(
            validate_arguments(&schema, &json!({"executionId":"run-1","timeoutSeconds":46}))
                .is_err()
        );
        assert!(
            validate_arguments(&schema, &json!({"executionId":"run-1","surprise":true})).is_err()
        );
        assert!(
            validate_arguments(&schema, &json!({"executionId":"run-1","timeoutSeconds":-1}))
                .is_err()
        );
    }

    #[test]
    fn durable_mutations_require_retry_keys_and_cancel_reason() {
        let run_definition = definition("loomex_workflow_run").unwrap();
        assert!(run_definition.annotations.idempotent_hint);
        let run = run_definition.input_schema;
        assert!(validate_arguments(
            &run,
            &json!({"workflowId":"workflow-1","bindingId":"binding-1"})
        )
        .is_err());
        assert!(validate_arguments(
            &run,
            &json!({
                "workflowId":"workflow-1",
                "bindingId":"binding-1",
                "idempotencyKey":"run-attempt-1"
            })
        )
        .is_ok());

        let cancel_definition = definition("loomex_run_cancel").unwrap();
        assert!(cancel_definition.annotations.idempotent_hint);
        let cancel = cancel_definition.input_schema;
        assert!(validate_arguments(
            &cancel,
            &json!({"executionId":"run-1","idempotencyKey":"cancel-1"})
        )
        .is_err());
        assert!(validate_arguments(
            &cancel,
            &json!({
                "executionId":"run-1",
                "reason":"No longer needed",
                "idempotencyKey":"cancel-1"
            })
        )
        .is_ok());
    }

    #[test]
    fn idempotency_keys_match_backend_length_boundary() {
        let schema = definition("loomex_workflow_run").unwrap().input_schema;
        let input = |key: String| {
            json!({
                "workflowId":"workflow-1",
                "bindingId":"binding-1",
                "idempotencyKey":key
            })
        };
        assert!(validate_arguments(&schema, &input("k".repeat(160))).is_ok());
        assert!(validate_arguments(&schema, &input("k".repeat(161))).is_err());
    }

    #[test]
    fn human_and_approval_lists_accept_pagination_cursor() {
        for name in ["loomex_human_list", "loomex_approval_list"] {
            let schema = definition(name).unwrap().input_schema;
            assert!(validate_arguments(
                &schema,
                &json!({"cursor":"2026-07-21T10:00:00Z:item-2","limit":25})
            )
            .is_ok());
        }
    }

    #[test]
    fn auth_wait_is_a_non_idempotent_open_world_state_change() {
        let annotations = definition("loomex_auth_wait").unwrap().annotations;
        assert!(!annotations.read_only_hint);
        assert!(!annotations.idempotent_hint);
        assert!(!annotations.destructive_hint);
        assert!(annotations.open_world_hint);
    }
}
