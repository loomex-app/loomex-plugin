#![cfg(unix)]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use loomex_protocol::{
    AgentDeliveryRouteV2, AgentErrorCode, AgentExecutionBindingV2, AgentExecutionRequirements,
    AgentExecutorCapability, AgentProcessDeliveryV2, AgentProcessDispatchV2,
    AgentProcessRetryKindV2, AgentProvider, AgentRuntimeFeatures, AgentSessionContinuationV2,
    AgentTaskRequestV2, AuthenticationState, ExecutorKind, InstallationState, ModelDiscoveryKind,
    ModelFallbackPolicy, ModelSelection, ModelSelectionMode, ModelTarget, ReasoningEffort,
    RuntimeReadiness, AGENT_PROCESS_DISPATCH_SCHEMA_V2, AGENT_SESSION_SCHEMA_V2,
    AGENT_TASK_SCHEMA_V2,
};
use serde_json::json;

use super::runtime::{ensure_ready, Candidate};
use super::*;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "loomex-agent-runtime-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn adapters_build_fixed_allowlisted_argv_and_keep_prompt_out_of_args() {
    let temp = TempDir::new();
    let schema = json!({"type": "object"});
    let invocation = ExecutionInvocation {
        executable: &temp.0.join("codex"),
        workspace: &temp.0,
        prompt: "secret prompt",
        provider_model_id: Some("gpt-5.2"),
        reasoning_effort: Some(ReasoningEffort::High),
        output_schema: Some(&schema),
        mode: InvocationMode::Start,
    };
    let codex = CodexAdapter.build_execution(&invocation).unwrap();
    assert_eq!(codex.executable, temp.0.join("codex"));
    assert!(codex.args.iter().any(|arg| arg == "--model=gpt-5.2"));
    assert!(!codex.args.iter().any(|arg| arg == "--model"));
    assert!(codex
        .args
        .windows(2)
        .any(|args| args == ["--config", "model_reasoning_effort=\"high\""]));
    assert!(!codex.args.iter().any(|arg| arg.contains("secret prompt")));
    assert_eq!(codex.stdin, b"secret prompt");
    assert!(!codex.args.iter().any(|arg| arg.contains("dangerously")));

    let claude = ClaudeAdapter
        .build_execution(&ExecutionInvocation {
            executable: &temp.0.join("claude"),
            workspace: &temp.0,
            prompt: "prompt",
            provider_model_id: Some("claude-sonnet-4-6"),
            reasoning_effort: Some(ReasoningEffort::Xhigh),
            output_schema: Some(&schema),
            mode: InvocationMode::Start,
        })
        .unwrap();
    assert!(claude
        .args
        .iter()
        .any(|arg| arg == "--model=claude-sonnet-4-6"));
    assert!(!claude.args.iter().any(|arg| arg == "--model"));
    assert!(claude
        .args
        .windows(2)
        .any(|args| args == ["--effort", "xhigh"]));
    assert!(claude.args.iter().any(|arg| arg == "--json-schema"));
}

#[test]
fn runtime_v2_disabled_dispatch_error_is_terminal_without_remediation() {
    let error = runtime_error(
        AgentErrorCode::AgentRuntimeV2Disabled,
        "Agent runtime v2 is disabled for this dispatch.",
        RuntimeErrorContext::default(),
    );
    assert_eq!(error.retry, loomex_protocol::AgentRetryDisposition::Never);
    assert!(error.remediation.is_empty());
    assert!(error.context.session_id.is_none());
    assert!(error.validate().is_ok());
}

#[test]
fn public_runtime_entry_requires_a_valid_process_dispatch_wrapper() {
    let temp = TempDir::new();
    let marker = temp.0.join("executed");
    let codex = temp.script(
        "codex",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
             if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
             touch '{}'\n\
             echo '{{\"thread_id\":\"dispatch-session\",\"text\":\"done\"}}'",
            marker.display()
        ),
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let mut dispatch = AgentProcessDispatchV2 {
        schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
        execution_id: "execution-node-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        attempt_number: 1,
        retry_kind: AgentProcessRetryKindV2::Initial,
        from_attempt_id: None,
        delivery: AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::DirectControl,
            runner_job_id: None,
            lease_target_runner_id: None,
        },
        task_idempotency_key: format!("loomex-agent-attempt-v2:{}", "1".repeat(64)),
        delivery_idempotency_key: format!("loomex-agent-delivery-v2:{}", "2".repeat(64)),
        payload_digest: format!("sha256:{}", "3".repeat(64)),
        task: request(exact_codex(), None),
    };
    dispatch.payload_digest = dispatch.computed_payload_digest().unwrap();
    let mut invalid = dispatch.clone();
    invalid.payload_digest = "sha256:not-a-digest".to_string();
    let error = LocalAgentRuntime::default()
        .execute(&invalid, &config, &temp.0, &CancellationToken::default())
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::InvalidRequest);
    assert!(!marker.exists());

    let result = LocalAgentRuntime::default()
        .execute(&dispatch, &config, &temp.0, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.output.content, "done");
    assert!(marker.exists());
}

#[test]
fn adapters_reject_adversarial_model_and_session_identifiers_before_building_argv() {
    let temp = TempDir::new();
    let oversized_model = "a".repeat(193);
    for model in [
        "-gpt-5.2",
        "gpt-5.2\n--dangerously-skip-permissions",
        "gpt\0model",
        "openai/../secret",
        oversized_model.as_str(),
    ] {
        let error = CodexAdapter
            .build_execution(&ExecutionInvocation {
                executable: &temp.0.join("codex"),
                workspace: &temp.0,
                prompt: "prompt",
                provider_model_id: Some(model),
                reasoning_effort: None,
                output_schema: None,
                mode: InvocationMode::Start,
            })
            .unwrap_err();
        assert_eq!(error, AdapterInvocationError::InvalidModelIdentifier);
    }

    let oversized_session = "s".repeat(257);
    for session in [
        "-session",
        "session\n--help",
        "session\0id",
        "provider/../session",
        oversized_session.as_str(),
    ] {
        let error = CodexAdapter
            .build_execution(&ExecutionInvocation {
                executable: &temp.0.join("codex"),
                workspace: &temp.0,
                prompt: "prompt",
                provider_model_id: Some("gpt-5.2"),
                reasoning_effort: None,
                output_schema: None,
                mode: InvocationMode::ResumeExact {
                    provider_session_id: session.to_string(),
                },
            })
            .unwrap_err();
        assert_eq!(error, AdapterInvocationError::InvalidSessionIdentifier);
    }
}

#[test]
fn agy_json_model_discovery_filters_non_gemini_unsafe_and_duplicate_ids() {
    let models = AgyAdapter.parse_models(
        r#"{"models":[
            {"id":"claude-sonnet-4-6"},
            {"id":"gemini-2.5-pro"},
            {"name":"gemini-2.5-pro"},
            "gemini-2.0-flash",
            {"id":"gemini-bad\n--flag"},
            {"id":"gemini/../secret"},
            {"id":"403"}
        ]}"#,
    );
    assert_eq!(
        models,
        vec![
            (
                "gemini-2.0-flash".to_string(),
                "gemini-2.0-flash".to_string()
            ),
            ("gemini-2.5-pro".to_string(), "gemini-2.5-pro".to_string()),
        ]
    );
}

#[test]
fn registry_accepts_agy_only_and_never_aliases_gemini() {
    let registry = AdapterRegistry::default();
    assert_eq!(registry.resolve_alias("google"), Some(ExecutorKind::AgyCli));
    assert_eq!(
        registry.resolve_alias("agy_cli"),
        Some(ExecutorKind::AgyCli)
    );
    assert_eq!(registry.resolve_alias("agy"), Some(ExecutorKind::AgyCli));
    assert_eq!(registry.resolve_alias("gemini"), None);
    assert_eq!(registry.resolve_alias("gemini_cli"), None);
    assert_eq!(
        registry
            .get(ExecutorKind::AgyCli)
            .unwrap()
            .executable_name(),
        "agy"
    );
}

#[test]
fn exact_resume_uses_the_same_session_and_model() {
    let temp = TempDir::new();
    let invocation = ExecutionInvocation {
        executable: &temp.0.join("codex"),
        workspace: &temp.0,
        prompt: "continue",
        provider_model_id: Some("gpt-5.2"),
        reasoning_effort: Some(ReasoningEffort::High),
        output_schema: None,
        mode: InvocationMode::ResumeExact {
            provider_session_id: "session-123".to_string(),
        },
    };
    let codex = CodexAdapter.build_execution(&invocation).unwrap();
    // Captured from the codex-cli 0.144.6 `exec resume --help` parser:
    // resume accepts --json, --skip-git-repo-check and --model, but not the
    // parent `exec` command's --color option.
    assert_eq!(
        codex.args,
        [
            "exec",
            "resume",
            "--json",
            "--skip-git-repo-check",
            "--model=gpt-5.2",
            "--config",
            "model_reasoning_effort=\"high\"",
            "--",
            "session-123",
            "-"
        ]
    );
    assert!(!codex.args.iter().any(|arg| arg == "--color"));

    let agy = AgyAdapter.build_execution(&ExecutionInvocation {
        executable: &temp.0.join("agy"),
        workspace: &temp.0,
        prompt: "continue",
        provider_model_id: Some("gemini-2.5-pro"),
        reasoning_effort: None,
        output_schema: None,
        mode: InvocationMode::ResumeExact {
            provider_session_id: "conversation-1".to_string(),
        },
    });
    assert_eq!(agy.unwrap_err(), AdapterInvocationError::UnsupportedResume);
    assert!(!AgyAdapter.features().session_resume);
}

#[test]
fn installed_codex_resume_parser_smoke_when_explicitly_configured() {
    let Some(executable) = std::env::var_os("LOOMEX_TEST_CODEX_BIN").map(PathBuf::from) else {
        return;
    };
    let workspace = std::env::current_dir().unwrap();
    let invocation = ExecutionInvocation {
        executable: &executable,
        workspace: &workspace,
        prompt: "continue",
        provider_model_id: Some("gpt-5.2"),
        reasoning_effort: Some(ReasoningEffort::High),
        output_schema: None,
        mode: InvocationMode::ResumeExact {
            provider_session_id: "00000000-0000-0000-0000-000000000000".to_string(),
        },
    };
    let spec = CodexAdapter.build_execution(&invocation).unwrap();
    let output = std::process::Command::new(&spec.executable)
        .args(&spec.args)
        .current_dir(&workspace)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unexpected option"),
        "codex resume argv did not reach session lookup: {stderr}"
    );
}

#[test]
fn resumed_session_receives_safe_continuation_prompt_not_original_task() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         cat > \"$(dirname \"$0\")/received-prompt\"\n\
         echo '{\"thread_id\":\"resume-session\",\"text\":\"continued\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let mut resumed_request = request(exact_codex(), None);
    resumed_request.prompt = "ORIGINAL TASK WITH SIDE EFFECT".to_string();
    resumed_request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "checkpoint-1".to_string(),
        sequence: 1,
        session_id: "loomex-session-1".to_string(),
        provider_session_id: "resume-session".to_string(),
        binding: resumed_request.binding.clone(),
        selection_index: 0,
        executor: ExecutorKind::CodexCli,
        provider: AgentProvider::OpenAi,
        model_key: Some("gpt-5.2".to_string()),
        provider_model_id: Some("gpt-5.2".to_string()),
    });
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(
            &resumed_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(result.output.content, "continued");
    let prompt = fs::read_to_string(temp.0.join("received-prompt")).unwrap();
    assert!(!prompt.contains("ORIGINAL TASK"));
    assert!(prompt.contains("Do not repeat"));
    assert!(prompt.contains("complete only unfinished work"));
}

#[test]
fn structured_resume_prompt_is_repair_phase_aware_without_replaying_original_task() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         cat > \"$(dirname \"$0\")/received-prompt\"\n\
         echo '{\"thread_id\":\"repair-resume\",\"text\":\"{\\\"ok\\\":true}\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"]
    });
    let mut resumed_request = request(exact_codex(), Some(schema));
    resumed_request.prompt = "ORIGINAL STRUCTURED TASK".to_string();
    resumed_request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "checkpoint-repair".to_string(),
        sequence: 2,
        session_id: "loomex-repair-session".to_string(),
        provider_session_id: "repair-resume".to_string(),
        binding: resumed_request.binding.clone(),
        selection_index: 0,
        executor: ExecutorKind::CodexCli,
        provider: AgentProvider::OpenAi,
        model_key: Some("gpt-5.2".to_string()),
        provider_model_id: Some("gpt-5.2".to_string()),
    });
    LocalAgentRuntime::default()
        .execute_task_for_test(
            &resumed_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    let prompt = fs::read_to_string(temp.0.join("received-prompt")).unwrap();
    assert!(!prompt.contains("ORIGINAL STRUCTURED TASK"));
    assert!(prompt.contains("structured-output repair"));
    assert!(prompt.contains("corrected JSON"));
}

#[test]
fn auto_selection_never_invents_or_passes_a_model_flag() {
    let temp = TempDir::new();
    let command = CodexAdapter
        .build_execution(&ExecutionInvocation {
            executable: &temp.0.join("codex"),
            workspace: &temp.0,
            prompt: "auto",
            provider_model_id: None,
            reasoning_effort: None,
            output_schema: None,
            mode: InvocationMode::Start,
        })
        .unwrap();
    assert!(!command.args.iter().any(|arg| arg == "--model"));
    assert!(!command.args.iter().any(|arg| arg == "-m"));
}

#[test]
fn auto_resume_pins_checkpoint_model_when_provider_default_changed() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         echo \"$*\" > \"$(dirname \"$0\")/execution-args\"\n\
         case \" $* \" in\n\
           *' --model=gpt-checkpoint '*) selected='gpt-checkpoint' ;;\n\
           *) selected='provider-new-default' ;;\n\
         esac\n\
         printf '{\"type\":\"thread.started\",\"thread_id\":\"checkpoint-session\"}\\n'\n\
         printf '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"%s\"}}\\n' \"$selected\"",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let mut request = request(
        ModelSelection {
            primary: ModelSelectionMode::Auto {
                executor: ExecutorKind::CodexCli,
                provider: AgentProvider::OpenAi,
            },
            fallback: ModelFallbackPolicy::None,
        },
        None,
    );
    request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "checkpoint-1".to_string(),
        sequence: 1,
        session_id: "loomex-session-1".to_string(),
        provider_session_id: "checkpoint-session".to_string(),
        binding: request.binding.clone(),
        selection_index: 0,
        executor: ExecutorKind::CodexCli,
        provider: AgentProvider::OpenAi,
        model_key: Some("catalog-checkpoint".to_string()),
        provider_model_id: Some("gpt-checkpoint".to_string()),
    });
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(&request, &config, &temp.0, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.output.content, "gpt-checkpoint");
    assert_eq!(
        result
            .model
            .as_ref()
            .map(|target| target.provider_model_id.as_str()),
        Some("gpt-checkpoint")
    );
    let args = fs::read_to_string(temp.0.join("execution-args")).unwrap();
    assert!(args.contains("resume --json"));
    assert!(args.contains("-- checkpoint-session"));
    assert!(args.contains("--model=gpt-checkpoint"));
    assert!(!args.contains("provider-new-default"));
}

#[test]
fn unresolved_auto_checkpoints_resume_codex_and_claude_without_model_override() {
    #[derive(Default)]
    struct Observer(Mutex<Vec<SessionDiscovery>>);
    impl AgentRuntimeObserver for Observer {
        fn on_session_initialized(
            &self,
            session: SessionDiscovery,
        ) -> Result<(), loomex_protocol::AgentRuntimeErrorEnvelopeV2> {
            self.0.lock().unwrap().push(session);
            Ok(())
        }
    }

    for (executor, provider, executable_name, script) in [
        (
            ExecutorKind::CodexCli,
            AgentProvider::OpenAi,
            "codex",
            "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
             if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
             echo \"$*\" >> \"$(dirname \"$0\")/args\"\n\
             echo '{\"type\":\"thread.started\",\"thread_id\":\"auto-session\"}'\n\
             case \" $* \" in *' resume '*) echo '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"resumed\"}}'; exit 0 ;; esac\n\
             echo 'crash after session' >&2; exit 1",
        ),
        (
            ExecutorKind::ClaudeCli,
            AgentProvider::Anthropic,
            "claude",
            "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
             if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
             echo \"$*\" >> \"$(dirname \"$0\")/args\"\n\
             echo '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"auto-session\"}'\n\
             case \" $* \" in *' --resume auto-session '*) echo '{\"type\":\"result\",\"session_id\":\"auto-session\",\"result\":\"resumed\"}'; exit 0 ;; esac\n\
             echo 'crash after session' >&2; exit 1",
        ),
    ] {
        let temp = TempDir::new();
        let executable = temp.script(executable_name, script);
        let mut config = RuntimeConfig::default();
        config.executables.insert(executor, executable);
        let selection = ModelSelection {
            primary: ModelSelectionMode::Auto { executor, provider },
            fallback: ModelFallbackPolicy::None,
        };
        let first_request = request(selection.clone(), None);
        let observer = Arc::new(Observer::default());
        let first_error = LocalAgentRuntime::default()
            .execute_task_observed_for_test(
                &first_request,
                &config,
                &temp.0,
                &CancellationToken::default(),
                observer.clone(),
            )
            .unwrap_err();
        assert_eq!(first_error.code, AgentErrorCode::ExecutionIndeterminate);
        let sessions = observer.0.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].model_key, None);
        assert_eq!(sessions[0].provider_model_id, None);
        drop(sessions);

        let mut resume_request = request(selection, None);
        resume_request.continuation = Some(AgentSessionContinuationV2 {
            schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: "checkpoint-auto".to_string(),
            sequence: 1,
            session_id: "loomex-auto-session".to_string(),
            provider_session_id: "auto-session".to_string(),
            binding: resume_request.binding.clone(),
            selection_index: 0,
            executor,
            provider,
            model_key: None,
            provider_model_id: None,
        });
        let resumed = LocalAgentRuntime::default()
            .execute_task_for_test(
                &resume_request,
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(resumed.output.content, "resumed");
        assert_eq!(resumed.model, None);
        let args = fs::read_to_string(temp.0.join("args")).unwrap();
        assert!(!args.contains("--model"));
        assert!(!args.contains("model=auto"));
    }
}

#[test]
fn parses_json_jsonl_and_plain_output() {
    let claude = parse_agent_output(
        r#"{"type":"result","session_id":"s1","result":"{\"ok\":true}","structured_output":{"ok":true}}"#,
    )
    .unwrap();
    assert_eq!(claude.provider_session_id.as_deref(), Some("s1"));
    assert_eq!(claude.structured, Some(json!({"ok": true})));

    let codex = parse_agent_output(
        "{\"type\":\"thread.started\",\"thread_id\":\"t1\"}\n\
         {\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"done\"}}",
    )
    .unwrap();
    assert_eq!(codex.provider_session_id.as_deref(), Some("t1"));
    assert_eq!(codex.text, "done");

    assert_eq!(parse_agent_output("hello").unwrap().text, "hello");
}

#[test]
fn schema_validation_covers_objects_arrays_and_combinators() {
    let schema = json!({
        "type": "object",
        "required": ["name", "scores"],
        "additionalProperties": false,
        "properties": {
            "name": {"type": "string", "minLength": 2},
            "scores": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "integer", "minimum": 0}
            }
        }
    });
    assert!(validate_json_schema(&json!({"name": "ok", "scores": [1]}), &schema).is_ok());
    let violations =
        validate_json_schema(&json!({"name": "", "scores": [-1], "extra": true}), &schema)
            .unwrap_err();
    assert!(violations
        .iter()
        .any(|violation| violation.path == "$.name"));
    assert!(violations
        .iter()
        .any(|violation| violation.path == "$.scores[0]"));
    assert!(violations
        .iter()
        .any(|violation| violation.path == "$.extra"));
}

#[test]
fn unsupported_and_recursive_output_schemas_fail_before_any_process_spawn() {
    let temp = TempDir::new();
    let marker = temp.0.join("spawned");
    let codex = temp.script(
        "codex",
        "touch \"$(dirname \"$0\")/spawned\"\n\
         echo '{\"thread_id\":\"session\",\"text\":\"{}\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);

    let schemas = [
        json!({"type": "object", "pattern": "^ok$"}),
        json!({"type": "object", "$ref": "#"}),
        json!({
            "type": "object",
            "$defs": {
                "a": {"$ref": "#/$defs/b"},
                "b": {"$ref": "#/$defs/a"}
            },
            "$ref": "#/$defs/a"
        }),
    ];
    for schema in schemas {
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(
                &request(exact_codex(), Some(schema)),
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::UnsupportedCapability);
        assert!(!marker.exists());
    }
}

#[test]
fn structured_schema_contract_rejects_missing_empty_scalar_and_array_roots_before_spawn() {
    let temp = TempDir::new();
    let marker = temp.0.join("spawned");
    let codex = temp.script(
        "codex",
        "touch \"$(dirname \"$0\")/spawned\"\n\
         echo '{\"thread_id\":\"session\",\"text\":\"{}\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);

    let mut missing = request(exact_codex(), None);
    missing.requirements.structured_output = true;
    let invalid_requests = [
        missing,
        request(exact_codex(), Some(json!({}))),
        request(exact_codex(), Some(json!({"type": "string"}))),
        request(exact_codex(), Some(json!({"type": "array"}))),
    ];
    for invalid in invalid_requests {
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(&invalid, &config, &temp.0, &CancellationToken::default())
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::InvalidRequest);
        assert!(!marker.exists());
    }

    let object_schema = request(exact_codex(), Some(json!({"type": "object"})));
    assert!(object_schema.validate().is_ok());
}

#[test]
fn terminal_structured_output_accepts_objects_and_rejects_scalars_and_arrays() {
    for (label, terminal_json, expected_error) in [
        ("object", r#"{"ok":true}"#, None),
        ("array", r#"[1,2]"#, Some(AgentErrorCode::OutputInvalid)),
        ("scalar", r#"42"#, Some(AgentErrorCode::OutputInvalid)),
    ] {
        let temp = TempDir::new();
        let codex = temp.script(
            "codex",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
                 if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
                 echo '{{\"thread_id\":\"shape-session\",\"structured_output\":{terminal_json}}}'"
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::CodexCli, codex);
        let result = LocalAgentRuntime::default().execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        );
        match expected_error {
            Some(expected) => assert_eq!(result.unwrap_err().code, expected, "{label}"),
            None => {
                let output = result.unwrap().output;
                assert_eq!(output.structured, Some(json!({"ok": true})));
                assert!(output.structured.as_ref().unwrap().is_object());
            }
        }
    }
}

#[test]
fn capability_version_is_bounded_and_never_exposes_raw_probe_output() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then\n\
           echo 'codex 1.2.3-super-secret token=super-secret /Users/private/account'; exit 0\n\
         fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let capability = LocalAgentRuntime::default().probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        true,
    );
    assert_eq!(capability.executor_version.as_deref(), Some("1.2.3"));
    let serialized = serde_json::to_string(&capability).unwrap();
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("/Users/private"));
    assert!(!serialized.contains("token="));
}

#[test]
fn process_runner_bounds_output_and_redacts_diagnostics() {
    let temp = TempDir::new();
    let script = temp.script(
        "noisy",
        "printf 'abcdefghijk'\nprintf 'token=super-secret\\n/home/user/private' >&2",
    );
    let runner = ProcessRunner::new(["PATH", "HOME"]);
    let output = runner
        .run(
            &CommandSpec::new(script, Vec::<String>::new()).cwd(&temp.0),
            &ProcessLimits {
                timeout: Duration::from_secs(30),
                max_stdout_bytes: 5,
                max_stderr_bytes: 1024,
                ..ProcessLimits::default()
            },
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(output.stdout, "abcde");
    assert!(output.stdout_truncated);
    assert!(!output.stderr.contains("super-secret"));
    assert!(output.stderr.contains("[REDACTED]"));
}

#[test]
fn process_runner_times_out_and_cancels_process_groups() {
    let temp = TempDir::new();
    let script = temp.script("slow", "sleep 10");
    let runner = ProcessRunner::default();
    let timeout = runner
        .run(
            &CommandSpec::new(&script, Vec::<String>::new()).cwd(&temp.0),
            &ProcessLimits {
                timeout: Duration::from_millis(80),
                terminate_grace: Duration::from_millis(20),
                ..ProcessLimits::default()
            },
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(timeout.timed_out);

    let cancellation = CancellationToken::default();
    let cancellation_worker = cancellation.clone();
    let script_for_thread = script.clone();
    let workspace = temp.0.clone();
    let handle = thread::spawn(move || {
        ProcessRunner::default()
            .run(
                &CommandSpec::new(script_for_thread, Vec::<String>::new()).cwd(workspace),
                &ProcessLimits {
                    timeout: Duration::from_secs(3),
                    terminate_grace: Duration::from_millis(20),
                    ..ProcessLimits::default()
                },
                &cancellation_worker,
            )
            .unwrap()
    });
    thread::sleep(Duration::from_millis(60));
    cancellation.cancel();
    assert!(handle.join().unwrap().cancelled);
}

#[test]
fn process_runner_does_not_hang_when_a_descendant_inherits_output_pipes() {
    let temp = TempDir::new();
    let script = temp.script(
        "orphan-pipe",
        "(sleep 30; touch \"$(dirname \"$0\")/descendant-completed\") &\n\
         descendant=$!\n\
         echo \"$descendant\" > \"$(dirname \"$0\")/descendant-pid\"\n\
         echo done",
    );
    let output = ProcessRunner::default()
        .run(
            &CommandSpec::new(&script, Vec::<String>::new()).cwd(&temp.0),
            &ProcessLimits {
                timeout: Duration::from_secs(20),
                terminate_grace: Duration::from_millis(20),
                reader_grace: Duration::from_millis(200),
                ..ProcessLimits::default()
            },
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout.trim(), "done");
    assert!(
        !temp.0.join("descendant-completed").exists(),
        "the runner waited for a descendant that inherited its output pipes"
    );

    let descendant = fs::read_to_string(temp.0.join("descendant-pid"))
        .unwrap()
        .trim()
        .parse::<libc::pid_t>()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while unsafe { libc::kill(descendant, 0) } == 0 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(
        unsafe { libc::kill(descendant, 0) },
        0,
        "descendant must be terminated with the contained process tree"
    );
}

#[test]
fn typed_failure_classification_is_redacted_and_remediable() {
    for (stderr, expected) in [
        (
            "please login first",
            AgentErrorCode::ProviderNotAuthenticated,
        ),
        (
            "403 forbidden: account is not eligible",
            AgentErrorCode::ProviderNotEligible,
        ),
        ("unknown model gpt-nope", AgentErrorCode::ModelNotAvailable),
        ("429 rate limit exceeded", AgentErrorCode::RateLimited),
        ("network error: DNS failed", AgentErrorCode::NetworkError),
        ("session not found", AgentErrorCode::SessionNotFound),
    ] {
        let output = ProcessOutput {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: String::new(),
            stderr: stderr.to_string(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            cancelled: false,
        };
        let error = classify_process_failure(&output, RuntimeErrorContext::default());
        assert_eq!(error.code, expected);
        assert!(error.validate().is_ok());
        assert!(!error.message.contains(stderr));
    }
}

#[test]
fn missing_and_authentication_probe_errors_are_typed() {
    let temp = TempDir::new();
    let runtime = LocalAgentRuntime::default();
    let config = RuntimeConfig::default();
    let missing = runtime.probe_executor(
        ExecutorKind::ClaudeCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        true,
    );
    let missing_error = missing.last_error.unwrap();
    assert_eq!(missing_error.code, AgentErrorCode::ProviderNotInstalled);
    assert!(missing_error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::InstallExecutor));
    assert!(missing_error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery));
    assert!(missing_error
        .message
        .contains("loomex setup agents refresh --confirm"));

    let unauthenticated = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'not authenticated' >&2; exit 1; fi\n\
         exit 1",
    );
    let mut config = RuntimeConfig::default();
    config
        .executables
        .insert(ExecutorKind::CodexCli, unauthenticated);
    let probe = runtime.probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        true,
    );
    assert_eq!(
        probe.last_error.unwrap().code,
        AgentErrorCode::ProviderNotAuthenticated
    );
}

#[test]
fn codex_and_claude_cli_version_gates_fail_closed_without_leaking_probe_output() {
    for (executor, executable_name, old_version, new_version) in [
        (ExecutorKind::CodexCli, "codex", "0.143.99", "0.144.0"),
        (ExecutorKind::ClaudeCli, "claude", "2.0.99", "2.1.0"),
    ] {
        let old = TempDir::new();
        let old_executable = old.script(
            executable_name,
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo '{old_version} token=raw-secret /private/local/path'; exit 0; fi\n\
                 touch \"$(dirname \"$0\")/unexpected-probe-or-execution\"\n\
                 exit 0"
            ),
        );
        let mut old_config = RuntimeConfig::default();
        old_config.executables.insert(executor, old_executable);
        let old_runtime = LocalAgentRuntime::default();
        let capability = old_runtime.probe_executor(
            executor,
            &old_config,
            &old.0,
            &CancellationToken::default(),
            true,
        );
        assert_eq!(capability.installation, InstallationState::Installed);
        assert_eq!(capability.readiness, RuntimeReadiness::Unavailable);
        assert_eq!(capability.executor_version.as_deref(), Some(old_version));
        assert!(!capability.features.structured_output);
        assert!(!capability.features.session_resume);
        assert!(!capability.features.reasoning_effort);
        let probe_error = capability.last_error.unwrap();
        assert_eq!(probe_error.code, AgentErrorCode::UnsupportedCapability);
        assert_eq!(
            probe_error.retry,
            loomex_protocol::AgentRetryDisposition::UserActionRequired
        );
        assert_eq!(
            probe_error.remediation,
            vec![
                loomex_protocol::AgentRemediationAction::UpgradeExecutor,
                loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
            ]
        );
        assert_eq!(
            probe_error.context.safe_details.get("reasonCode"),
            Some(&"executor_version_unverified".to_string())
        );
        assert!(probe_error.validate().is_ok());
        assert!(!probe_error.message.contains("raw-secret"));
        assert!(!probe_error.message.contains("/private/local/path"));
        assert!(!old.0.join("unexpected-probe-or-execution").exists());

        let selection = match executor {
            ExecutorKind::CodexCli => exact_codex(),
            ExecutorKind::ClaudeCli => ModelSelection {
                primary: ModelSelectionMode::Exact {
                    target: target(
                        ExecutorKind::ClaudeCli,
                        AgentProvider::Anthropic,
                        "claude-sonnet",
                    ),
                },
                fallback: ModelFallbackPolicy::None,
            },
            ExecutorKind::AgyCli => unreachable!("test covers version-gated adapters"),
        };
        let execution_error = old_runtime
            .execute_task_for_test(
                &request(selection, None),
                &old_config,
                &old.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(execution_error.code, AgentErrorCode::UnsupportedCapability);
        assert_eq!(
            execution_error.remediation,
            vec![
                loomex_protocol::AgentRemediationAction::UpgradeExecutor,
                loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
            ]
        );
        assert!(!old.0.join("unexpected-probe-or-execution").exists());

        let new = TempDir::new();
        let new_executable = new.script(
            executable_name,
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo '{new_version}'; exit 0; fi\n\
                 if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
                 if [ \"$1\" = \"auth\" ]; then echo '{{\"loggedIn\":true}}'; exit 0; fi\n\
                 exit 1"
            ),
        );
        let mut new_config = RuntimeConfig::default();
        new_config.executables.insert(executor, new_executable);
        let new_capability = LocalAgentRuntime::default().probe_executor(
            executor,
            &new_config,
            &new.0,
            &CancellationToken::default(),
            true,
        );
        assert_eq!(new_capability.readiness, RuntimeReadiness::Ready);
        assert!(new_capability.features.structured_output);
        assert!(new_capability.features.session_resume);
        assert!(new_capability.features.reasoning_effort);
    }

    let unknown = TempDir::new();
    let unknown_executable = unknown.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'nightly token=unknown-secret'; exit 0; fi\n\
         touch \"$(dirname \"$0\")/unexpected-execution\"",
    );
    let mut unknown_config = RuntimeConfig::default();
    unknown_config
        .executables
        .insert(ExecutorKind::CodexCli, unknown_executable);
    let unknown_capability = LocalAgentRuntime::default().probe_executor(
        ExecutorKind::CodexCli,
        &unknown_config,
        &unknown.0,
        &CancellationToken::default(),
        true,
    );
    assert_eq!(unknown_capability.readiness, RuntimeReadiness::Unavailable);
    assert_eq!(unknown_capability.executor_version, None);
    assert!(!unknown_capability.features.structured_output);
    let unknown_error = unknown_capability.last_error.as_ref().unwrap();
    assert_eq!(
        unknown_error.remediation,
        vec![
            loomex_protocol::AgentRemediationAction::UpgradeExecutor,
            loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
        ]
    );
    assert_eq!(
        unknown_error.context.safe_details.get("reasonCode"),
        Some(&"executor_version_unverified".to_string())
    );
    assert!(unknown_error.validate().is_ok());
    let serialized = serde_json::to_string(&unknown_capability).unwrap();
    assert!(!serialized.contains("unknown-secret"));
    assert!(!unknown.0.join("unexpected-execution").exists());
}

#[test]
fn agy_cli_version_gate_fails_closed_before_models_or_execution() {
    for version in ["1.1.3", "nightly-private"] {
        let temp = TempDir::new();
        let marker = temp.0.join("unexpected-command");
        let agy = temp.script(
            "agy",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo '{version} token=raw-secret'; exit 0; fi\n\
                 touch '{}'",
                marker.display()
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::AgyCli, agy);
        let runtime = LocalAgentRuntime::default();
        let capability = runtime.probe_executor(
            ExecutorKind::AgyCli,
            &config,
            &temp.0,
            &CancellationToken::default(),
            true,
        );
        assert_eq!(capability.readiness, RuntimeReadiness::Unavailable);
        assert!(!capability.features.structured_output);
        assert_eq!(
            capability.last_error.as_ref().unwrap().code,
            AgentErrorCode::UnsupportedCapability
        );
        assert_eq!(
            capability.last_error.as_ref().unwrap().remediation,
            vec![
                loomex_protocol::AgentRemediationAction::UpgradeExecutor,
                loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
            ]
        );
        assert_eq!(
            capability
                .last_error
                .as_ref()
                .unwrap()
                .context
                .safe_details
                .get("reasonCode"),
            Some(&"executor_version_unverified".to_string())
        );
        assert!(!serde_json::to_string(&capability)
            .unwrap()
            .contains("raw-secret"));
        let error = runtime
            .execute_task_for_test(
                &request(
                    ModelSelection {
                        primary: ModelSelectionMode::Exact {
                            target: target(
                                ExecutorKind::AgyCli,
                                AgentProvider::Google,
                                "gemini-2.5-pro",
                            ),
                        },
                        fallback: ModelFallbackPolicy::None,
                    },
                    None,
                ),
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::UnsupportedCapability);
        assert_eq!(
            error.remediation,
            vec![
                loomex_protocol::AgentRemediationAction::UpgradeExecutor,
                loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
            ]
        );
        assert!(!marker.exists());
    }

    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         exit 1",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let capability = LocalAgentRuntime::default().probe_executor(
        ExecutorKind::AgyCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        true,
    );
    assert_eq!(capability.readiness, RuntimeReadiness::Ready);
    assert!(capability.features.structured_output);
    assert_eq!(capability.models.len(), 1);
}

#[test]
fn probe_cache_obeys_ttl_and_force_refresh_hooks() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "COUNT=\"$(dirname \"$0\")/probe-count\"\n\
         if [ \"$1\" = \"--version\" ]; then\n\
           n=0; [ ! -f \"$COUNT\" ] || n=$(cat \"$COUNT\"); n=$((n + 1)); echo \"$n\" > \"$COUNT\"; echo 'codex 0.144.0'; exit 0\n\
         fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    config.probe_ttl = Duration::from_secs(60);
    let runtime = LocalAgentRuntime::default();
    runtime.probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        false,
    );
    runtime.probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        false,
    );
    assert_eq!(
        fs::read_to_string(temp.0.join("probe-count"))
            .unwrap()
            .trim(),
        "1"
    );
    runtime.probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        true,
    );
    assert_eq!(
        fs::read_to_string(temp.0.join("probe-count"))
            .unwrap()
            .trim(),
        "2"
    );
}

#[test]
fn explicit_execution_reprobes_cached_auth_and_runs_immediately_after_login() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then\n\
           if [ -f \"$(dirname \"$0\")/auth-ready\" ]; then echo 'logged in'; exit 0; fi\n\
           echo 'not authenticated' >&2; exit 1\n\
         fi\n\
         touch \"$(dirname \"$0\")/executed\"\n\
         printf '{\"type\":\"thread.started\",\"thread_id\":\"fresh-auth\"}\\n'\n\
         printf '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"done\"}}\\n'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    config.probe_ttl = Duration::from_secs(600);
    let runtime = LocalAgentRuntime::default();
    let cached = runtime.probe_executor(
        ExecutorKind::CodexCli,
        &config,
        &temp.0,
        &CancellationToken::default(),
        false,
    );
    assert_eq!(cached.readiness, RuntimeReadiness::NotAuthenticated);

    fs::write(temp.0.join("auth-ready"), b"ready").unwrap();
    let result = runtime
        .execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(result.output.content, "done");
    assert!(temp.0.join("executed").exists());
}

#[test]
fn pre_spawn_probe_timeout_remains_retryable_without_resume_semantics() {
    let temp = TempDir::new();
    let marker = temp.0.join("execution-spawned");
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then sleep 10; exit 0; fi\n\
         touch \"$(dirname \"$0\")/execution-spawned\"\n\
         echo '{\"thread_id\":\"never\",\"text\":\"never\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    config.probe_limits.timeout = Duration::from_millis(60);
    config.probe_limits.terminate_grace = Duration::from_millis(20);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::Timeout);
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::Retryable
    );
    assert!(!error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::ResumeSession));
    assert!(!marker.exists());
}

#[test]
fn truncated_main_output_is_never_accepted_as_an_early_valid_event() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         printf '{\"thread_id\":\"truncated-session\",\"text\":\"early success\"}\\n'\n\
         i=0; while [ \"$i\" -lt 300 ]; do printf x; i=$((i + 1)); done",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    config.execution_limits.max_stdout_bytes = 80;
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::OutputInvalid);
}

#[test]
fn ordered_fallback_runs_only_explicit_next_target() {
    let temp = TempDir::new();
    let claude = temp.script(
        "claude",
        "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
         if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
         echo '{\"type\":\"result\",\"session_id\":\"s2\",\"result\":\"ok\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let request = request(
        ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: target(ExecutorKind::CodexCli, AgentProvider::OpenAi, "gpt-5.2"),
            },
            fallback: ModelFallbackPolicy::Ordered {
                targets: vec![target(
                    ExecutorKind::ClaudeCli,
                    AgentProvider::Anthropic,
                    "claude-sonnet-4-6",
                )],
            },
        },
        None,
    );
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(&request, &config, &temp.0, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.executor, ExecutorKind::ClaudeCli);
    assert_eq!(result.selection_index, 1);
}

#[test]
fn fallback_checkpoint_and_continuation_preserve_the_authoritative_selection_index() {
    #[derive(Default)]
    struct Observer(Mutex<Vec<SessionDiscovery>>);
    impl AgentRuntimeObserver for Observer {
        fn on_session_initialized(
            &self,
            session: SessionDiscovery,
        ) -> Result<(), loomex_protocol::AgentRuntimeErrorEnvelopeV2> {
            self.0.lock().unwrap().push(session);
            Ok(())
        }
    }

    let temp = TempDir::new();
    let claude = temp.script(
        "claude",
        "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
         if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
         echo \"$*\" >> \"$(dirname \"$0\")/args\"\n\
         echo '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"fallback-session\"}'\n\
         echo '{\"type\":\"result\",\"session_id\":\"fallback-session\",\"result\":\"fallback done\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let fallback_target = target(
        ExecutorKind::ClaudeCli,
        AgentProvider::Anthropic,
        "claude-sonnet",
    );
    let selection = ModelSelection {
        primary: ModelSelectionMode::Exact {
            target: target(ExecutorKind::CodexCli, AgentProvider::OpenAi, "gpt-missing"),
        },
        fallback: ModelFallbackPolicy::Ordered {
            targets: vec![fallback_target.clone()],
        },
    };
    let initial_request = request(selection.clone(), None);
    let observer = Arc::new(Observer::default());
    let initial = LocalAgentRuntime::default()
        .execute_task_observed_for_test(
            &initial_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
            observer.clone(),
        )
        .unwrap();
    assert_eq!(initial.selection_index, 1);
    let discovered = observer.0.lock().unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].selection_index, 1);
    assert_eq!(discovered[0].model_key.as_deref(), Some("claude-sonnet"));
    drop(discovered);

    let mut resumed_request = request(selection, None);
    resumed_request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "checkpoint-fallback".to_string(),
        sequence: 1,
        session_id: "loomex-fallback-session".to_string(),
        provider_session_id: "fallback-session".to_string(),
        binding: resumed_request.binding.clone(),
        selection_index: 1,
        executor: fallback_target.executor,
        provider: fallback_target.provider,
        model_key: Some(fallback_target.model_key),
        provider_model_id: Some(fallback_target.provider_model_id),
    });
    let resumed = LocalAgentRuntime::default()
        .execute_task_for_test(
            &resumed_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(resumed.selection_index, 1);
    let args = fs::read_to_string(temp.0.join("args")).unwrap();
    assert!(args.contains("--resume fallback-session"));
}

#[test]
fn nonmember_or_repinned_continuation_is_rejected_before_any_process_spawn() {
    let temp = TempDir::new();
    let marker = temp.0.join("spawned");
    let claude = temp.script(
        "claude",
        &format!(
            "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
             touch '{}'",
            marker.display()
        ),
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let fallback_target = target(
        ExecutorKind::ClaudeCli,
        AgentProvider::Anthropic,
        "claude-sonnet",
    );
    let selection = ModelSelection {
        primary: ModelSelectionMode::Exact {
            target: target(ExecutorKind::CodexCli, AgentProvider::OpenAi, "gpt-5.2"),
        },
        fallback: ModelFallbackPolicy::Ordered {
            targets: vec![fallback_target.clone()],
        },
    };
    for (label, selection_index, model) in [
        ("nonmember-model", 1, "claude-opus"),
        ("nonmember-slot", 2, "claude-sonnet"),
        ("repinned-to-primary-slot", 0, "claude-sonnet"),
    ] {
        let mut task = request(selection.clone(), None);
        task.continuation = Some(AgentSessionContinuationV2 {
            schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: format!("checkpoint-{label}"),
            sequence: 1,
            session_id: format!("session-{label}"),
            provider_session_id: format!("provider-{label}"),
            binding: task.binding.clone(),
            selection_index,
            executor: fallback_target.executor,
            provider: fallback_target.provider,
            model_key: Some(model.to_string()),
            provider_model_id: Some(model.to_string()),
        });
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(&task, &config, &temp.0, &CancellationToken::default())
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::InvalidRequest, "{label}");
        assert!(!marker.exists(), "{label}");
    }
}

#[test]
fn ordered_fallback_never_spawns_second_provider_after_primary_process_started() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         touch \"$(dirname \"$0\")/primary-spawned\"\n\
         echo '429 rate limit after process start' >&2\n\
         exit 1",
    );
    let claude = temp.script(
        "claude",
        "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
         if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
         touch \"$(dirname \"$0\")/fallback-spawned\"\n\
         echo '{\"result\":\"unexpected\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(ExecutorKind::CodexCli, AgentProvider::OpenAi, "gpt-5.2"),
                    },
                    fallback: ModelFallbackPolicy::Ordered {
                        targets: vec![target(
                            ExecutorKind::ClaudeCli,
                            AgentProvider::Anthropic,
                            "claude-sonnet-4-6",
                        )],
                    },
                },
                None,
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert!(temp.0.join("primary-spawned").exists());
    assert!(!temp.0.join("fallback-spawned").exists());
}

#[test]
fn agy_runtime_discovers_models_and_executes_agy_binary() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         echo '{\"conversationId\":\"agy-session\",\"result\":\"done\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let request = request(
        ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: target(
                    ExecutorKind::AgyCli,
                    AgentProvider::Google,
                    "gemini-2.5-pro",
                ),
            },
            fallback: ModelFallbackPolicy::None,
        },
        None,
    );
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(&request, &config, &temp.0, &CancellationToken::default())
        .unwrap();
    assert_eq!(result.executor, ExecutorKind::AgyCli);
    assert_eq!(result.provider_session_id, None);
}

#[test]
fn exact_model_identity_requires_matching_key_and_provider_id_before_spawn() {
    let temp = TempDir::new();
    let marker = temp.0.join("executed");
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"},{\"id\":\"gemini-2.5-flash\"}]'; exit 0; fi\n\
         touch \"$(dirname \"$0\")/executed\"\n\
         echo '{\"result\":\"unexpected\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);

    for (label, model_key, provider_model_id) in [
        ("key-a-id-b", "gemini-2.5-pro", "gemini-2.5-flash"),
        ("key-b-id-a", "gemini-2.5-flash", "gemini-2.5-pro"),
    ] {
        let task = request(
            ModelSelection {
                primary: ModelSelectionMode::Exact {
                    target: ModelTarget {
                        executor: ExecutorKind::AgyCli,
                        provider: AgentProvider::Google,
                        model_key: model_key.to_string(),
                        provider_model_id: provider_model_id.to_string(),
                    },
                },
                fallback: ModelFallbackPolicy::None,
            },
            None,
        );
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(&task, &config, &temp.0, &CancellationToken::default())
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::ModelUnknown, "{label}");
        assert_eq!(
            error.context.requested_model_key.as_deref(),
            Some(model_key),
            "{label}"
        );
        assert_eq!(
            error.context.requested_provider_model_id.as_deref(),
            Some(provider_model_id),
            "{label}"
        );
        assert_eq!(error.context.resolved_model_key, None, "{label}");
        assert_eq!(error.context.resolved_provider_model_id, None, "{label}");
        assert!(!marker.exists(), "{label}");
    }
}

#[test]
fn agy_resume_is_typed_unsupported_and_never_spawns_conversation_flag() {
    let temp = TempDir::new();
    let marker = temp.0.join("executed");
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         touch \"$(dirname \"$0\")/executed\"\n\
         echo '{\"conversationId\":\"agy-session\",\"result\":\"done\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let mut request = request(
        ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: target(
                    ExecutorKind::AgyCli,
                    AgentProvider::Google,
                    "gemini-2.5-pro",
                ),
            },
            fallback: ModelFallbackPolicy::None,
        },
        None,
    );
    request.requirements.session_resume = true;
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(&request, &config, &temp.0, &CancellationToken::default())
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::UnsupportedCapability);
    assert_eq!(
        error.remediation,
        vec![loomex_protocol::AgentRemediationAction::ReconfigureWorkflow]
    );
    assert!(!marker.exists());
}

#[test]
fn agy_403_probe_is_typed_not_eligible_and_never_executes() {
    let temp = TempDir::new();
    let marker = temp.0.join("executed");
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '403 forbidden: account is not eligible' >&2; exit 1; fi\n\
         touch \"$(dirname \"$0\")/executed\"\n\
         echo '{\"result\":\"unexpected\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let request = request(
        ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: target(
                    ExecutorKind::AgyCli,
                    AgentProvider::Google,
                    "gemini-2.5-pro",
                ),
            },
            fallback: ModelFallbackPolicy::None,
        },
        None,
    );
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(&request, &config, &temp.0, &CancellationToken::default())
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ProviderNotEligible);
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::UserActionRequired
    );
    assert_eq!(
        error.remediation,
        vec![
            loomex_protocol::AgentRemediationAction::VerifyProviderAccess,
            loomex_protocol::AgentRemediationAction::ContactSupport,
        ]
    );
    assert!(error.validate().is_ok());
    assert!(!marker.exists());
}

#[test]
fn agy_exit_zero_denials_and_error_envelopes_never_become_models() {
    for (name, body, expected) in [
        (
            "agy-plain-denial",
            "403 forbidden: account is not eligible",
            AgentErrorCode::ProviderNotEligible,
        ),
        (
            "agy-json-denial",
            "{\"error\":{\"code\":403,\"message\":\"forbidden\"}}",
            AgentErrorCode::ProviderNotEligible,
        ),
        (
            "agy-json-error",
            "{\"error\":{\"code\":\"provider_error\",\"message\":\"failed\"}}",
            AgentErrorCode::RuntimeUnavailable,
        ),
        (
            "agy-malformed-success",
            "this is not a model response",
            AgentErrorCode::RuntimeUnavailable,
        ),
    ] {
        let temp = TempDir::new();
        let agy = temp.script(
            name,
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
                 if [ \"$1\" = \"models\" ]; then echo '{body}'; exit 0; fi\n\
                 touch \"$(dirname \"$0\")/executed\"\n\
                 echo '{{\"result\":\"unexpected\"}}'"
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::AgyCli, agy);
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(
                &request(
                    ModelSelection {
                        primary: ModelSelectionMode::Exact {
                            target: target(
                                ExecutorKind::AgyCli,
                                AgentProvider::Google,
                                "gemini-2.5-pro",
                            ),
                        },
                        fallback: ModelFallbackPolicy::None,
                    },
                    None,
                ),
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error.code, expected);
        assert!(!temp.0.join("executed").exists());
    }
}

#[test]
fn execution_exit_zero_403_is_typed_failure_and_never_leaks_raw_body() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         echo '{\"error\":{\"code\":403,\"message\":\"forbidden token=raw-secret\"}}'\n\
         exit 0",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::AgyCli,
                            AgentProvider::Google,
                            "gemini-2.5-pro",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                None,
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ProviderNotEligible);
    assert!(!error.message.contains("raw-secret"));
    assert!(error.validate().is_ok());
}

#[test]
fn exit_zero_model_error_envelopes_are_typed_without_scanning_normal_answers() {
    for (label, envelope) in [
        (
            "code",
            r#"{"type":"error","code":"model_not_found","message":"provider detail"}"#,
        ),
        (
            "trusted_text",
            r#"{"type":"error","code":"provider_error","message":"unknown model gpt-5.2"}"#,
        ),
    ] {
        let temp = TempDir::new();
        let codex = temp.script(
            "codex",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
                 if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
                 echo '{envelope}'"
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::CodexCli, codex);
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(
                &request(exact_codex(), None),
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error.code, AgentErrorCode::ModelNotAvailable, "{label}");
        assert_eq!(
            error.context.resolved_model_key.as_deref(),
            Some("gpt-5.2"),
            "{label}"
        );
        assert_eq!(
            error.context.resolved_provider_model_id.as_deref(),
            Some("gpt-5.2"),
            "{label}"
        );
        assert!(error
            .remediation
            .contains(&loomex_protocol::AgentRemediationAction::SelectDifferentModel));
    }
}

#[test]
fn exit_zero_resume_session_error_envelope_is_typed_session_not_found() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         echo '{\"type\":\"error\",\"code\":\"session_not_found\",\"message\":\"thread missing\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let mut resumed_request = request(exact_codex(), None);
    resumed_request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "checkpoint-missing".to_string(),
        sequence: 1,
        session_id: "loomex-missing-session".to_string(),
        provider_session_id: "provider-missing-session".to_string(),
        binding: resumed_request.binding.clone(),
        selection_index: 0,
        executor: ExecutorKind::CodexCli,
        provider: AgentProvider::OpenAi,
        model_key: Some("gpt-5.2".to_string()),
        provider_model_id: Some("gpt-5.2".to_string()),
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &resumed_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::SessionNotFound);
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::ResumeRequired
    );
}

#[test]
fn exit_zero_stderr_json_and_jsonl_error_envelopes_are_typed_safely() {
    for (label, stderr, continuation, expected) in [
        (
            "auth-json",
            r#"{"type":"error","code":"authentication_error","message":"secret detail"}"#,
            false,
            AgentErrorCode::ProviderNotAuthenticated,
        ),
        (
            "model-jsonl",
            "not-json diagnostic\n{\"type\":\"error\",\"code\":\"model_not_found\",\"message\":\"secret detail\"}",
            false,
            AgentErrorCode::ModelNotAvailable,
        ),
        (
            "session-jsonl",
            "{\"type\":\"progress\",\"message\":\"checking\"}\n{\"type\":\"error\",\"code\":\"session_not_found\",\"message\":\"secret detail\"}",
            true,
            AgentErrorCode::SessionNotFound,
        ),
        (
            "rate-json",
            r#"{"type":"error","code":"rate_limited","message":"secret detail"}"#,
            false,
            AgentErrorCode::ExecutionIndeterminate,
        ),
    ] {
        let temp = TempDir::new();
        let codex = temp.script(
            "codex",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
                 if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
                 printf '%s\\n' '{stderr}' >&2\n\
                 exit 0"
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::CodexCli, codex);
        let mut task = request(exact_codex(), None);
        if continuation {
            task.continuation = Some(AgentSessionContinuationV2 {
                schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
                checkpoint_id: "checkpoint-stderr".to_string(),
                sequence: 1,
                session_id: "loomex-stderr-session".to_string(),
                provider_session_id: "provider-stderr-session".to_string(),
                binding: task.binding.clone(),
                selection_index: 0,
                executor: ExecutorKind::CodexCli,
                provider: AgentProvider::OpenAi,
                model_key: Some("gpt-5.2".to_string()),
                provider_model_id: Some("gpt-5.2".to_string()),
            });
        }
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(&task, &config, &temp.0, &CancellationToken::default())
            .unwrap_err();
        assert_eq!(error.code, expected, "{label}");
        assert!(!error.message.contains("secret detail"), "{label}");
        assert!(error.validate().is_ok(), "{label}");
    }
}

#[test]
fn normal_agent_answer_may_discuss_provider_error_phrases() {
    let temp = TempDir::new();
    let codex = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         printf '%s\\n' '403 forbidden; rate limit; model not found; session not found' >&2\n\
         printf '%s\\n' '{\"type\":\"diagnostic\",\"message\":\"not authenticated\"}' >&2\n\
         printf '{\"type\":\"thread.started\",\"thread_id\":\"discussion-session\"}\\n'\n\
         printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Explain 403 forbidden, rate limit, and not authenticated errors.\"}}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, codex);
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(result.output.content.contains("403 forbidden"));
    assert!(result.output.content.contains("rate limit"));
    assert!(result.output.content.contains("not authenticated"));
}

#[test]
fn legitimate_structured_output_may_have_a_single_error_property() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         echo '{\"error\":\"validation explanation\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let schema = json!({
        "type": "object",
        "properties": {"error": {"type": "string"}},
        "required": ["error"],
        "additionalProperties": false
    });
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::AgyCli,
                            AgentProvider::Google,
                            "gemini-2.5-pro",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                Some(schema),
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(
        result.output.structured,
        Some(json!({"error": "validation explanation"}))
    );
}

#[test]
fn degraded_and_unknown_readiness_fail_closed() {
    let candidate = Candidate {
        selection_index: 0,
        executor: ExecutorKind::CodexCli,
        target: Some(target(
            ExecutorKind::CodexCli,
            AgentProvider::OpenAi,
            "gpt-5.2",
        )),
    };
    for readiness in [RuntimeReadiness::Degraded, RuntimeReadiness::Unknown] {
        let capability = AgentExecutorCapability {
            executor: ExecutorKind::CodexCli,
            provider: AgentProvider::OpenAi,
            readiness,
            installation: InstallationState::Installed,
            authentication: AuthenticationState::Unknown,
            executor_version: Some("test".to_string()),
            model_discovery: ModelDiscoveryKind::Unknown,
            models: Vec::new(),
            features: AgentRuntimeFeatures {
                structured_output: true,
                session_resume: true,
                cancellation: true,
                reasoning_effort: true,
            },
            last_error: None,
        };
        let error = ensure_ready(&capability, &candidate).unwrap_err();
        assert_eq!(error.code, AgentErrorCode::RuntimeUnavailable);
    }
}

#[test]
fn model_rate_network_and_malformed_failures_surface_typed_errors() {
    for (message, expected) in [
        ("unknown model", AgentErrorCode::ModelNotAvailable),
        ("429 rate limit", AgentErrorCode::ExecutionIndeterminate),
        ("network error", AgentErrorCode::ExecutionIndeterminate),
    ] {
        let temp = TempDir::new();
        let script = temp.script(
            "codex",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
                 if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
                 echo '{message}' >&2; exit 1"
            ),
        );
        let mut config = RuntimeConfig::default();
        config.executables.insert(ExecutorKind::CodexCli, script);
        let error = LocalAgentRuntime::default()
            .execute_task_for_test(
                &request(exact_codex(), None),
                &config,
                &temp.0,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error.code, expected);
    }

    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         printf '{bad-json'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), None),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::OutputInvalid);
}

#[test]
fn structured_output_gets_at_most_one_repair_turn_in_same_session() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         case \" $* \" in\n\
           *' -- repair-session '*) echo '{\"thread_id\":\"repair-session\",\"text\":\"{\\\"ok\\\":true}\"}' ;;\n\
           *) echo '{\"thread_id\":\"repair-session\",\"text\":\"{\\\"ok\\\":false}\"}' ;;\n\
         esac",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"],
        "additionalProperties": false
    });
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), Some(schema)),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(result.repair_used);
    assert_eq!(
        result.provider_session_id.as_deref(),
        Some("repair-session")
    );
    assert_eq!(result.output.structured, Some(json!({"ok": true})));
}

#[test]
fn repair_process_failure_after_checkpoint_is_indeterminate_not_blocked() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         case \" $* \" in\n\
           *' -- repair-failure-session '*) echo 'not authenticated' >&2; exit 1 ;;\n\
           *) echo '{\"thread_id\":\"repair-failure-session\",\"text\":\"{\\\"ok\\\":false}\"}' ;;\n\
         esac",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"]
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), Some(schema)),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::ResumeRequired
    );
    assert!(error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::ResumeSession));
}

#[test]
fn repair_spawn_failure_after_checkpoint_is_indeterminate() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         rm \"$0\"\n\
         echo '{\"thread_id\":\"repair-spawn-session\",\"text\":\"{\\\"ok\\\":false}\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"]
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), Some(schema)),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::ResumeRequired
    );
}

#[test]
fn repair_timeout_preserves_timeout_provenance_and_requires_resume() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         case \" $* \" in\n\
           *' -- repair-timeout-session '*) sleep 10 ;;\n\
           *) echo '{\"thread_id\":\"repair-timeout-session\",\"text\":\"{\\\"ok\\\":false}\"}' ;;\n\
         esac",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    config.execution_limits.timeout = Duration::from_millis(80);
    config.execution_limits.terminate_grace = Duration::from_millis(20);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"]
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), Some(schema)),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert_eq!(
        error.context.safe_details.get("processLoss"),
        Some(&"timeout".to_string())
    );
    assert_eq!(
        error.retry,
        loomex_protocol::AgentRetryDisposition::ResumeRequired
    );
}

#[test]
fn truncated_repair_output_is_rejected_before_parsing_early_valid_json() {
    let temp = TempDir::new();
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         case \" $* \" in\n\
           *' -- truncated-repair-session '*)\n\
             printf '{\"thread_id\":\"truncated-repair-session\",\"text\":\"{\\\"ok\\\":true}\"}\\n'\n\
             i=0; while [ \"$i\" -lt 300 ]; do printf x; i=$((i + 1)); done ;;\n\
           *) echo '{\"thread_id\":\"truncated-repair-session\",\"text\":\"{\\\"ok\\\":false}\"}' ;;\n\
         esac",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    config.execution_limits.max_stdout_bytes = 100;
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"]
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(exact_codex(), Some(schema)),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::OutputInvalid);
}

#[test]
fn claude_repairs_structured_output_in_the_exact_same_session() {
    let temp = TempDir::new();
    let claude = temp.script(
        "claude",
        "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
         if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
         echo \"$*\" >> \"$(dirname \"$0\")/execution-args\"\n\
         case \" $* \" in\n\
           *' --resume claude-repair-session '*) echo '{\"session_id\":\"claude-repair-session\",\"structured_output\":{\"ok\":true},\"result\":\"{\\\"ok\\\":true}\"}' ;;\n\
           *) echo '{\"session_id\":\"claude-repair-session\",\"structured_output\":{\"ok\":false},\"result\":\"{\\\"ok\\\":false}\"}' ;;\n\
         esac",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"],
        "additionalProperties": false
    });
    let result = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::ClaudeCli,
                            AgentProvider::Anthropic,
                            "claude-sonnet-4-6",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                Some(schema),
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(result.repair_used);
    assert_eq!(result.output.structured, Some(json!({"ok": true})));
    let args = fs::read_to_string(temp.0.join("execution-args")).unwrap();
    assert_eq!(args.lines().count(), 2);
    assert!(args.contains("--resume claude-repair-session"));
}

#[test]
fn claude_stream_json_checkpoints_before_crash_and_resumes_exact_session() {
    #[derive(Default)]
    struct Observer {
        sessions: Mutex<Vec<SessionDiscovery>>,
        acknowledgement: PathBuf,
    }
    impl AgentRuntimeObserver for Observer {
        fn on_session_initialized(
            &self,
            session: SessionDiscovery,
        ) -> Result<(), loomex_protocol::AgentRuntimeErrorEnvelopeV2> {
            self.sessions.lock().unwrap().push(session);
            fs::write(&self.acknowledgement, b"checkpointed").unwrap();
            Ok(())
        }
    }

    let temp = TempDir::new();
    let acknowledgement = temp.0.join("claude-checkpoint-ack");
    let claude = temp.script(
        "claude",
        "if [ \"$1\" = \"--version\" ]; then echo 'claude 2.1.0'; exit 0; fi\n\
         if [ \"$1\" = \"auth\" ]; then echo '{\"loggedIn\":true}'; exit 0; fi\n\
         echo \"$*\" >> \"$(dirname \"$0\")/execution-args\"\n\
         echo '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"claude-early\"}'\n\
         case \" $* \" in\n\
           *' --resume claude-early '*) echo '{\"type\":\"result\",\"session_id\":\"claude-early\",\"result\":\"resumed\"}'; exit 0 ;;\n\
         esac\n\
         ACK=\"$(dirname \"$0\")/claude-checkpoint-ack\"\n\
         i=0\n\
         while [ ! -f \"$ACK\" ] && [ \"$i\" -lt 250 ]; do sleep 0.02; i=$((i + 1)); done\n\
         [ -f \"$ACK\" ] || exit 9\n\
         echo 'crashed after init' >&2\n\
         exit 1",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::ClaudeCli, claude);
    let selection = ModelSelection {
        primary: ModelSelectionMode::Exact {
            target: target(
                ExecutorKind::ClaudeCli,
                AgentProvider::Anthropic,
                "claude-sonnet-4-6",
            ),
        },
        fallback: ModelFallbackPolicy::None,
    };
    let first_request = request(selection.clone(), None);
    let observer = Arc::new(Observer {
        sessions: Mutex::new(Vec::new()),
        acknowledgement,
    });
    let error = LocalAgentRuntime::default()
        .execute_task_observed_for_test(
            &first_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
            observer.clone(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    let sessions = observer.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].provider_session_id, "claude-early");
    drop(sessions);

    let mut resume_request = request(selection, None);
    resume_request.continuation = Some(AgentSessionContinuationV2 {
        schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
        checkpoint_id: "claude-checkpoint".to_string(),
        sequence: 1,
        session_id: "loomex-claude-session".to_string(),
        provider_session_id: "claude-early".to_string(),
        binding: resume_request.binding.clone(),
        selection_index: 0,
        executor: ExecutorKind::ClaudeCli,
        provider: AgentProvider::Anthropic,
        model_key: Some("claude-sonnet-4-6".to_string()),
        provider_model_id: Some("claude-sonnet-4-6".to_string()),
    });
    let resumed = LocalAgentRuntime::default()
        .execute_task_for_test(
            &resume_request,
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(resumed.output.content, "resumed");
    let args = fs::read_to_string(temp.0.join("execution-args")).unwrap();
    assert!(args.contains("--output-format stream-json --verbose"));
    assert!(args.contains("--resume claude-early"));
}

#[test]
fn agy_invalid_structured_output_never_spawns_a_repair_process() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         echo \"$*\" >> \"$(dirname \"$0\")/execution-args\"\n\
         echo '{\"conversationId\":\"agy-session\",\"result\":\"{\\\"ok\\\":false}\"}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let schema = json!({
        "type": "object",
        "properties": {"ok": {"const": true}},
        "required": ["ok"],
        "additionalProperties": false
    });
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::AgyCli,
                            AgentProvider::Google,
                            "gemini-2.5-pro",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                Some(schema),
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::OutputInvalid);
    let args = fs::read_to_string(temp.0.join("execution-args")).unwrap();
    assert_eq!(args.lines().count(), 1);
    assert!(!args.contains("--conversation"));
}

#[test]
fn agy_indeterminate_failure_never_suggests_resume() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         echo 'agent crashed after starting' >&2\n\
         exit 1",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::AgyCli,
                            AgentProvider::Google,
                            "gemini-2.5-pro",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                None,
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert!(!error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::ResumeSession));
    assert_eq!(error.retry, loomex_protocol::AgentRetryDisposition::Never);
}

#[test]
fn agy_timeout_never_suggests_resume() {
    let temp = TempDir::new();
    let agy = temp.script(
        "agy",
        "if [ \"$1\" = \"--version\" ]; then echo '1.1.4'; exit 0; fi\n\
         if [ \"$1\" = \"models\" ]; then echo '[{\"id\":\"gemini-2.5-pro\"}]'; exit 0; fi\n\
         sleep 10",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::AgyCli, agy);
    config.execution_limits.timeout = Duration::from_millis(80);
    config.execution_limits.terminate_grace = Duration::from_millis(20);
    let error = LocalAgentRuntime::default()
        .execute_task_for_test(
            &request(
                ModelSelection {
                    primary: ModelSelectionMode::Exact {
                        target: target(
                            ExecutorKind::AgyCli,
                            AgentProvider::Google,
                            "gemini-2.5-pro",
                        ),
                    },
                    fallback: ModelFallbackPolicy::None,
                },
                None,
            ),
            &config,
            &temp.0,
            &CancellationToken::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, AgentErrorCode::ExecutionIndeterminate);
    assert!(!error
        .remediation
        .contains(&loomex_protocol::AgentRemediationAction::ResumeSession));
}

#[test]
fn typed_session_observer_runs_before_the_process_finishes() {
    #[derive(Default)]
    struct Observer {
        called: AtomicBool,
        sessions: Mutex<Vec<SessionDiscovery>>,
        acknowledgement: Mutex<Option<PathBuf>>,
    }
    impl AgentRuntimeObserver for Observer {
        fn on_session_initialized(
            &self,
            session: SessionDiscovery,
        ) -> Result<(), loomex_protocol::AgentRuntimeErrorEnvelopeV2> {
            self.sessions.lock().unwrap().push(session);
            if let Some(path) = self.acknowledgement.lock().unwrap().as_ref() {
                fs::write(path, b"checkpointed").unwrap();
            }
            self.called.store(true, Ordering::Release);
            Ok(())
        }
    }

    let temp = TempDir::new();
    let acknowledgement = temp.0.join("checkpoint-ack");
    let script = temp.script(
        "codex",
        "if [ \"$1\" = \"--version\" ]; then echo 'codex 0.144.0'; exit 0; fi\n\
         if [ \"$1\" = \"login\" ]; then echo 'logged in'; exit 0; fi\n\
         echo '{\"type\":\"thread.started\",\"thread_id\":\"early-session\"}'\n\
         ACK=\"$(dirname \"$0\")/checkpoint-ack\"\n\
         i=0\n\
         while [ ! -f \"$ACK\" ] && [ \"$i\" -lt 250 ]; do sleep 0.02; i=$((i + 1)); done\n\
         [ -f \"$ACK\" ] || exit 9\n\
         echo '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"done\"}}'",
    );
    let mut config = RuntimeConfig::default();
    config.executables.insert(ExecutorKind::CodexCli, script);
    let observer = Arc::new(Observer {
        acknowledgement: Mutex::new(Some(acknowledgement.clone())),
        ..Observer::default()
    });
    let observer_for_thread = observer.clone();
    let workspace = temp.0.clone();
    let handle = thread::spawn(move || {
        LocalAgentRuntime::default().execute_task_observed_for_test(
            &request(exact_codex(), None),
            &config,
            &workspace,
            &CancellationToken::default(),
            observer_for_thread,
        )
    });
    let result = handle.join().unwrap().unwrap();
    assert!(observer.called.load(Ordering::Acquire));
    assert!(acknowledgement.is_file());
    assert_eq!(result.provider_session_id.as_deref(), Some("early-session"));
    let sessions = observer.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].provider_session_id, "early-session");
    assert_eq!(sessions[0].model_key.as_deref(), Some("gpt-5.2"));
}

fn exact_codex() -> ModelSelection {
    ModelSelection {
        primary: ModelSelectionMode::Exact {
            target: target(ExecutorKind::CodexCli, AgentProvider::OpenAi, "gpt-5.2"),
        },
        fallback: ModelFallbackPolicy::None,
    }
}

fn target(executor: ExecutorKind, provider: AgentProvider, model: &str) -> ModelTarget {
    ModelTarget {
        executor,
        provider,
        model_key: model.to_string(),
        provider_model_id: model.to_string(),
    }
}

fn request(
    selection: ModelSelection,
    output_schema: Option<serde_json::Value>,
) -> AgentTaskRequestV2 {
    AgentTaskRequestV2 {
        schema_version: AGENT_TASK_SCHEMA_V2.to_string(),
        request_id: "request-1".to_string(),
        idempotency_key: "idempotency-1".to_string(),
        binding: AgentExecutionBindingV2 {
            workspace_binding_id: "binding-1".to_string(),
            workspace_binding_generation: 1,
            runner_id: "runner-1".to_string(),
        },
        selection,
        prompt: "do work".to_string(),
        output_schema,
        requirements: AgentExecutionRequirements {
            structured_output: false,
            session_resume: false,
            cancellation: true,
            reasoning_effort: None,
        },
        continuation: None,
    }
}
