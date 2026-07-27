use std::path::Path;

use loomex_protocol::{ExecutorKind, ModelDiscoveryKind, ReasoningEffort};

use crate::agent_runtime::{
    adapter::{
        effort_name, validate_invocation_identifiers, version_at_least, AdapterFeatures,
        AdapterInvocationError,
    },
    AgentAdapter, CommandSpec, ExecutionInvocation, InvocationMode, ProbeCommands,
};

#[derive(Debug, Default)]
pub struct ClaudeAdapter;

impl AgentAdapter for ClaudeAdapter {
    fn executor(&self) -> ExecutorKind {
        ExecutorKind::ClaudeCli
    }

    fn executable_name(&self) -> &'static str {
        "claude"
    }

    fn features(&self) -> AdapterFeatures {
        AdapterFeatures {
            model_selection: true,
            structured_output: true,
            session_resume: true,
            cancellation: true,
            reasoning_effort: true,
            model_discovery: ModelDiscoveryKind::ProviderDefaultOnly,
        }
    }

    fn features_for_version(&self, version: Option<&str>) -> AdapterFeatures {
        // 2.1 is the oldest revision whose non-interactive model, stream-json,
        // effort, JSON-schema and exact-resume interface Loomex has verified.
        let verified = version_at_least(version, (2, 1, 0));
        AdapterFeatures {
            model_selection: verified,
            structured_output: verified,
            session_resume: verified,
            cancellation: true,
            reasoning_effort: verified,
            model_discovery: ModelDiscoveryKind::ProviderDefaultOnly,
        }
    }

    fn supports_reasoning_effort(&self, effort: ReasoningEffort) -> bool {
        !matches!(effort, ReasoningEffort::Minimal)
    }

    fn build_execution(
        &self,
        invocation: &ExecutionInvocation<'_>,
    ) -> Result<CommandSpec, AdapterInvocationError> {
        validate_invocation_identifiers(invocation)?;
        let mut args = vec![
            "--print".to_string(),
            "--output-format".to_string(),
            "stream-json".to_string(),
            "--verbose".to_string(),
        ];
        if let InvocationMode::ResumeExact {
            provider_session_id,
        } = &invocation.mode
        {
            args.extend(["--resume".to_string(), provider_session_id.clone()]);
        }
        if let Some(model) = invocation.provider_model_id {
            args.push(format!("--model={model}"));
        }
        if let Some(effort) = invocation.reasoning_effort {
            // Claude does not expose a "minimal" effort. Failures caused by an
            // unsupported value are classified rather than silently remapped.
            args.extend(["--effort".to_string(), effort_name(effort).to_string()]);
        }
        if let Some(schema) = invocation.output_schema {
            args.extend([
                "--json-schema".to_string(),
                serde_json::to_string(schema).unwrap_or_else(|_| "{}".to_string()),
            ]);
        }
        Ok(CommandSpec::new(invocation.executable, args)
            .cwd(invocation.workspace)
            .stdin(invocation.prompt.as_bytes().to_vec()))
    }

    fn probe_commands(&self, executable: &Path, workspace: &Path) -> ProbeCommands {
        ProbeCommands {
            version: CommandSpec::new(executable, ["--version"]).cwd(workspace),
            authentication: Some(
                CommandSpec::new(executable, ["auth", "status", "--json"]).cwd(workspace),
            ),
            models: None,
        }
    }

    fn authentication_succeeded(&self, output: &str) -> Option<bool> {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(output) {
            for key in ["loggedIn", "authenticated", "isAuthenticated"] {
                if let Some(value) = value.get(key).and_then(|value| value.as_bool()) {
                    return Some(value);
                }
            }
        }
        let normalized = output.to_ascii_lowercase();
        if normalized.contains("\"loggedin\":true") || normalized.contains("\"authenticated\":true")
        {
            Some(true)
        } else if normalized.contains("not authenticated")
            || normalized.contains("login required")
            || normalized.contains("\"loggedin\":false")
            || normalized.contains("\"authenticated\":false")
        {
            Some(false)
        } else {
            None
        }
    }
}
