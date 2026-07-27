use std::path::Path;

use loomex_protocol::{ExecutorKind, ModelDiscoveryKind};

use crate::agent_runtime::{
    adapter::{
        effort_name, validate_invocation_identifiers, version_at_least, AdapterFeatures,
        AdapterInvocationError,
    },
    AgentAdapter, CommandSpec, ExecutionInvocation, InvocationMode, ProbeCommands,
};

#[derive(Debug, Default)]
pub struct CodexAdapter;

impl AgentAdapter for CodexAdapter {
    fn executor(&self) -> ExecutorKind {
        ExecutorKind::CodexCli
    }

    fn executable_name(&self) -> &'static str {
        "codex"
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
        // 0.144 is the oldest revision whose fixed exec interface Loomex has
        // verified end-to-end for --model, --json, --config reasoning and
        // exact `exec resume`. Unknown or older builds remain installed but
        // unavailable instead of receiving speculative flags.
        let verified = version_at_least(version, (0, 144, 0));
        AdapterFeatures {
            model_selection: verified,
            structured_output: verified,
            session_resume: verified,
            cancellation: true,
            reasoning_effort: verified,
            model_discovery: ModelDiscoveryKind::ProviderDefaultOnly,
        }
    }

    fn build_execution(
        &self,
        invocation: &ExecutionInvocation<'_>,
    ) -> Result<CommandSpec, AdapterInvocationError> {
        validate_invocation_identifiers(invocation)?;
        let mut args = vec!["exec".to_string()];
        let resume_session = if let InvocationMode::ResumeExact {
            provider_session_id,
        } = &invocation.mode
        {
            args.push("resume".to_string());
            Some(provider_session_id)
        } else {
            None
        };
        args.push("--json".to_string());
        // `--color` belongs to `codex exec` itself. It is not accepted by the
        // nested `codex exec resume` parser in the verified 0.144 interface.
        if resume_session.is_none() {
            args.extend(["--color".to_string(), "never".to_string()]);
        }
        args.push("--skip-git-repo-check".to_string());
        if let Some(model) = invocation.provider_model_id {
            args.push(format!("--model={model}"));
        }
        if let Some(effort) = invocation.reasoning_effort {
            args.extend([
                "--config".to_string(),
                format!("model_reasoning_effort=\"{}\"", effort_name(effort)),
            ]);
        }
        if let Some(session) = resume_session {
            args.extend(["--".to_string(), session.clone()]);
        }
        // A dash keeps the prompt out of argv/process listings.
        args.push("-".to_string());
        Ok(CommandSpec::new(invocation.executable, args)
            .cwd(invocation.workspace)
            .stdin(invocation.prompt.as_bytes().to_vec()))
    }

    fn probe_commands(&self, executable: &Path, workspace: &Path) -> ProbeCommands {
        ProbeCommands {
            version: CommandSpec::new(executable, ["--version"]).cwd(workspace),
            authentication: Some(CommandSpec::new(executable, ["login", "status"]).cwd(workspace)),
            models: None,
        }
    }

    fn authentication_succeeded(&self, output: &str) -> Option<bool> {
        let normalized = output.to_ascii_lowercase();
        if normalized.contains("not logged in")
            || normalized.contains("not authenticated")
            || normalized.contains("login required")
        {
            Some(false)
        } else if normalized.contains("logged in") || normalized.contains("authenticated") {
            Some(true)
        } else {
            None
        }
    }
}
