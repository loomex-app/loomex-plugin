use std::{collections::BTreeSet, path::Path};

use loomex_protocol::{ExecutorKind, ModelDiscoveryKind};

use crate::agent_runtime::{
    adapter::{
        is_safe_provider_model_id, validate_invocation_identifiers, version_at_least,
        AdapterFeatures, AdapterInvocationError,
    },
    AgentAdapter, CommandSpec, ExecutionInvocation, InvocationMode, ProbeCommands,
};

/// Adapter for Google's Gemini-compatible `agy` CLI.
///
/// There is intentionally no `gemini` fallback executable. Allowing one would
/// make capability advertisements and exact-resume behavior dependent on an
/// unversioned alias, contrary to the v2 protocol.
#[derive(Debug, Default)]
pub struct AgyAdapter;

impl AgentAdapter for AgyAdapter {
    fn executor(&self) -> ExecutorKind {
        ExecutorKind::AgyCli
    }

    fn executable_name(&self) -> &'static str {
        "agy"
    }

    fn features(&self) -> AdapterFeatures {
        AdapterFeatures {
            model_selection: true,
            structured_output: true,
            // The current agy CLI exposes a conversation flag, but its exact
            // cross-process resume semantics are not yet a verified contract.
            // Keep this disabled until a version-gated probe proves support.
            session_resume: false,
            cancellation: true,
            reasoning_effort: false,
            model_discovery: ModelDiscoveryKind::RuntimeProbe,
        }
    }

    fn features_for_version(&self, version: Option<&str>) -> AdapterFeatures {
        // 1.1.4 is the oldest `agy` revision verified for the non-interactive
        // --print/--model interface and bounded `models` discovery output.
        let verified = version_at_least(version, (1, 1, 4));
        AdapterFeatures {
            model_selection: verified,
            structured_output: verified,
            session_resume: false,
            cancellation: true,
            reasoning_effort: false,
            model_discovery: if verified {
                ModelDiscoveryKind::RuntimeProbe
            } else {
                ModelDiscoveryKind::Unknown
            },
        }
    }

    fn requires_machine_readable_output(&self) -> bool {
        false
    }

    fn build_execution(
        &self,
        invocation: &ExecutionInvocation<'_>,
    ) -> Result<CommandSpec, AdapterInvocationError> {
        validate_invocation_identifiers(invocation)?;
        if matches!(invocation.mode, InvocationMode::ResumeExact { .. }) {
            return Err(AdapterInvocationError::UnsupportedResume);
        }
        let mut args = vec!["--print".to_string()];
        if let Some(model) = invocation.provider_model_id {
            args.push(format!("--model={model}"));
        }
        Ok(CommandSpec::new(invocation.executable, args)
            .cwd(invocation.workspace)
            .stdin(invocation.prompt.as_bytes().to_vec()))
    }

    fn probe_commands(&self, executable: &Path, workspace: &Path) -> ProbeCommands {
        // `agy models` is both the model-discovery probe and the least invasive
        // authenticated provider operation exposed by the current CLI.
        ProbeCommands {
            version: CommandSpec::new(executable, ["--version"]).cwd(workspace),
            authentication: None,
            models: Some(CommandSpec::new(executable, ["models"]).cwd(workspace)),
        }
    }

    fn parse_models(&self, stdout: &str) -> Vec<(String, String)> {
        let mut models = BTreeSet::new();
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) {
            let values = value
                .as_array()
                .or_else(|| value.get("models").and_then(|models| models.as_array()));
            if let Some(values) = values {
                for value in values {
                    if let Some(id) = value
                        .as_str()
                        .or_else(|| value.get("id").and_then(|id| id.as_str()))
                        .or_else(|| value.get("name").and_then(|name| name.as_str()))
                    {
                        if id.starts_with("gemini-") && is_safe_provider_model_id(id) {
                            models.insert(id.to_string());
                        }
                    }
                }
                return models.into_iter().map(|id| (id.clone(), id)).collect();
            }
        }
        for line in stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if !line.to_ascii_lowercase().starts_with("available") {
                if let Some(id) = line
                    .trim_start_matches(['-', '*', ' '])
                    .split_whitespace()
                    .next()
                {
                    if id.starts_with("gemini-") && is_safe_provider_model_id(id) {
                        models.insert(id.to_string());
                    }
                }
            }
        }
        models.into_iter().map(|id| (id.clone(), id)).collect()
    }

    fn authentication_succeeded(&self, output: &str) -> Option<bool> {
        let normalized = output.to_ascii_lowercase();
        if normalized.contains("not authenticated")
            || normalized.contains("login required")
            || normalized.contains("unauthorized")
        {
            Some(false)
        } else if !output.trim().is_empty() {
            Some(true)
        } else {
            None
        }
    }
}
