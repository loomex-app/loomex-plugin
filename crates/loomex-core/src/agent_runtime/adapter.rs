use std::path::Path;

use loomex_protocol::{
    validate_cli_identifier, AgentProvider, AgentRuntimeFeatures, ExecutorKind, ModelDiscoveryKind,
    ReasoningEffort, MAX_PROVIDER_MODEL_ID_LENGTH, MAX_PROVIDER_SESSION_ID_LENGTH,
};
use serde_json::Value;

use super::process::CommandSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterFeatures {
    /// Whether this exact CLI revision has a verified model-selection flag.
    /// This is an internal execution gate; the public protocol currently
    /// represents it through executor readiness rather than a feature bit.
    pub model_selection: bool,
    pub structured_output: bool,
    pub session_resume: bool,
    pub cancellation: bool,
    pub reasoning_effort: bool,
    pub model_discovery: ModelDiscoveryKind,
}

impl From<AdapterFeatures> for AgentRuntimeFeatures {
    fn from(value: AdapterFeatures) -> Self {
        Self {
            structured_output: value.structured_output,
            session_resume: value.session_resume,
            cancellation: value.cancellation,
            reasoning_effort: value.reasoning_effort,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationMode {
    Start,
    ResumeExact { provider_session_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterInvocationError {
    UnsupportedResume,
    InvalidModelIdentifier,
    InvalidSessionIdentifier,
}

#[derive(Debug, Clone)]
pub struct ExecutionInvocation<'a> {
    pub executable: &'a Path,
    pub workspace: &'a Path,
    pub prompt: &'a str,
    pub provider_model_id: Option<&'a str>,
    pub reasoning_effort: Option<ReasoningEffort>,
    pub output_schema: Option<&'a Value>,
    pub mode: InvocationMode,
}

#[derive(Debug, Clone)]
pub struct ProbeCommands {
    pub version: CommandSpec,
    pub authentication: Option<CommandSpec>,
    pub models: Option<CommandSpec>,
}

pub trait AgentAdapter: Send + Sync {
    fn executor(&self) -> ExecutorKind;
    fn provider(&self) -> AgentProvider {
        self.executor().provider()
    }
    fn executable_name(&self) -> &'static str;
    fn features(&self) -> AdapterFeatures;
    /// Narrows the adapter's maximum feature set to the capabilities verified
    /// for a sanitized CLI version. Unknown and older revisions must return a
    /// fail-closed set rather than inheriting the latest adapter behavior.
    fn features_for_version(&self, _version: Option<&str>) -> AdapterFeatures {
        self.features()
    }
    fn supports_reasoning_effort(&self, effort: ReasoningEffort) -> bool {
        self.features().reasoning_effort && {
            let _ = effort;
            true
        }
    }
    fn requires_machine_readable_output(&self) -> bool {
        true
    }
    fn build_execution(
        &self,
        invocation: &ExecutionInvocation<'_>,
    ) -> Result<CommandSpec, AdapterInvocationError>;
    fn probe_commands(&self, executable: &Path, workspace: &Path) -> ProbeCommands;
    fn parse_models(&self, _stdout: &str) -> Vec<(String, String)> {
        Vec::new()
    }
    fn authentication_succeeded(&self, output: &str) -> Option<bool>;
}

pub(crate) fn validate_invocation_identifiers(
    invocation: &ExecutionInvocation<'_>,
) -> Result<(), AdapterInvocationError> {
    if invocation
        .provider_model_id
        .is_some_and(|model| validate_cli_identifier(model, MAX_PROVIDER_MODEL_ID_LENGTH).is_err())
    {
        return Err(AdapterInvocationError::InvalidModelIdentifier);
    }
    if let InvocationMode::ResumeExact {
        provider_session_id,
    } = &invocation.mode
    {
        if validate_cli_identifier(provider_session_id, MAX_PROVIDER_SESSION_ID_LENGTH).is_err() {
            return Err(AdapterInvocationError::InvalidSessionIdentifier);
        }
    }
    Ok(())
}

pub(crate) fn is_safe_provider_model_id(value: &str) -> bool {
    validate_cli_identifier(value, MAX_PROVIDER_MODEL_ID_LENGTH).is_ok()
}

pub(crate) fn effort_name(effort: ReasoningEffort) -> &'static str {
    match effort {
        ReasoningEffort::Minimal => "minimal",
        ReasoningEffort::Low => "low",
        ReasoningEffort::Medium => "medium",
        ReasoningEffort::High => "high",
        ReasoningEffort::Xhigh => "xhigh",
    }
}

pub(crate) fn version_at_least(version: Option<&str>, minimum: (u64, u64, u64)) -> bool {
    let Some(version) = version else {
        return false;
    };
    let mut components = version.split('.');
    let parsed = (
        components
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
        components
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
        components
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
    );
    if components.next().is_some() {
        return false;
    }
    matches!(parsed, (Some(major), Some(minor), Some(patch)) if (major, minor, patch) >= minimum)
}
