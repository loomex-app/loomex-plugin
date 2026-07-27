use loomex_protocol::{
    AgentErrorCode, AgentErrorContext, AgentRemediationAction, AgentRetryDisposition,
    AgentRuntimeErrorEnvelopeV2, ExecutorKind, ModelTarget, AGENT_ERROR_SCHEMA_V2,
};

use super::ProcessOutput;

#[derive(Debug, Clone, Default)]
pub struct RuntimeErrorContext {
    pub executor: Option<ExecutorKind>,
    /// The exact model identity requested by the workflow, when one was
    /// supplied. This does not imply that capability resolution succeeded.
    pub target: Option<ModelTarget>,
    /// The model identity resolved atomically by capability selection. Both
    /// catalog key and provider ID are emitted together, or neither is.
    pub resolved_target: Option<ModelTarget>,
    pub execution_id: Option<String>,
    pub attempt_id: Option<String>,
    pub session_id: Option<String>,
}

pub fn runtime_error(
    code: AgentErrorCode,
    message: impl Into<String>,
    context: RuntimeErrorContext,
) -> AgentRuntimeErrorEnvelopeV2 {
    let (retry, remediation) = disposition(code);
    let target = context.target.as_ref();
    let resolved_target = context.resolved_target.as_ref();
    AgentRuntimeErrorEnvelopeV2 {
        schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
        code,
        category: code.category(),
        message: message.into(),
        retry,
        retry_after_seconds: None,
        remediation,
        context: AgentErrorContext {
            executor: context.executor,
            provider: context
                .executor
                .map(ExecutorKind::provider)
                .or_else(|| target.map(|target| target.provider)),
            requested_model_key: target.map(|target| target.model_key.clone()),
            requested_provider_model_id: target.map(|target| target.provider_model_id.clone()),
            resolved_model_key: resolved_target.map(|target| target.model_key.clone()),
            resolved_provider_model_id: resolved_target
                .map(|target| target.provider_model_id.clone()),
            execution_id: context.execution_id,
            attempt_id: context.attempt_id,
            session_id: context.session_id,
            safe_details: Default::default(),
        },
    }
}

pub fn classify_process_failure(
    output: &ProcessOutput,
    context: RuntimeErrorContext,
) -> AgentRuntimeErrorEnvelopeV2 {
    if output.cancelled {
        return runtime_error(
            AgentErrorCode::Cancelled,
            "The local agent execution was cancelled.",
            context,
        );
    }
    if output.timed_out {
        return runtime_error(
            AgentErrorCode::Timeout,
            "The local agent did not finish before the execution timeout.",
            context,
        );
    }

    let diagnostic = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    let (code, message) = if contains_any(
        &diagnostic,
        &[
            "403",
            "forbidden",
            "permission_denied",
            "permission denied",
            "not eligible",
            "eligibility",
            "account is not allowed",
            "organization is not allowed",
            "plan does not include",
            "region is not supported",
        ],
    ) {
        (
            AgentErrorCode::ProviderNotEligible,
            "The local agent account is not eligible to use the selected provider or model.",
        )
    } else if contains_any(
        &diagnostic,
        &[
            "not authenticated",
            "authentication required",
            "login required",
            "please log in",
            "please login",
            "unauthorized",
            "invalid api key",
            "invalid_api_key",
            "401 unauthorized",
        ],
    ) {
        (
            AgentErrorCode::ProviderNotAuthenticated,
            "The selected local agent is installed but is not authenticated.",
        )
    } else if contains_any(
        &diagnostic,
        &[
            "model not found",
            "unknown model",
            "invalid model",
            "model is not available",
            "model unavailable",
            "does not have access to model",
            "unsupported model",
        ],
    ) {
        (
            AgentErrorCode::ModelNotAvailable,
            "The selected model is not available to this local agent account.",
        )
    } else if contains_any(
        &diagnostic,
        &[
            "rate limit",
            "rate_limit",
            "too many requests",
            "resource exhausted",
            "429",
            "overloaded",
            "capacity",
        ],
    ) {
        (
            AgentErrorCode::RateLimited,
            "The model provider is temporarily rate limited or overloaded.",
        )
    } else if contains_any(
        &diagnostic,
        &[
            "network error",
            "connection refused",
            "connection reset",
            "dns",
            "timed out",
            "timeout connecting",
            "failed to connect",
            "service unavailable",
            "502 bad gateway",
            "503 service unavailable",
        ],
    ) {
        (
            AgentErrorCode::NetworkError,
            "The local agent could not reach its model provider.",
        )
    } else if contains_any(
        &diagnostic,
        &[
            "session not found",
            "conversation not found",
            "thread not found",
            "no session",
            "unknown session",
            "invalid session",
        ],
    ) {
        (
            AgentErrorCode::SessionNotFound,
            "The exact provider session could not be resumed.",
        )
    } else {
        (
            AgentErrorCode::ExecutionFailed,
            "The local agent process exited unsuccessfully.",
        )
    };
    runtime_error(code, message, context)
}

fn disposition(code: AgentErrorCode) -> (AgentRetryDisposition, Vec<AgentRemediationAction>) {
    use AgentErrorCode::*;
    match code {
        ProviderNotInstalled => (
            AgentRetryDisposition::UserActionRequired,
            vec![
                AgentRemediationAction::InstallExecutor,
                AgentRemediationAction::RefreshExecutorDiscovery,
            ],
        ),
        ProviderNotAuthenticated => (
            AgentRetryDisposition::UserActionRequired,
            vec![AgentRemediationAction::Authenticate],
        ),
        ProviderNotEligible => (
            AgentRetryDisposition::UserActionRequired,
            vec![
                AgentRemediationAction::VerifyProviderAccess,
                AgentRemediationAction::ContactSupport,
            ],
        ),
        ModelUnknown | ModelNotAvailable => (
            AgentRetryDisposition::UserActionRequired,
            vec![AgentRemediationAction::SelectDifferentModel],
        ),
        RuntimeUnavailable => (
            AgentRetryDisposition::UserActionRequired,
            vec![
                AgentRemediationAction::Retry,
                AgentRemediationAction::InstallExecutor,
            ],
        ),
        RateLimited | NetworkError | Timeout => (
            AgentRetryDisposition::Retryable,
            vec![AgentRemediationAction::Retry],
        ),
        SessionNotFound | SessionMismatch | ExecutionIndeterminate => (
            AgentRetryDisposition::ResumeRequired,
            vec![AgentRemediationAction::ResumeSession],
        ),
        InvalidRequest | ProtocolMismatch | UnsupportedCapability => (
            AgentRetryDisposition::Never,
            vec![AgentRemediationAction::ReconfigureWorkflow],
        ),
        OutputInvalid | ExecutionFailed | InternalError => (
            AgentRetryDisposition::Never,
            vec![AgentRemediationAction::ContactSupport],
        ),
        Cancelled | AgentRuntimeV2Disabled => (AgentRetryDisposition::Never, Vec::new()),
    }
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}
