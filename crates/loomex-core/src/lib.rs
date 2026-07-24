#![allow(clippy::large_enum_variant)]

pub mod approval;
pub mod auth;
pub mod binding;
pub mod capability;
pub mod config;
pub mod device;
pub mod enterprise_acceptance;
pub mod execution;
pub mod grpc;
pub mod lifecycle;
pub mod local_capabilities;
pub mod local_control;
pub mod logs;
pub mod management;
pub mod operational_readiness;
pub mod policy;
pub mod protocol;
pub mod redaction;
pub mod release_distribution;
pub mod release_security;
pub mod runtime_guard;
pub mod runtime_install;
pub mod security;
pub mod service;
pub mod stream;
pub mod transport;

pub use loomex_protocol::{
    check_protocol_compatibility, ProtocolCompatibility, RunnerIdentity, RunnerPlatform,
    RunnerSurface, MINIMUM_SUPPORTED_PROTOCOL_VERSION,
};

pub use approval::{
    ApprovalAuditEvent, ApprovalChannel, ApprovalDecision, ApprovalDecisionInput,
    ApprovalDecisionOutcome, ApprovalPayload, ApprovalPolicySnapshot, ApprovalPrompt,
    ApprovalPromptProvider, ApprovalRegistry, ApprovalRequest, ApprovalRequestKind, ApprovalStatus,
    CreateApprovalRequestInput,
};
pub use binding::{
    BindingRegistry, BindingStatus, BindingValidationContext, CreateBindingInput,
    CreateRunnerSessionInput, ProjectRunnerBinding, RunnerCapabilityGrant, RunnerSession,
    RunnerSessionActivation, RunnerSessionRegistry, RunnerSessionReplacementPolicy,
    RunnerSessionStatus, WorkspacePath,
};
pub use capability::{CapabilityExecutor, CapabilityRequest, CapabilityResult};
pub use config::{CliConfig, CliConfigOverrides, CliProfile, ResolvedCliSettings, RunnerConfig};
pub use device::{RunnerDeviceMetadata, RunnerDeviceRecord, TokenScope};
pub use enterprise_acceptance::{
    evaluate_enterprise_acceptance_report, official_acceptance_checks, official_compliance_package,
    official_enterprise_acceptance_plan, official_enterprise_release_blocking_thresholds,
    official_security_review_scope, validate_enterprise_acceptance_plan, CompliancePackageItem,
    ComplianceReviewResult, EnterpriseAcceptanceCheck, EnterpriseAcceptanceDecision,
    EnterpriseAcceptancePlan, EnterpriseAcceptanceReport, EnterpriseReleaseBlockingThresholds,
    EnterpriseScenarioResult, EnterpriseSecurityFinding, LoadChaosAcceptanceResult,
    SecurityFindingSeverity, SecurityFindingStatus, SecurityReviewResult, SecurityReviewScopeItem,
    SupportedRunnerVersionResult, ENTERPRISE_ACCEPTANCE_PLAN_SCHEMA_VERSION,
    ENTERPRISE_ACCEPTANCE_REPORT_SCHEMA_VERSION,
};
pub use lifecycle::{RunnerLifecycleState, RunnerStateMachine, RunnerStateSnapshot};
pub use local_capabilities::{
    BrowserPlaywrightArtifacts, BrowserPlaywrightInput, BrowserPlaywrightOutput, DbQueryArtifacts,
    DbQueryInput, DbQueryOutput, DockerExecInput, DockerExecOutput, FileChange, FileEntry,
    FsApplyPatchInput, FsApplyPatchOutput, FsListInput, FsListOutput, FsReadInput, FsReadOutput,
    FsWriteInput, FsWriteOutput, GitCommit, GitDiffInput, GitDiffOutput, GitLogInput, GitLogOutput,
    GitStatusFile, GitStatusInput, GitStatusOutput, HttpRequestArtifacts, HttpRequestInput,
    HttpRequestOutput, LocalCapabilityExecutor, RedactionMetadata, ShellCancellationToken,
    ShellExecInput, ShellExecOutput, ShellExecOutputArtifacts, TestRunInput, TestRunOutput,
};
#[cfg(unix)]
pub use local_control::UnixLocalControlServer;
pub use local_control::{
    handle_local_control_request, prepare_local_control_paths, read_local_control_token,
    LocalControlDispatcher, LocalControlError, LocalControlPaths, LocalControlRequest,
    LocalControlResponse, LOCAL_CONTROL_PROTOCOL_VERSION,
};
pub use logs::{
    read_recent_log_entries, redact_log_entry_for_local_output, FileLogSink, LogEntry, LogSink,
    MemoryLogSink,
};
pub use management::{
    user_credential_profile, ApiKeyExchangeResult, AuthTokenResponse, CredentialKind,
    CredentialStorageBackend, CredentialStorageOutcome, CredentialStore, DeviceLoginChallenge,
    HttpManagementApiClient, HumanRequestExecution, HumanRequestResolveResponse,
    HumanRequestSummary, LocalCredentialStore, ManagementApiClient, ManagementCredential,
    ManagementProjectRunnerBinding, Organization, Project, ProjectRunnerBindingCreateRequest,
    Runner, RunnerHumanRequestListQuery, RunnerHumanRequestListResponse,
    RunnerJobEventCreateResponse, RunnerJobResponse, RunnerSessionResponse, RunnerUpsertRequest,
    RunnerWorkflowExecutionListResponse, RunnerWorkflowExecutionResponse,
    RunnerWorkflowExecutionStartOptions, RunnerWorkflowInputSchemaResponse, RunnerWorkflowSummary,
    StreamCredentialRequest, StreamCredentialResponse, SystemCredentialStore,
    WorkflowRunStartRequest, WorkflowRunStartResponse, WorkspaceLoginResult,
};
pub use operational_readiness::{
    capacity_plan_for_runner_connections, evaluate_operational_alerts, evaluate_release_gate,
    evaluate_slo, official_alert_rules, official_dashboard_queries,
    official_operational_readiness_plan, official_runbooks, official_slos, runbook_drill_result,
    validate_operational_readiness_plan, AlertRule, CapacityPlan, DashboardQuery, ErrorBudgetBurn,
    OperationalAlert, OperationalMetric, OperationalMetricsRecorder, OperationalReadinessPlan,
    OperationalReadinessReport, ReleaseGateDecision, Runbook, RunbookDrillResult, SloDefinition,
    SloKind, SloObservation, SloResult, OPERATIONAL_READINESS_PLAN_SCHEMA_VERSION,
    OPERATIONAL_READINESS_REPORT_SCHEMA_VERSION,
};
pub use policy::{
    enforce_managed_policy_version, enforce_policy_decision, managed_policy_engine,
    policy_applies_to_runner, rollback_managed_policy, validate_managed_policy_document,
    CapabilitySupport, ManagedPolicyDocument, ManagedPolicySnapshot, ManagedPolicyVersionState,
    PolicyDecision, PolicyEngine, PolicyEvaluation, PolicyEvaluationInput, PolicyLayer, PolicyRule,
    PolicySet, PolicySource,
};
pub use release_distribution::{
    official_compatibility_matrix, official_distribution_installers,
    official_release_channel_policies, official_release_distribution_plan,
    validate_compatibility_matrix, validate_release_distribution_plan, CompatibilityMatrixEntry,
    DistributionInstaller, InstallerKind, LegacyDeprecationNotice, ReleaseChannelPolicy,
    ReleaseCompatibilityMatrix, ReleaseDistributionPlan,
    RELEASE_COMPATIBILITY_MATRIX_SCHEMA_VERSION, RELEASE_DISTRIBUTION_PLAN_SCHEMA_VERSION,
};
pub use release_security::{
    generate_sbom, plan_update, sign_release_artifact, sign_release_manifest,
    verify_release_artifact, verify_release_manifest, verifying_key_hex_from_signing_key,
    BuildProvenance, ReleaseArtifact, ReleaseChannel, ReleaseManifest, SbomPackage, UpdateDecision,
    UpdatePolicy, RELEASE_MANIFEST_SCHEMA_VERSION,
};
pub use runtime_guard::{
    acquire_runner_runtime_guard, cleanup_stale_runner_runtime_guard, read_runner_runtime_guard,
    release_runner_runtime_guard_for_surface, release_runner_runtime_guard_owned,
    runner_runtime_guard_path, RunnerRuntimeGuard, RunnerRuntimeGuardInfo,
};
pub use runtime_install::{
    default_runtime_root, BundledRuntimeInstall, InstalledRuntime, RuntimeActivation,
    RuntimeInstallLayout, RuntimeInstallOutcome, RuntimeInstaller, VerifiedRuntimeInstall,
    RUNTIME_HOME_ENV, RUNTIME_INSTALL_METADATA_SCHEMA_VERSION,
};
pub use security::{
    ChildEnvironmentPolicy, IpNetworkRange, LocalSecurityPolicy, NetworkSecurityPolicy,
    RunnerDevicePosture, SandboxProfile,
};
pub use service::{
    validate_cross_platform_relative_path, RunnerServiceManifest, RunnerServicePlatform,
    RunnerServiceSpec,
};
pub use stream::{StreamSupervisor, StreamSupervisorConfig};
pub use transport::{
    decode_websocket_frame, encode_websocket_frame, negotiate_transport, websocket_request,
    FlowControlPermit, FlowControlWindow, RunnerTransport, RunnerTransportRuntime,
    RunnerTransportSession, RuntimeStep, TransportClientConfig, TransportConnector,
    TransportMetrics, TransportNegotiationPolicy, TransportProbe, TransportSelection,
    WebSocketClientConfig, WebSocketFrame, WebSocketProxyConfig, WebSocketRunnerClient,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub code: &'static str,
    pub message: String,
}

impl CoreError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_exports_execution_boundaries_without_ui_logic() {
        let request = CapabilityRequest {
            capability: "shell.exec".to_string(),
            input: "python -m pytest".to_string(),
        };
        assert_eq!("shell.exec", request.capability);

        let prompt = ApprovalPrompt {
            approval_request_id: "approval_123".to_string(),
            workflow_run_id: "run_123".to_string(),
            node_id: "node_123".to_string(),
            capability: "shell.exec".to_string(),
            action_summary: "Run python -m pytest".to_string(),
            full_request_details: "shell.exec: python -m pytest in workspace".to_string(),
            risk_indicators: vec!["shell".to_string()],
            risk_level: "medium".to_string(),
            expires_at_epoch_ms: 30_000,
            policy_snapshot: ApprovalPolicySnapshot {
                policy_id: "policy_123".to_string(),
                policy_version: 1,
                decision_reason: "shell requires approval".to_string(),
            },
            channel: ApprovalChannel::CliPrompt,
        };
        assert_eq!("approval_123", prompt.approval_request_id);
    }
}
