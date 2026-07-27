//! Offline API compatibility guard.
//!
//! This integration test is compiled as a crate consumer. Renaming, hiding, or
//! removing the referenced v1 and v2 API is therefore a deliberate breaking
//! change that fails CI.

use loomex_protocol::{
    check_protocol_compatibility, synthesize_malformed_dispatch_error, AgentAttemptRetryV2,
    AgentAttemptState, AgentAttemptV2, AgentCandidatePinV2, AgentDeliveryRouteV2, AgentErrorCode,
    AgentErrorContext, AgentExecutionBindingV2, AgentExecutionRequirements,
    AgentExecutionUpdateKind, AgentExecutionV2, AgentPrestartCancellationReplacement,
    AgentProcessDeliveryV2, AgentProcessDispatchV2, AgentProcessRetryKindV2, AgentProvider,
    AgentRemediationAction, AgentRuntimeCapabilitySnapshotV2, AgentRuntimeErrorEnvelopeV2,
    AgentSessionCheckpointV2, AgentTaskRequestV2, ExecutorKind, LegacyAgentTaskMode,
    LegacyAgentTasksAdvertisementV1, ModelFallbackPolicy, ModelSelection, ModelSelectionMode,
    ProtocolCompatibility, RunnerAgentAdvertisementV1, RunnerIdentity, RunnerPlatform,
    RunnerSurface, AGENT_CAPABILITY_SCHEMA_V2, AGENT_ERROR_SCHEMA_V2, AGENT_EXECUTION_SCHEMA_V2,
    AGENT_MALFORMED_DISPATCH_MESSAGE, AGENT_MALFORMED_DISPATCH_REASON_CODE,
    AGENT_PROCESS_DISPATCH_SCHEMA_V2, AGENT_RUNTIME_CAPABILITY_V2,
    AGENT_RUNTIME_V2_DISABLED_MESSAGE, AGENT_RUNTIME_V2_DISABLED_REASON_CODE,
    AGENT_SESSION_SCHEMA_V2, AGENT_TASK_SCHEMA_V2, LEGACY_AGENT_TASK_DRAIN_CAPABILITY,
    MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION, MINIMUM_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION,
    RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1, RUNNER_PROTOCOL_V1,
};

fn assert_public_type<T>() {}

#[test]
fn v1_runner_and_v2_agent_public_surface_remain_available() {
    assert_public_type::<RunnerIdentity>();
    assert_public_type::<AgentTaskRequestV2>();
    assert_public_type::<AgentRuntimeCapabilitySnapshotV2>();
    assert_public_type::<AgentRuntimeErrorEnvelopeV2>();
    assert_public_type::<AgentSessionCheckpointV2>();
    assert_public_type::<AgentCandidatePinV2>();
    assert_public_type::<AgentExecutionV2>();
    assert_public_type::<AgentAttemptV2>();
    assert_public_type::<AgentAttemptRetryV2>();
    assert_public_type::<AgentExecutionUpdateKind>();
    assert_public_type::<AgentPrestartCancellationReplacement>();
    assert_public_type::<AgentProcessDispatchV2>();
    assert_public_type::<AgentProcessDeliveryV2>();
    assert_public_type::<AgentDeliveryRouteV2>();
    assert_public_type::<AgentProcessRetryKindV2>();
    assert_public_type::<AgentErrorContext>();
    assert_public_type::<AgentExecutionBindingV2>();
    assert_public_type::<AgentExecutionRequirements>();
    assert_public_type::<ModelSelection>();
    assert_public_type::<ModelSelectionMode>();
    assert_public_type::<ModelFallbackPolicy>();
    assert_public_type::<RunnerAgentAdvertisementV1>();
    assert_public_type::<LegacyAgentTasksAdvertisementV1>();
    assert_public_type::<LegacyAgentTaskMode>();

    assert_eq!(RUNNER_PROTOCOL_V1, "runner.v1");
    assert_eq!(PROTOCOL_VERSION, RUNNER_PROTOCOL_V1);
    assert_eq!(MINIMUM_SUPPORTED_PROTOCOL_VERSION, RUNNER_PROTOCOL_V1);
    assert_eq!(AGENT_RUNTIME_CAPABILITY_V2, "agent.runtime.v2");
    assert_eq!(LEGACY_AGENT_TASK_DRAIN_CAPABILITY, "agent.task.v1.drain");
    assert_eq!(
        RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1,
        "loomex.runner-agent-advertisement/v1"
    );
    assert_eq!(AGENT_TASK_SCHEMA_V2, "loomex.plugin-agent-task/v2");
    assert_eq!(AGENT_CAPABILITY_SCHEMA_V2, "loomex.agent-capabilities.v2");
    assert_eq!(AGENT_EXECUTION_SCHEMA_V2, "loomex.agent-execution.v2");
    assert_eq!(
        AGENT_PROCESS_DISPATCH_SCHEMA_V2,
        "loomex.agent-process-dispatch.v2"
    );
    assert_eq!(AGENT_ERROR_SCHEMA_V2, "loomex.agent-error.v2");
    assert_eq!(AGENT_SESSION_SCHEMA_V2, "loomex.agent-session.v2");
    assert_eq!(
        AGENT_RUNTIME_V2_DISABLED_REASON_CODE,
        "agent_runtime_v2_disabled"
    );
    assert_eq!(
        AGENT_RUNTIME_V2_DISABLED_MESSAGE,
        "Local agent runtime v2 execution is disabled."
    );
    assert_eq!(AGENT_MALFORMED_DISPATCH_REASON_CODE, "malformed_dispatch");
    assert_eq!(
        AGENT_MALFORMED_DISPATCH_MESSAGE,
        "The process dispatch payload was malformed."
    );
    assert_eq!(MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION, 8);

    assert_eq!(
        check_protocol_compatibility(RUNNER_PROTOCOL_V1),
        ProtocolCompatibility::Compatible
    );

    let identity: RunnerIdentity =
        serde_json::from_str(include_str!("../fixtures/runner_identity_v1.json")).unwrap();
    assert_eq!(identity.surface, RunnerSurface::Plugin);
    assert_eq!(identity.platform, RunnerPlatform::Macos);
    assert!(identity.supports_protocol());

    assert_eq!(ExecutorKind::CodexCli.provider(), AgentProvider::OpenAi);
    assert_eq!(ExecutorKind::ClaudeCli.provider(), AgentProvider::Anthropic);
    assert_eq!(ExecutorKind::AgyCli.provider(), AgentProvider::Google);
    assert_eq!(
        AgentErrorCode::ProviderNotEligible.category(),
        loomex_protocol::AgentErrorCategory::Authorization
    );
    assert_eq!(
        serde_json::to_string(&AgentRemediationAction::UpgradeExecutor).unwrap(),
        "\"upgrade_executor\""
    );
    assert_eq!(
        serde_json::to_string(&AgentAttemptState::DispatchRejected).unwrap(),
        "\"dispatch_rejected\""
    );
    assert_eq!(
        serde_json::to_string(&AgentAttemptState::DispatchCancelled).unwrap(),
        "\"dispatch_cancelled\""
    );
    assert_eq!(
        serde_json::to_string(&AgentErrorCode::AgentRuntimeV2Disabled).unwrap(),
        "\"agent_runtime_v2_disabled\""
    );

    let malformed: AgentExecutionV2 = serde_json::from_str(include_str!(
        "../fixtures/agent_execution_v2_malformed_dispatch_rejected.json"
    ))
    .unwrap();
    assert_eq!(
        synthesize_malformed_dispatch_error(&malformed.execution_id, &malformed.attempts[0]),
        malformed.error.unwrap()
    );
}
