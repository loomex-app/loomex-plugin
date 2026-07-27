//! Wire fixture drift guard.

use loomex_protocol::{
    AgentExecutionV2, AgentProcessDispatchV2, AgentRuntimeCapabilitySnapshotV2,
    AgentRuntimeErrorEnvelopeV2, AgentSessionCheckpointV2, AgentSessionContinuationV2,
    AgentTaskRequestV2, AgentTerminalPayloadLimitsV1, ExecutorKind, RunnerAgentAdvertisementV1,
    RunnerIdentity,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

fn assert_round_trip<T>(fixture: &str)
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::from_str::<Value>(fixture).unwrap()
    );
}

#[test]
fn all_checked_in_fixtures_match_the_public_wire_types() {
    assert_round_trip::<RunnerIdentity>(include_str!("../fixtures/runner_identity_v1.json"));
    assert_round_trip::<RunnerAgentAdvertisementV1>(include_str!(
        "../fixtures/runner_agent_advertisement_v1_drain_enabled.json"
    ));
    assert_round_trip::<RunnerAgentAdvertisementV1>(include_str!(
        "../fixtures/runner_agent_advertisement_v1_disabled.json"
    ));
    assert_round_trip::<AgentTaskRequestV2>(include_str!("../fixtures/agent_task_v2.json"));
    assert_round_trip::<AgentTaskRequestV2>(include_str!(
        "../fixtures/agent_task_v2_ordered_fallback.json"
    ));
    assert_round_trip::<AgentProcessDispatchV2>(include_str!(
        "../fixtures/agent_process_dispatch_v2.json"
    ));
    assert_round_trip::<AgentProcessDispatchV2>(include_str!(
        "../fixtures/agent_process_dispatch_v2_resumed.json"
    ));
    assert_round_trip::<AgentProcessDispatchV2>(include_str!(
        "../fixtures/agent_process_dispatch_v2_fresh_after_remediation.json"
    ));
    assert_round_trip::<AgentProcessDispatchV2>(include_str!(
        "../fixtures/agent_process_dispatch_v2_jcs_edge.json"
    ));
    assert_round_trip::<AgentRuntimeCapabilitySnapshotV2>(include_str!(
        "../fixtures/agent_capabilities_v2.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_v2.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_provider_not_eligible_v2.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_refresh_executor_discovery_v2.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_upgrade_executor_v2.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_runtime_v2_disabled.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_malformed_dispatch.json"
    ));
    assert_round_trip::<AgentRuntimeErrorEnvelopeV2>(include_str!(
        "../fixtures/agent_error_prestart_cancelled.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!("../fixtures/agent_execution_v2.json"));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_blocked_resumed.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_pre_session_blocked.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_fresh_after_remediation.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_dispatch_rejected.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_malformed_dispatch_rejected.json"
    ));
    assert_round_trip::<AgentExecutionV2>(include_str!(
        "../fixtures/agent_execution_v2_dispatch_cancelled.json"
    ));
    assert_round_trip::<AgentSessionCheckpointV2>(include_str!(
        "../fixtures/agent_session_checkpoint_v2.json"
    ));
    assert_round_trip::<AgentSessionCheckpointV2>(include_str!(
        "../fixtures/agent_session_checkpoint_v2_auto_unresolved.json"
    ));
    assert_round_trip::<AgentSessionContinuationV2>(include_str!(
        "../fixtures/agent_session_continuation_v2_auto_unresolved.json"
    ));
    assert_round_trip::<AgentSessionCheckpointV2>(include_str!(
        "../fixtures/agent_session_checkpoint_v2_ordered_fallback.json"
    ));
    assert_round_trip::<AgentSessionContinuationV2>(include_str!(
        "../fixtures/agent_session_continuation_v2_ordered_fallback.json"
    ));
    assert_round_trip::<AgentTerminalPayloadLimitsV1>(include_str!(
        "../fixtures/agent_terminal_payload_limits_v1.json"
    ));
}

#[test]
fn executor_wire_identity_accepts_agy_and_rejects_gemini() {
    assert_eq!(
        serde_json::from_str::<ExecutorKind>("\"agy_cli\"").unwrap(),
        ExecutorKind::AgyCli
    );
    assert!(serde_json::from_str::<ExecutorKind>("\"gemini_cli\"").is_err());
}
