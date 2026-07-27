use crate::{CoreError, CoreResult};

pub use loomex_protocol::{
    AGENT_MALFORMED_DISPATCH_MESSAGE, AGENT_MALFORMED_DISPATCH_REASON_CODE,
    AGENT_PROCESS_DISPATCH_SCHEMA_V2, AGENT_RUNTIME_CAPABILITY_V2,
    LEGACY_AGENT_TASK_DRAIN_CAPABILITY, MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION,
    MINIMUM_SUPPORTED_PROTOCOL_VERSION as MINIMUM_SUPPORTED_VERSION, PROTOCOL_VERSION,
    RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1, RUNNER_PROTOCOL_V1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamIdentity {
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub runner_session_id: String,
    pub protocol_version: String,
    pub runner_version: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SequenceTracker {
    next_expected: u64,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self { next_expected: 1 }
    }

    pub fn accept(&mut self, sequence: u64) -> CoreResult<()> {
        if sequence != self.next_expected {
            return Err(CoreError::new(
                "OUT_OF_ORDER_SEQUENCE",
                format!("expected {}, got {sequence}", self.next_expected),
            ));
        }
        self.next_expected += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_tracker_rejects_out_of_order_messages() {
        let mut tracker = SequenceTracker::new();
        tracker.accept(1).unwrap();
        assert_eq!("OUT_OF_ORDER_SEQUENCE", tracker.accept(3).unwrap_err().code);
    }

    #[test]
    fn agent_runtime_v2_constants_are_reexported_from_the_authoritative_protocol() {
        assert_eq!(
            AGENT_PROCESS_DISPATCH_SCHEMA_V2,
            "loomex.agent-process-dispatch.v2"
        );
        assert_eq!(MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION, 8);
        assert_eq!(
            RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1,
            "loomex.runner-agent-advertisement/v1"
        );
        assert_eq!(LEGACY_AGENT_TASK_DRAIN_CAPABILITY, "agent.task.v1.drain");
        assert_eq!(AGENT_MALFORMED_DISPATCH_REASON_CODE, "malformed_dispatch");
        assert_eq!(
            AGENT_MALFORMED_DISPATCH_MESSAGE,
            "The process dispatch payload was malformed."
        );
    }
}
