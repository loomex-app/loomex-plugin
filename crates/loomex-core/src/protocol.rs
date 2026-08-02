use crate::{CoreError, CoreResult};

pub use loomex_protocol::{
    check_protocol_compatibility, negotiate_protocol_version, ProtocolCompatibility,
    ProtocolNegotiationError, RunnerIdentity, RunnerPlatform, RunnerSurface,
    MINIMUM_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};

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
}
