use crate::CoreResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub capability: String,
    pub input: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityResult {
    pub capability: String,
    pub output: String,
}

pub trait CapabilityExecutor {
    fn capability(&self) -> &'static str;
    fn supports(&self, capability: &str) -> bool {
        self.capability() == capability
    }
    fn execute(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult>;
}

#[cfg(test)]
mod tests {
    use crate::{CoreError, CoreResult};

    use super::*;

    struct MockExecutor;

    impl CapabilityExecutor for MockExecutor {
        fn capability(&self) -> &'static str {
            "mock.echo"
        }

        fn execute(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult> {
            if request.capability != self.capability() {
                return Err(CoreError::new("UNSUPPORTED_CAPABILITY", request.capability));
            }
            Ok(CapabilityResult {
                capability: request.capability,
                output: request.input,
            })
        }
    }

    #[test]
    fn mock_executor_enforces_capability_boundary() {
        let executor = MockExecutor;
        let result = executor
            .execute(CapabilityRequest {
                capability: "mock.echo".to_string(),
                input: "ok".to_string(),
            })
            .unwrap();

        assert_eq!("ok", result.output);
        assert_eq!(
            "UNSUPPORTED_CAPABILITY",
            executor
                .execute(CapabilityRequest {
                    capability: "shell.exec".to_string(),
                    input: "echo no".to_string(),
                })
                .unwrap_err()
                .code
        );
    }
}
