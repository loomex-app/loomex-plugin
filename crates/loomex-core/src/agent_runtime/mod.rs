//! Local, policy-constrained AI agent execution.
//!
//! This module deliberately keeps transport, configuration persistence, MCP,
//! and CLI wiring outside the runtime. Callers provide canonical executable
//! paths and an already validated workspace binding. Commands are assembled by
//! fixed adapters and are never accepted from a backend payload.

// The protocol-owned error envelope is intentionally returned by value so
// callers can serialize it directly without a runtime-specific wrapper.
#![allow(clippy::result_large_err)]

mod adapter;
mod adapters;
mod cache;
mod error;
mod output;
mod process;
mod runtime;
mod schema;

pub use adapter::{
    AdapterFeatures, AdapterInvocationError, AgentAdapter, ExecutionInvocation, InvocationMode,
    ProbeCommands,
};
pub use adapters::{AgyAdapter, ClaudeAdapter, CodexAdapter};
pub use cache::ProbeCache;
pub use error::{classify_process_failure, runtime_error, RuntimeErrorContext};
pub use output::{parse_agent_output, ParsedAgentOutput};
pub use process::{
    CancellationToken, CommandSpec, ProcessLimits, ProcessObserver, ProcessOutput, ProcessRunner,
};
pub use runtime::{
    AdapterRegistry, AgentRuntimeObserver, LocalAgentRuntime, RuntimeConfig,
    RuntimeExecutionResult, SessionDiscovery,
};
pub use schema::{
    validate_json_schema, validate_schema_contract, SchemaContractError, SchemaViolation,
};

#[cfg(test)]
mod tests;
