//! Codex-facing MCP adapter for the long-lived Loomex local runner.
//!
//! The adapter deliberately owns no workflow execution state. Every tool call is
//! forwarded over the authenticated, per-user local-control channel, so closing
//! Codex cannot terminate an active workflow.

pub mod ipc;
pub mod protocol;
pub mod tools;

pub use protocol::{serve, Server};
