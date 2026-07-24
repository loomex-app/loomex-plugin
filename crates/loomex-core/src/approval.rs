use std::collections::BTreeMap;

use crate::{CoreError, CoreResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ApprovalChannel {
    CliPrompt,
    MacDialog,
    WebUi,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ApprovalRequestKind {
    LocalExecution,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPolicySnapshot {
    pub policy_id: String,
    pub policy_version: u64,
    pub decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPayload {
    pub workflow_run_id: String,
    pub node_id: String,
    pub capability: String,
    pub summary: String,
    pub full_request_details: String,
    pub risk_indicators: Vec<String>,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: String,
    pub kind: ApprovalRequestKind,
    pub status: ApprovalStatus,
    pub payload: ApprovalPayload,
    pub policy_snapshot: ApprovalPolicySnapshot,
    pub requested_channel: ApprovalChannel,
    pub authorized_user_ids: Vec<String>,
    pub created_at_epoch_ms: u64,
    pub decided_at_epoch_ms: Option<u64>,
    pub decided_by_user_id: Option<String>,
    pub decision: Option<ApprovalDecision>,
    pub cancel_reason: Option<String>,
}

impl ApprovalRequest {
    pub fn prompt(&self) -> ApprovalPrompt {
        ApprovalPrompt {
            approval_request_id: self.id.clone(),
            workflow_run_id: self.payload.workflow_run_id.clone(),
            node_id: self.payload.node_id.clone(),
            capability: self.payload.capability.clone(),
            action_summary: self.payload.summary.clone(),
            full_request_details: self.payload.full_request_details.clone(),
            risk_indicators: self.payload.risk_indicators.clone(),
            risk_level: risk_level(&self.payload.risk_indicators).to_string(),
            expires_at_epoch_ms: self.payload.expires_at_epoch_ms,
            policy_snapshot: self.policy_snapshot.clone(),
            channel: self.requested_channel,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateApprovalRequestInput {
    pub id: String,
    pub workflow_run_id: String,
    pub node_id: String,
    pub capability: String,
    pub summary: String,
    pub full_request_details: String,
    pub risk_indicators: Vec<String>,
    pub timeout_ms: u64,
    pub policy_snapshot: ApprovalPolicySnapshot,
    pub requested_channel: ApprovalChannel,
    pub authorized_user_ids: Vec<String>,
    pub now_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrompt {
    pub approval_request_id: String,
    pub workflow_run_id: String,
    pub node_id: String,
    pub capability: String,
    pub action_summary: String,
    pub full_request_details: String,
    pub risk_indicators: Vec<String>,
    pub risk_level: String,
    pub expires_at_epoch_ms: u64,
    pub policy_snapshot: ApprovalPolicySnapshot,
    pub channel: ApprovalChannel,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    AllowOnce,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionInput {
    pub approval_request_id: String,
    pub decision: ApprovalDecision,
    pub user_id: String,
    pub idempotency_key: String,
    pub decided_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionOutcome {
    pub approval_request_id: String,
    pub status: ApprovalStatus,
    pub decision: Option<ApprovalDecision>,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalAuditEvent {
    pub approval_request_id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub occurred_at_epoch_ms: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApprovalRegistry {
    requests: BTreeMap<String, ApprovalRequest>,
    decision_idempotency: BTreeMap<ApprovalIdempotencyKey, ApprovalIdempotencyRecord>,
    audit_events: Vec<ApprovalAuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ApprovalIdempotencyKey {
    approval_request_id: String,
    user_id: String,
    idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalIdempotencyRecord {
    decision: ApprovalDecision,
    result: CoreResult<ApprovalDecisionOutcome>,
}

impl ApprovalRegistry {
    pub fn create_request(
        &mut self,
        input: CreateApprovalRequestInput,
    ) -> CoreResult<ApprovalRequest> {
        validate_create_input(&input)?;
        if self.requests.contains_key(&input.id) {
            return Err(CoreError::new(
                "APPROVAL_REQUEST_DUPLICATE",
                "approval request id already exists",
            ));
        }

        let request = ApprovalRequest {
            id: input.id,
            kind: ApprovalRequestKind::LocalExecution,
            status: ApprovalStatus::Pending,
            payload: ApprovalPayload {
                workflow_run_id: input.workflow_run_id,
                node_id: input.node_id,
                capability: input.capability,
                summary: input.summary,
                full_request_details: input.full_request_details,
                risk_indicators: input.risk_indicators,
                expires_at_epoch_ms: input.now_epoch_ms + input.timeout_ms,
            },
            policy_snapshot: input.policy_snapshot,
            requested_channel: input.requested_channel,
            authorized_user_ids: input.authorized_user_ids,
            created_at_epoch_ms: input.now_epoch_ms,
            decided_at_epoch_ms: None,
            decided_by_user_id: None,
            decision: None,
            cancel_reason: None,
        };
        self.audit_events.push(ApprovalAuditEvent {
            approval_request_id: request.id.clone(),
            event_type: "approval.created".to_string(),
            user_id: None,
            idempotency_key: None,
            occurred_at_epoch_ms: request.created_at_epoch_ms,
        });
        self.requests.insert(request.id.clone(), request.clone());
        Ok(request)
    }

    pub fn decide(&mut self, input: ApprovalDecisionInput) -> CoreResult<ApprovalDecisionOutcome> {
        validate_decision_input(&input)?;
        let request = self
            .requests
            .get_mut(&input.approval_request_id)
            .ok_or_else(|| {
                CoreError::new(
                    "APPROVAL_REQUEST_NOT_FOUND",
                    "approval request was not found",
                )
            })?;
        if !request
            .authorized_user_ids
            .iter()
            .any(|authorized| authorized == &input.user_id)
        {
            return Err(CoreError::new(
                "APPROVAL_USER_UNAUTHORIZED",
                "user is not authorized to decide this approval request",
            ));
        }
        let idempotency_key = ApprovalIdempotencyKey {
            approval_request_id: input.approval_request_id.clone(),
            user_id: input.user_id.clone(),
            idempotency_key: input.idempotency_key.clone(),
        };
        if let Some(record) = self.decision_idempotency.get(&idempotency_key) {
            if record.decision != input.decision {
                return Err(CoreError::new(
                    "APPROVAL_IDEMPOTENCY_CONFLICT",
                    "idempotency key was already used with a different approval decision",
                ));
            }
            return record.result.clone().map(|mut outcome| {
                outcome.duplicate = true;
                outcome
            });
        }
        if input.decided_at_epoch_ms >= request.payload.expires_at_epoch_ms {
            request.status = ApprovalStatus::Expired;
            request.decided_at_epoch_ms = Some(input.decided_at_epoch_ms);
            self.audit_events.push(ApprovalAuditEvent {
                approval_request_id: request.id.clone(),
                event_type: "approval.expired".to_string(),
                user_id: Some(input.user_id),
                idempotency_key: Some(input.idempotency_key),
                occurred_at_epoch_ms: input.decided_at_epoch_ms,
            });
            let result = Err(CoreError::new(
                "APPROVAL_REQUEST_EXPIRED",
                "approval request expired before decision",
            ));
            self.decision_idempotency.insert(
                idempotency_key,
                ApprovalIdempotencyRecord {
                    decision: input.decision,
                    result: result.clone(),
                },
            );
            return result;
        }
        if request.status != ApprovalStatus::Pending {
            return Err(CoreError::new(
                "APPROVAL_REQUEST_TERMINAL",
                "approval request is no longer pending",
            ));
        }

        request.status = match input.decision {
            ApprovalDecision::AllowOnce => ApprovalStatus::Approved,
            ApprovalDecision::Deny => ApprovalStatus::Denied,
        };
        request.decision = Some(input.decision);
        request.decided_at_epoch_ms = Some(input.decided_at_epoch_ms);
        request.decided_by_user_id = Some(input.user_id.clone());
        let outcome = ApprovalDecisionOutcome {
            approval_request_id: request.id.clone(),
            status: request.status,
            decision: request.decision,
            duplicate: false,
        };
        self.decision_idempotency.insert(
            idempotency_key,
            ApprovalIdempotencyRecord {
                decision: input.decision,
                result: Ok(outcome.clone()),
            },
        );
        self.audit_events.push(ApprovalAuditEvent {
            approval_request_id: request.id.clone(),
            event_type: match input.decision {
                ApprovalDecision::AllowOnce => "approval.approved",
                ApprovalDecision::Deny => "approval.denied",
            }
            .to_string(),
            user_id: Some(input.user_id),
            idempotency_key: Some(input.idempotency_key),
            occurred_at_epoch_ms: input.decided_at_epoch_ms,
        });
        Ok(outcome)
    }

    pub fn expire_pending(&mut self, now_epoch_ms: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for request in self.requests.values_mut() {
            if request.status == ApprovalStatus::Pending
                && now_epoch_ms >= request.payload.expires_at_epoch_ms
            {
                request.status = ApprovalStatus::Expired;
                request.decided_at_epoch_ms = Some(now_epoch_ms);
                expired.push(request.id.clone());
                self.audit_events.push(ApprovalAuditEvent {
                    approval_request_id: request.id.clone(),
                    event_type: "approval.expired".to_string(),
                    user_id: None,
                    idempotency_key: None,
                    occurred_at_epoch_ms: now_epoch_ms,
                });
            }
        }
        expired
    }

    pub fn cancel_run(
        &mut self,
        workflow_run_id: &str,
        now_epoch_ms: u64,
        reason: impl Into<String>,
    ) -> Vec<String> {
        let reason = reason.into();
        let mut cancelled = Vec::new();
        for request in self.requests.values_mut() {
            if request.payload.workflow_run_id == workflow_run_id
                && request.status == ApprovalStatus::Pending
            {
                request.status = ApprovalStatus::Cancelled;
                request.decided_at_epoch_ms = Some(now_epoch_ms);
                request.cancel_reason = Some(reason.clone());
                cancelled.push(request.id.clone());
                self.audit_events.push(ApprovalAuditEvent {
                    approval_request_id: request.id.clone(),
                    event_type: "approval.cancelled".to_string(),
                    user_id: None,
                    idempotency_key: None,
                    occurred_at_epoch_ms: now_epoch_ms,
                });
            }
        }
        cancelled
    }

    pub fn get(&self, approval_request_id: &str) -> Option<&ApprovalRequest> {
        self.requests.get(approval_request_id)
    }

    pub fn pending_for_run(&self, workflow_run_id: &str) -> Vec<&ApprovalRequest> {
        self.requests
            .values()
            .filter(|request| {
                request.payload.workflow_run_id == workflow_run_id
                    && request.status == ApprovalStatus::Pending
            })
            .collect()
    }

    pub fn audit_events(&self) -> &[ApprovalAuditEvent] {
        &self.audit_events
    }
}

pub trait ApprovalPromptProvider {
    fn decide(&self, prompt: &ApprovalPrompt) -> CoreResult<ApprovalDecision>;
}

#[derive(Debug, Default)]
pub struct TerminalPromptProvider;

impl ApprovalPromptProvider for TerminalPromptProvider {
    fn decide(&self, _prompt: &ApprovalPrompt) -> CoreResult<ApprovalDecision> {
        Err(CoreError::new(
            "INTERACTIVE_PROMPT_NOT_WIRED",
            "terminal prompt UI is wired by loomex-cli",
        ))
    }
}

#[derive(Debug, Default)]
pub struct MacDialogPromptProvider;

impl ApprovalPromptProvider for MacDialogPromptProvider {
    fn decide(&self, _prompt: &ApprovalPrompt) -> CoreResult<ApprovalDecision> {
        Err(CoreError::new(
            "MAC_DIALOG_NOT_WIRED",
            "mac dialog UI is wired by loomex-tauri",
        ))
    }
}

#[derive(Debug, Default)]
pub struct NonInteractivePromptProvider;

impl ApprovalPromptProvider for NonInteractivePromptProvider {
    fn decide(&self, _prompt: &ApprovalPrompt) -> CoreResult<ApprovalDecision> {
        Err(CoreError::new(
            "APPROVAL_REQUIRED",
            "approval required in non-interactive mode",
        ))
    }
}

pub fn decide_with_provider(
    provider: &dyn ApprovalPromptProvider,
    request: &ApprovalRequest,
) -> CoreResult<ApprovalDecision> {
    if request.kind != ApprovalRequestKind::LocalExecution {
        return Err(CoreError::new(
            "APPROVAL_KIND_UNSUPPORTED",
            "only local execution approvals are supported",
        ));
    }
    provider.decide(&request.prompt())
}

fn validate_create_input(input: &CreateApprovalRequestInput) -> CoreResult<()> {
    for (field, value) in [
        ("id", &input.id),
        ("workflow_run_id", &input.workflow_run_id),
        ("node_id", &input.node_id),
        ("capability", &input.capability),
        ("summary", &input.summary),
        ("full_request_details", &input.full_request_details),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("APPROVAL_REQUEST_MISSING_FIELD", field));
        }
    }
    if input.timeout_ms == 0 {
        return Err(CoreError::new(
            "APPROVAL_TIMEOUT_INVALID",
            "approval timeout must be positive",
        ));
    }
    if input.authorized_user_ids.is_empty() {
        return Err(CoreError::new(
            "APPROVAL_AUTHORIZATION_REQUIRED",
            "approval requires at least one authorized user",
        ));
    }
    Ok(())
}

fn validate_decision_input(input: &ApprovalDecisionInput) -> CoreResult<()> {
    for (field, value) in [
        ("approval_request_id", &input.approval_request_id),
        ("user_id", &input.user_id),
        ("idempotency_key", &input.idempotency_key),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("APPROVAL_DECISION_MISSING_FIELD", field));
        }
    }
    Ok(())
}

fn risk_level(risk_indicators: &[String]) -> &'static str {
    if risk_indicators
        .iter()
        .any(|indicator| indicator == "destructive" || indicator == "external_network")
    {
        "high"
    } else if risk_indicators.is_empty() {
        "low"
    } else {
        "medium"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticPromptProvider {
        decision: ApprovalDecision,
    }

    impl ApprovalPromptProvider for StaticPromptProvider {
        fn decide(&self, _prompt: &ApprovalPrompt) -> CoreResult<ApprovalDecision> {
            Ok(self.decision)
        }
    }

    fn snapshot() -> ApprovalPolicySnapshot {
        ApprovalPolicySnapshot {
            policy_id: "policy_123".to_string(),
            policy_version: 1,
            decision_reason: "shell requires approval".to_string(),
        }
    }

    fn create_input(id: &str, channel: ApprovalChannel) -> CreateApprovalRequestInput {
        CreateApprovalRequestInput {
            id: id.to_string(),
            workflow_run_id: "run_123".to_string(),
            node_id: "node_123".to_string(),
            capability: "shell.exec".to_string(),
            summary: "Run make test".to_string(),
            full_request_details: "shell.exec: make test in workspace".to_string(),
            risk_indicators: vec!["shell".to_string()],
            timeout_ms: 30_000,
            policy_snapshot: snapshot(),
            requested_channel: channel,
            authorized_user_ids: vec!["user_123".to_string()],
            now_epoch_ms: 1_000,
        }
    }

    fn decision(
        approval_request_id: &str,
        decision: ApprovalDecision,
        key: &str,
    ) -> ApprovalDecisionInput {
        ApprovalDecisionInput {
            approval_request_id: approval_request_id.to_string(),
            decision,
            user_id: "user_123".to_string(),
            idempotency_key: key.to_string(),
            decided_at_epoch_ms: 2_000,
        }
    }

    fn assert_prompt_has_full_context(prompt: &ApprovalPrompt, channel: ApprovalChannel) {
        assert_eq!("approval_123", prompt.approval_request_id);
        assert_eq!("run_123", prompt.workflow_run_id);
        assert_eq!("node_123", prompt.node_id);
        assert_eq!("shell.exec", prompt.capability);
        assert_eq!("Run make test", prompt.action_summary);
        assert_eq!(
            "shell.exec: make test in workspace",
            prompt.full_request_details
        );
        assert_eq!(vec!["shell".to_string()], prompt.risk_indicators);
        assert_eq!("medium", prompt.risk_level);
        assert_eq!(31_000, prompt.expires_at_epoch_ms);
        assert_eq!(snapshot(), prompt.policy_snapshot);
        assert_eq!(channel, prompt.channel);
    }

    #[test]
    fn create_approval_request() {
        let mut registry = ApprovalRegistry::default();

        let request = registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        assert_eq!(ApprovalRequestKind::LocalExecution, request.kind);
        assert_eq!(ApprovalStatus::Pending, request.status);
        assert_eq!("run_123", request.payload.workflow_run_id);
        assert_eq!("node_123", request.payload.node_id);
        assert_eq!("shell.exec", request.payload.capability);
        assert_eq!(31_000, request.payload.expires_at_epoch_ms);
    }

    #[test]
    fn approve_once() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        let outcome = registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_1",
            ))
            .unwrap();

        assert_eq!(ApprovalStatus::Approved, outcome.status);
        assert_eq!(Some(ApprovalDecision::AllowOnce), outcome.decision);
    }

    #[test]
    fn deny() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        let outcome = registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::Deny,
                "decision_1",
            ))
            .unwrap();

        assert_eq!(ApprovalStatus::Denied, outcome.status);
        assert_eq!(Some(ApprovalDecision::Deny), outcome.decision);
    }

    #[test]
    fn timeout() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        let expired = registry.expire_pending(31_000);

        assert_eq!(vec!["approval_123".to_string()], expired);
        assert_eq!(
            ApprovalStatus::Expired,
            registry.get("approval_123").unwrap().status
        );
    }

    #[test]
    fn cancel_run_cancels_approval() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        let cancelled = registry.cancel_run("run_123", 2_000, "run_cancelled");

        assert_eq!(vec!["approval_123".to_string()], cancelled);
        let request = registry.get("approval_123").unwrap();
        assert_eq!(ApprovalStatus::Cancelled, request.status);
        assert_eq!(Some("run_cancelled".to_string()), request.cancel_reason);
    }

    #[test]
    fn duplicate_decision_ignored() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_1",
            ))
            .unwrap();

        let duplicate = registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_1",
            ))
            .unwrap();

        assert!(duplicate.duplicate);
        assert_eq!(ApprovalStatus::Approved, duplicate.status);
        assert_eq!(2, registry.audit_events().len());
    }

    #[test]
    fn same_idempotency_key_for_another_approval_does_not_replay_previous_outcome() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        registry
            .create_request(create_input("approval_456", ApprovalChannel::CliPrompt))
            .unwrap();
        registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_shared",
            ))
            .unwrap();

        let outcome = registry
            .decide(decision(
                "approval_456",
                ApprovalDecision::Deny,
                "decision_shared",
            ))
            .unwrap();

        assert!(!outcome.duplicate);
        assert_eq!("approval_456", outcome.approval_request_id);
        assert_eq!(ApprovalStatus::Denied, outcome.status);
        assert_eq!(Some(ApprovalDecision::Deny), outcome.decision);
    }

    #[test]
    fn decision_from_unauthorized_user_rejected() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        let mut input = decision("approval_123", ApprovalDecision::AllowOnce, "decision_1");
        input.user_id = "user_other".to_string();

        let err = registry.decide(input).unwrap_err();

        assert_eq!("APPROVAL_USER_UNAUTHORIZED", err.code);
    }

    #[test]
    fn unauthorized_user_with_reused_idempotency_key_is_still_rejected() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        registry
            .create_request(create_input("approval_456", ApprovalChannel::CliPrompt))
            .unwrap();
        registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_shared",
            ))
            .unwrap();
        let mut input = decision(
            "approval_456",
            ApprovalDecision::AllowOnce,
            "decision_shared",
        );
        input.user_id = "user_other".to_string();

        let err = registry.decide(input).unwrap_err();

        assert_eq!("APPROVAL_USER_UNAUTHORIZED", err.code);
    }

    #[test]
    fn expired_decision_retry_is_idempotent_without_duplicate_audit() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        let mut input = decision("approval_123", ApprovalDecision::AllowOnce, "decision_1");
        input.decided_at_epoch_ms = 31_000;

        let first = registry.decide(input.clone()).unwrap_err();
        let audit_count = registry.audit_events().len();
        let retry = registry.decide(input).unwrap_err();

        assert_eq!("APPROVAL_REQUEST_EXPIRED", first.code);
        assert_eq!("APPROVAL_REQUEST_EXPIRED", retry.code);
        assert_eq!(2, audit_count);
        assert_eq!(audit_count, registry.audit_events().len());
    }

    #[test]
    fn cli_approval() {
        let mut registry = ApprovalRegistry::default();
        let request = registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        let provider = StaticPromptProvider {
            decision: ApprovalDecision::AllowOnce,
        };

        let decision = decide_with_provider(&provider, &request).unwrap();

        assert_eq!(ApprovalDecision::AllowOnce, decision);
        assert_eq!(ApprovalChannel::CliPrompt, request.prompt().channel);
        assert_prompt_has_full_context(&request.prompt(), ApprovalChannel::CliPrompt);
    }

    #[test]
    fn mac_app_approval() {
        let mut registry = ApprovalRegistry::default();
        let request = registry
            .create_request(create_input("approval_123", ApprovalChannel::MacDialog))
            .unwrap();
        let provider = StaticPromptProvider {
            decision: ApprovalDecision::Deny,
        };

        let decision = decide_with_provider(&provider, &request).unwrap();

        assert_eq!(ApprovalDecision::Deny, decision);
        assert_eq!(ApprovalChannel::MacDialog, request.prompt().channel);
        assert_prompt_has_full_context(&request.prompt(), ApprovalChannel::MacDialog);
    }

    #[test]
    fn approval_is_not_human_input() {
        let mut registry = ApprovalRegistry::default();

        let request = registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        assert_eq!(ApprovalRequestKind::LocalExecution, request.kind);
    }

    #[test]
    fn pending_approval_resumes_after_reconnect() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();

        let pending = registry.pending_for_run("run_123");

        assert_eq!(1, pending.len());
        assert_eq!("approval_123", pending[0].id);
    }

    #[test]
    fn approval_after_cancel_is_rejected() {
        let mut registry = ApprovalRegistry::default();
        registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        registry.cancel_run("run_123", 2_000, "run_cancelled");

        let err = registry
            .decide(decision(
                "approval_123",
                ApprovalDecision::AllowOnce,
                "decision_1",
            ))
            .unwrap_err();

        assert_eq!("APPROVAL_REQUEST_TERMINAL", err.code);
    }

    #[test]
    fn non_interactive_provider_fails_closed() {
        let provider = NonInteractivePromptProvider;
        let mut registry = ApprovalRegistry::default();
        let request = registry
            .create_request(create_input("approval_123", ApprovalChannel::CliPrompt))
            .unwrap();
        let prompt = request.prompt();

        assert_eq!(
            "APPROVAL_REQUIRED",
            provider.decide(&prompt).unwrap_err().code
        );
    }
}
