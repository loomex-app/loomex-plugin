use crate::binding::{
    normalize_workspace_path, validate_workspace_path_inside_binding, ProjectRunnerBinding,
};
use crate::{CoreError, CoreResult};

pub const MVP_CAPABILITIES: &[&str] = &[
    "fs.list",
    "fs.read",
    "fs.write",
    "fs.apply_patch",
    "shell.exec",
    "git.status",
    "git.diff",
    "git.log",
    "http.request",
    "browser.playwright",
    "db.query",
    "docker.exec",
    "test.run",
];

pub const CONTRACT_MVP_COMPAT_CAPABILITIES: &[&str] = &[];

pub const RESERVED_CAPABILITIES: &[&str] = &["git.commit", "git.push"];

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    #[default]
    Ask,
    Deny,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PolicySource {
    BuiltInDefault,
    Project,
    Organization,
    EnterpriseManaged,
    LocalConfig,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CapabilitySupport {
    MvpExecutor,
    ReservedNoExecutor,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityPolicy {
    pub capability: String,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub capability: String,
    pub decision: PolicyDecision,
    pub path_prefix: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub command_prefix: Option<String>,
    pub sensitive_path_pattern: Option<String>,
}

impl PolicyRule {
    pub fn for_capability(capability: impl Into<String>, decision: PolicyDecision) -> Self {
        Self {
            capability: capability.into(),
            decision,
            path_prefix: None,
            host: None,
            method: None,
            command_prefix: None,
            sensitive_path_pattern: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLayer {
    pub source: PolicySource,
    pub default_decision: Option<PolicyDecision>,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    pub default_decision: PolicyDecision,
    pub capability_rules: Vec<CapabilityPolicy>,
}

impl PolicySet {
    pub fn evaluate(&self, capability: &str) -> PolicyDecision {
        self.capability_rules
            .iter()
            .find(|rule| rule.capability == capability)
            .map(|rule| rule.decision)
            .unwrap_or(self.default_decision)
    }

    pub fn as_layer(&self, source: PolicySource) -> PolicyLayer {
        PolicyLayer {
            source,
            default_decision: Some(self.default_decision),
            rules: self
                .capability_rules
                .iter()
                .map(|rule| PolicyRule::for_capability(rule.capability.clone(), rule.decision))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationInput {
    pub capability: String,
    pub requested_path: Option<String>,
    pub resolved_path: Option<String>,
    pub http_host: Option<String>,
    pub http_method: Option<String>,
    pub shell_command: Option<String>,
}

impl PolicyEvaluationInput {
    pub fn capability(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            requested_path: None,
            resolved_path: None,
            http_host: None,
            http_method: None,
            shell_command: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub source: PolicySource,
    pub capability_support: CapabilitySupport,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEngine {
    pub layers: Vec<PolicyLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicyDocument {
    pub policy_id: String,
    pub version: u64,
    pub rollout_percent: u8,
    pub locked: bool,
    pub layer: PolicyLayer,
    pub previous_versions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicySnapshot {
    pub organization: Option<ManagedPolicyDocument>,
    pub project: Option<ManagedPolicyDocument>,
    pub local_config: Option<PolicyLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicyVersionState {
    pub required_version: u64,
    pub runner_version: Option<u64>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            layers: vec![default_policy_layer()],
        }
    }
}

impl ManagedPolicyDocument {
    pub fn organization(
        policy_id: impl Into<String>,
        version: u64,
        rules: Vec<PolicyRule>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            version,
            rollout_percent: 100,
            locked: true,
            layer: PolicyLayer {
                source: PolicySource::Organization,
                default_decision: None,
                rules,
            },
            previous_versions: vec![],
        }
    }

    pub fn project(policy_id: impl Into<String>, version: u64, rules: Vec<PolicyRule>) -> Self {
        Self {
            policy_id: policy_id.into(),
            version,
            rollout_percent: 100,
            locked: true,
            layer: PolicyLayer {
                source: PolicySource::Project,
                default_decision: None,
                rules,
            },
            previous_versions: vec![],
        }
    }
}

impl PolicyEngine {
    pub fn new(layers: Vec<PolicyLayer>) -> Self {
        Self { layers }
    }

    pub fn evaluate(
        &self,
        input: &PolicyEvaluationInput,
        binding: &ProjectRunnerBinding,
    ) -> CoreResult<PolicyEvaluation> {
        let support = capability_support(&input.capability);
        if support == CapabilitySupport::ReservedNoExecutor {
            return Ok(PolicyEvaluation {
                decision: PolicyDecision::Deny,
                source: PolicySource::BuiltInDefault,
                capability_support: support,
                reason: "reserved_capability_without_mvp_executor",
            });
        }

        if let Some(requested_path) = &input.requested_path {
            validate_workspace_path_inside_binding(
                binding,
                requested_path,
                input.resolved_path.as_deref(),
            )
            .map_err(|_| {
                CoreError::new(
                    "POLICY_DENIED_OUTSIDE_WORKSPACE",
                    "policy denied path outside binding workspace",
                )
            })?;
        }

        let mut best: Option<PolicyEvaluation> = None;
        for layer in &self.layers {
            if let Some(rule) = layer.rules.iter().find(|rule| rule_matches(rule, input)) {
                let evaluation = PolicyEvaluation {
                    decision: rule.decision,
                    source: layer.source,
                    capability_support: support,
                    reason: "matched_rule",
                };
                best = Some(merge_evaluation(best, evaluation));
            } else if let Some(default_decision) = layer.default_decision {
                let evaluation = PolicyEvaluation {
                    decision: default_decision,
                    source: layer.source,
                    capability_support: support,
                    reason: "matched_layer_default",
                };
                best = Some(merge_evaluation(best, evaluation));
            }
        }

        let evaluation = best.unwrap_or(PolicyEvaluation {
            decision: PolicyDecision::Ask,
            source: PolicySource::BuiltInDefault,
            capability_support: support,
            reason: "unknown_capability_default_ask",
        });
        Ok(apply_shell_risk_floor(evaluation, input))
    }

    pub fn dry_run(
        &self,
        input: &PolicyEvaluationInput,
        binding: &ProjectRunnerBinding,
    ) -> CoreResult<PolicyEvaluation> {
        self.evaluate(input, binding)
    }
}

pub fn managed_policy_engine(
    snapshot: &ManagedPolicySnapshot,
    runner_rollout_bucket: u8,
) -> CoreResult<PolicyEngine> {
    let mut layers = vec![default_policy_layer()];
    if let Some(local_config) = &snapshot.local_config {
        let mut local = local_config.clone();
        local.source = PolicySource::LocalConfig;
        layers.push(local);
    }
    if let Some(org_policy) = &snapshot.organization {
        validate_managed_policy_document(org_policy)?;
        if policy_applies_to_runner(org_policy.rollout_percent, runner_rollout_bucket)? {
            let mut layer = org_policy.layer.clone();
            layer.source = PolicySource::Organization;
            layers.push(layer);
        }
    }
    if let Some(project_policy) = &snapshot.project {
        validate_managed_policy_document(project_policy)?;
        if policy_applies_to_runner(project_policy.rollout_percent, runner_rollout_bucket)? {
            let mut layer = project_policy.layer.clone();
            layer.source = PolicySource::Project;
            layers.push(layer);
        }
    }
    Ok(PolicyEngine::new(layers))
}

pub fn validate_managed_policy_document(policy: &ManagedPolicyDocument) -> CoreResult<()> {
    if policy.policy_id.trim().is_empty() || policy.version == 0 {
        return Err(CoreError::new(
            "MANAGED_POLICY_INVALID",
            "managed policy id and positive version are required",
        ));
    }
    policy_applies_to_runner(policy.rollout_percent, 0)?;
    Ok(())
}

pub fn policy_applies_to_runner(
    rollout_percent: u8,
    runner_rollout_bucket: u8,
) -> CoreResult<bool> {
    if rollout_percent > 100 || runner_rollout_bucket > 100 {
        return Err(CoreError::new(
            "MANAGED_POLICY_ROLLOUT_INVALID",
            "policy rollout_percent and runner bucket must be between 0 and 100",
        ));
    }
    Ok(runner_rollout_bucket < rollout_percent)
}

pub fn enforce_managed_policy_version(state: &ManagedPolicyVersionState) -> CoreResult<()> {
    let Some(runner_version) = state.runner_version else {
        return Err(CoreError::new(
            "MANAGED_POLICY_VERSION_REQUIRED",
            "runner must report the managed policy version before local execution",
        ));
    };
    if runner_version < state.required_version {
        return Err(CoreError::new(
            "MANAGED_POLICY_STALE",
            "runner policy version is stale and must be refreshed",
        ));
    }
    Ok(())
}

pub fn rollback_managed_policy(
    active: &ManagedPolicyDocument,
    target_version: u64,
) -> CoreResult<ManagedPolicyDocument> {
    if !active.previous_versions.contains(&target_version) {
        return Err(CoreError::new(
            "MANAGED_POLICY_ROLLBACK_TARGET_INVALID",
            "rollback target must be present in previous_versions",
        ));
    }
    let mut rollback = active.clone();
    rollback.version += 1;
    rollback.previous_versions.push(active.version);
    rollback.layer.default_decision = active.layer.default_decision;
    Ok(rollback)
}

pub fn enforce_policy_decision(evaluation: &PolicyEvaluation) -> CoreResult<()> {
    match evaluation.decision {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Ask => Err(CoreError::new(
            "POLICY_APPROVAL_REQUIRED",
            "policy requires approval before local execution",
        )),
        PolicyDecision::Deny => Err(CoreError::new(
            "POLICY_DENIED",
            "policy denied local execution",
        )),
    }
}

pub fn capability_support(capability: &str) -> CapabilitySupport {
    if MVP_CAPABILITIES.contains(&capability)
        || CONTRACT_MVP_COMPAT_CAPABILITIES.contains(&capability)
    {
        CapabilitySupport::MvpExecutor
    } else if RESERVED_CAPABILITIES.contains(&capability) {
        CapabilitySupport::ReservedNoExecutor
    } else {
        CapabilitySupport::Unknown
    }
}

pub fn default_policy_layer() -> PolicyLayer {
    PolicyLayer {
        source: PolicySource::BuiltInDefault,
        default_decision: Some(PolicyDecision::Ask),
        rules: vec![
            PolicyRule::for_capability("fs.read", PolicyDecision::Ask),
            PolicyRule::for_capability("fs.list", PolicyDecision::Allow),
            PolicyRule::for_capability("git.status", PolicyDecision::Allow),
            PolicyRule::for_capability("git.diff", PolicyDecision::Allow),
            PolicyRule::for_capability("git.log", PolicyDecision::Allow),
            PolicyRule::for_capability("fs.write", PolicyDecision::Ask),
            PolicyRule::for_capability("fs.apply_patch", PolicyDecision::Ask),
            PolicyRule::for_capability("shell.exec", PolicyDecision::Ask),
            PolicyRule::for_capability("http.request", PolicyDecision::Ask),
            PolicyRule::for_capability("browser.playwright", PolicyDecision::Ask),
            PolicyRule::for_capability("db.query", PolicyDecision::Ask),
            PolicyRule::for_capability("docker.exec", PolicyDecision::Ask),
            PolicyRule::for_capability("test.run", PolicyDecision::Ask),
            PolicyRule::for_capability("git.commit", PolicyDecision::Deny),
            PolicyRule::for_capability("git.push", PolicyDecision::Deny),
        ],
    }
}

fn merge_evaluation(current: Option<PolicyEvaluation>, next: PolicyEvaluation) -> PolicyEvaluation {
    let Some(current) = current else {
        return next;
    };
    if current.decision == PolicyDecision::Deny || next.decision == PolicyDecision::Deny {
        return if current.decision == PolicyDecision::Deny {
            current
        } else {
            next
        };
    }
    if source_precedence(next.source) >= source_precedence(current.source) {
        next
    } else {
        current
    }
}

fn source_precedence(source: PolicySource) -> u8 {
    match source {
        PolicySource::BuiltInDefault => 0,
        PolicySource::LocalConfig => 1,
        PolicySource::Project => 2,
        PolicySource::Organization => 3,
        PolicySource::EnterpriseManaged => 4,
    }
}

fn rule_matches(rule: &PolicyRule, input: &PolicyEvaluationInput) -> bool {
    if rule.capability != "*" && rule.capability != input.capability {
        return false;
    }
    if let Some(path_prefix) = &rule.path_prefix {
        let Some(path) = input.requested_path.as_deref() else {
            return false;
        };
        let Ok(normalized_prefix) = normalize_workspace_path(path_prefix) else {
            return false;
        };
        let Ok(normalized_path) = normalize_workspace_path(path) else {
            return false;
        };
        if !path_is_under_prefix(&normalized_prefix, &normalized_path) {
            return false;
        }
    }
    if let Some(pattern) = &rule.sensitive_path_pattern {
        let Some(path) = input.requested_path.as_deref() else {
            return false;
        };
        if !path.contains(pattern) {
            return false;
        }
    }
    if let Some(host) = &rule.host {
        if input.http_host.as_deref() != Some(host.as_str()) {
            return false;
        }
    }
    if let Some(method) = &rule.method {
        if input.http_method.as_deref() != Some(method.as_str()) {
            return false;
        }
    }
    if let Some(command_prefix) = &rule.command_prefix {
        let Some(command) = input.shell_command.as_deref() else {
            return false;
        };
        if !command.trim_start().starts_with(command_prefix) {
            return false;
        }
    }
    true
}

fn path_is_under_prefix(prefix: &str, path: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_shell_risky(command: Option<&str>) -> bool {
    let Some(command) = command else {
        return false;
    };
    let command = command.trim();
    command.starts_with("sh -c")
        || command.starts_with("bash -c")
        || command.contains(" rm ")
        || command.starts_with("rm ")
        || command.contains("curl ")
        || command.contains(" | sh")
}

fn apply_shell_risk_floor(
    evaluation: PolicyEvaluation,
    input: &PolicyEvaluationInput,
) -> PolicyEvaluation {
    if input.capability != "shell.exec" || !is_shell_risky(input.shell_command.as_deref()) {
        return evaluation;
    }
    if evaluation.decision == PolicyDecision::Allow {
        return PolicyEvaluation {
            decision: PolicyDecision::Ask,
            source: evaluation.source,
            capability_support: evaluation.capability_support,
            reason: "shell_command_requires_review",
        };
    }
    evaluation
}

#[cfg(test)]
mod tests {
    use crate::binding::{BindingStatus, ProjectRunnerBinding, WorkspacePath};

    use super::*;

    fn binding() -> ProjectRunnerBinding {
        ProjectRunnerBinding {
            id: "bind_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            runner_device_id: "device_123".to_string(),
            workspace: WorkspacePath::new("/Users/example/app", None).unwrap(),
            status: BindingStatus::Active,
            created_by: "user_123".to_string(),
            last_seen_at_epoch_ms: Some(1_000),
            revoked_at_epoch_ms: None,
        }
    }

    fn layer(source: PolicySource, capability: &str, decision: PolicyDecision) -> PolicyLayer {
        PolicyLayer {
            source,
            default_decision: None,
            rules: vec![PolicyRule::for_capability(capability, decision)],
        }
    }

    #[test]
    fn allow_decision() {
        let engine = PolicyEngine::new(vec![layer(
            PolicySource::Project,
            "git.status",
            PolicyDecision::Allow,
        )]);

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("git.status"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Allow, evaluation.decision);
    }

    #[test]
    fn ask_decision() {
        let engine = PolicyEngine::default();

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("shell.exec"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Ask, evaluation.decision);
    }

    #[test]
    fn deny_decision() {
        let engine = PolicyEngine::new(vec![layer(
            PolicySource::Project,
            "fs.write",
            PolicyDecision::Deny,
        )]);

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("fs.write"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
    }

    #[test]
    fn unknown_capability_asks() {
        let engine = PolicyEngine::default();

        let evaluation = engine
            .dry_run(
                &PolicyEvaluationInput::capability("future.unknown"),
                &binding(),
            )
            .unwrap();

        assert_eq!(CapabilitySupport::Unknown, evaluation.capability_support);
        assert_eq!(PolicyDecision::Ask, evaluation.decision);
    }

    #[test]
    fn org_policy_override_project_policy() {
        let engine = PolicyEngine::new(vec![
            layer(PolicySource::Project, "fs.read", PolicyDecision::Ask),
            layer(PolicySource::Organization, "fs.read", PolicyDecision::Allow),
        ]);

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("fs.read"), &binding())
            .unwrap();

        assert_eq!(PolicySource::Organization, evaluation.source);
        assert_eq!(PolicyDecision::Allow, evaluation.decision);
    }

    #[test]
    fn deny_cannot_be_weakened_by_local_config() {
        let engine = PolicyEngine::new(vec![
            layer(PolicySource::Project, "fs.write", PolicyDecision::Deny),
            layer(PolicySource::LocalConfig, "fs.write", PolicyDecision::Allow),
        ]);

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("fs.write"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
    }

    #[test]
    fn path_outside_workspace_denied() {
        let engine = PolicyEngine::default();
        let mut input = PolicyEvaluationInput::capability("fs.read");
        input.requested_path = Some("/Users/example/secret.txt".to_string());

        let err = engine.dry_run(&input, &binding()).unwrap_err();

        assert_eq!("POLICY_DENIED_OUTSIDE_WORKSPACE", err.code);
    }

    #[test]
    fn sensitive_file_pattern_can_ask_or_deny() {
        let mut rule = PolicyRule::for_capability("fs.read", PolicyDecision::Deny);
        rule.sensitive_path_pattern = Some(".env".to_string());
        let engine = PolicyEngine::new(vec![PolicyLayer {
            source: PolicySource::Project,
            default_decision: Some(PolicyDecision::Ask),
            rules: vec![rule],
        }]);
        let mut input = PolicyEvaluationInput::capability("fs.read");
        input.requested_path = Some("/Users/example/app/.env".to_string());

        let evaluation = engine.dry_run(&input, &binding()).unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
    }

    #[test]
    fn network_domain_allowlist() {
        let mut rule = PolicyRule::for_capability("http.request", PolicyDecision::Allow);
        rule.host = Some("api.internal".to_string());
        rule.method = Some("GET".to_string());
        let engine = PolicyEngine::new(vec![PolicyLayer {
            source: PolicySource::Project,
            default_decision: Some(PolicyDecision::Ask),
            rules: vec![rule],
        }]);
        let mut input = PolicyEvaluationInput::capability("http.request");
        input.http_host = Some("api.internal".to_string());
        input.http_method = Some("GET".to_string());

        let evaluation = engine.dry_run(&input, &binding()).unwrap();

        assert_eq!(PolicyDecision::Allow, evaluation.decision);
    }

    #[test]
    fn shell_command_risk_classification() {
        let engine = PolicyEngine::new(vec![layer(
            PolicySource::Project,
            "shell.exec",
            PolicyDecision::Allow,
        )]);
        let mut input = PolicyEvaluationInput::capability("shell.exec");
        input.shell_command = Some("sh -c 'rm -rf build'".to_string());

        let evaluation = engine.dry_run(&input, &binding()).unwrap();

        assert_eq!(PolicyDecision::Ask, evaluation.decision);
        assert_eq!("shell_command_requires_review", evaluation.reason);
    }

    #[test]
    fn risky_shell_deny_is_not_weakened_to_ask() {
        let engine = PolicyEngine::new(vec![layer(
            PolicySource::Organization,
            "shell.exec",
            PolicyDecision::Deny,
        )]);
        let mut input = PolicyEvaluationInput::capability("shell.exec");
        input.shell_command = Some("sh -c 'rm -rf build'".to_string());

        let evaluation = engine.dry_run(&input, &binding()).unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
    }

    #[test]
    fn future_capability_without_executor_returns_unsupported() {
        let engine = PolicyEngine::default();

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("git.push"), &binding())
            .unwrap();

        assert_eq!(
            CapabilitySupport::ReservedNoExecutor,
            evaluation.capability_support
        );
        assert_eq!(PolicyDecision::Deny, evaluation.decision);
        assert_eq!(
            "reserved_capability_without_mvp_executor",
            evaluation.reason
        );
    }

    #[test]
    fn expanded_capabilities_are_policy_bound_mvp_executor_actions() {
        for capability in ["browser.playwright", "db.query", "docker.exec", "test.run"] {
            let evaluation = PolicyEngine::default()
                .dry_run(&PolicyEvaluationInput::capability(capability), &binding())
                .unwrap();

            assert_eq!(PolicyDecision::Ask, evaluation.decision);
            assert_eq!(
                CapabilitySupport::MvpExecutor,
                evaluation.capability_support
            );
        }
    }

    #[test]
    fn browser_and_docker_can_be_denied_by_policy() {
        for capability in ["browser.playwright", "docker.exec"] {
            let engine = PolicyEngine::new(vec![PolicyLayer {
                source: PolicySource::Project,
                default_decision: Some(PolicyDecision::Ask),
                rules: vec![PolicyRule::for_capability(capability, PolicyDecision::Deny)],
            }]);

            let evaluation = engine
                .dry_run(&PolicyEvaluationInput::capability(capability), &binding())
                .unwrap();

            assert_eq!(PolicyDecision::Deny, evaluation.decision);
            assert_eq!("matched_rule", evaluation.reason);
        }
    }

    #[test]
    fn managed_org_deny_overrides_project_allow() {
        let org_policy = ManagedPolicyDocument::organization(
            "org_policy",
            3,
            vec![PolicyRule::for_capability(
                "shell.exec",
                PolicyDecision::Deny,
            )],
        );
        let project_policy = ManagedPolicyDocument::project(
            "project_policy",
            2,
            vec![PolicyRule::for_capability(
                "shell.exec",
                PolicyDecision::Allow,
            )],
        );
        let engine = managed_policy_engine(
            &ManagedPolicySnapshot {
                organization: Some(org_policy),
                project: Some(project_policy),
                local_config: None,
            },
            0,
        )
        .unwrap();

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("shell.exec"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
        assert_eq!(PolicySource::Organization, evaluation.source);
    }

    #[test]
    fn managed_project_policy_can_make_org_policy_stricter() {
        let org_policy = ManagedPolicyDocument::organization(
            "org_policy",
            1,
            vec![PolicyRule::for_capability(
                "http.request",
                PolicyDecision::Allow,
            )],
        );
        let project_policy = ManagedPolicyDocument::project(
            "project_policy",
            5,
            vec![PolicyRule::for_capability(
                "http.request",
                PolicyDecision::Deny,
            )],
        );
        let engine = managed_policy_engine(
            &ManagedPolicySnapshot {
                organization: Some(org_policy),
                project: Some(project_policy),
                local_config: None,
            },
            0,
        )
        .unwrap();

        let evaluation = engine
            .dry_run(
                &PolicyEvaluationInput::capability("http.request"),
                &binding(),
            )
            .unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
        assert_eq!(PolicySource::Project, evaluation.source);
    }

    #[test]
    fn local_config_cannot_weaken_managed_policy() {
        let org_policy = ManagedPolicyDocument::organization(
            "org_policy",
            1,
            vec![PolicyRule::for_capability("fs.write", PolicyDecision::Deny)],
        );
        let local_config = PolicyLayer {
            source: PolicySource::LocalConfig,
            default_decision: None,
            rules: vec![PolicyRule::for_capability(
                "fs.write",
                PolicyDecision::Allow,
            )],
        };
        let engine = managed_policy_engine(
            &ManagedPolicySnapshot {
                organization: Some(org_policy),
                project: None,
                local_config: Some(local_config),
            },
            0,
        )
        .unwrap();

        let evaluation = engine
            .dry_run(&PolicyEvaluationInput::capability("fs.write"), &binding())
            .unwrap();

        assert_eq!(PolicyDecision::Deny, evaluation.decision);
    }

    #[test]
    fn managed_policy_version_must_be_current_before_execution() {
        enforce_managed_policy_version(&ManagedPolicyVersionState {
            required_version: 9,
            runner_version: Some(9),
        })
        .unwrap();

        let err = enforce_managed_policy_version(&ManagedPolicyVersionState {
            required_version: 9,
            runner_version: Some(8),
        })
        .unwrap_err();

        assert_eq!("MANAGED_POLICY_STALE", err.code);
    }

    #[test]
    fn managed_policy_rollout_controls_application() {
        assert!(policy_applies_to_runner(10, 0).unwrap());
        assert!(!policy_applies_to_runner(10, 10).unwrap());
        assert!(!policy_applies_to_runner(0, 0).unwrap());
        assert!(policy_applies_to_runner(100, 99).unwrap());
    }

    #[test]
    fn managed_policy_rollback_requires_previous_version() {
        let mut active = ManagedPolicyDocument::organization(
            "org_policy",
            8,
            vec![PolicyRule::for_capability(
                "shell.exec",
                PolicyDecision::Deny,
            )],
        );
        active.previous_versions = vec![6, 7];

        let rollback = rollback_managed_policy(&active, 7).unwrap();
        let err = rollback_managed_policy(&active, 5).unwrap_err();

        assert_eq!(9, rollback.version);
        assert!(rollback.previous_versions.contains(&8));
        assert_eq!("MANAGED_POLICY_ROLLBACK_TARGET_INVALID", err.code);
    }
}
