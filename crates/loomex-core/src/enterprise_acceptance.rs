use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

pub const ENTERPRISE_ACCEPTANCE_PLAN_SCHEMA_VERSION: &str =
    "loomex.runner.enterpriseAcceptancePlan/v1";
pub const ENTERPRISE_ACCEPTANCE_REPORT_SCHEMA_VERSION: &str =
    "loomex.runner.enterpriseAcceptanceReport/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAcceptancePlan {
    pub schema_version: String,
    pub checklist: Vec<EnterpriseAcceptanceCheck>,
    pub security_review_scope: Vec<SecurityReviewScopeItem>,
    pub compliance_package: Vec<CompliancePackageItem>,
    pub release_blocking_thresholds: EnterpriseReleaseBlockingThresholds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAcceptanceCheck {
    pub id: String,
    pub title: String,
    pub evidence_required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReviewScopeItem {
    pub id: String,
    pub title: String,
    pub required_tests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePackageItem {
    pub id: String,
    pub title: String,
    pub required_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseReleaseBlockingThresholds {
    pub max_open_critical_high_security_findings: u32,
    pub medium_findings_require_mitigation_owner_and_date: bool,
    pub update_chain_tamper_test_must_pass: bool,
    pub workspace_escape_tests_must_pass: bool,
    pub secret_leakage_scan_must_pass: bool,
    pub policy_bypass_tests_must_pass: bool,
    pub retention_legal_hold_must_be_documented: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAcceptanceReport {
    pub schema_version: String,
    pub scenario_results: Vec<EnterpriseScenarioResult>,
    pub security_review_results: Vec<SecurityReviewResult>,
    pub security_findings: Vec<EnterpriseSecurityFinding>,
    pub compliance_reviews: Vec<ComplianceReviewResult>,
    pub load_chaos_result: LoadChaosAcceptanceResult,
    pub supported_runner_versions: Vec<SupportedRunnerVersionResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseScenarioResult {
    pub id: String,
    pub passed: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityFindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityFindingStatus {
    Open,
    Mitigated,
    Accepted,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseSecurityFinding {
    pub id: String,
    pub severity: SecurityFindingSeverity,
    pub status: SecurityFindingStatus,
    pub owner: Option<String>,
    pub mitigation: Option<String>,
    pub target_date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReviewResult {
    pub id: String,
    pub passed: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReviewResult {
    pub id: String,
    pub reviewed: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadChaosAcceptanceResult {
    pub passed: bool,
    pub max_concurrent_runners: u32,
    pub reconnect_recovery_p95_ms: u64,
    pub transport_fallback_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedRunnerVersionResult {
    pub version: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAcceptanceDecision {
    pub allowed: bool,
    pub blockers: Vec<String>,
    pub thresholds: EnterpriseReleaseBlockingThresholds,
}

pub fn official_enterprise_acceptance_plan() -> EnterpriseAcceptancePlan {
    EnterpriseAcceptancePlan {
        schema_version: ENTERPRISE_ACCEPTANCE_PLAN_SCHEMA_VERSION.to_string(),
        checklist: official_acceptance_checks(),
        security_review_scope: official_security_review_scope(),
        compliance_package: official_compliance_package(),
        release_blocking_thresholds: official_enterprise_release_blocking_thresholds(),
    }
}

pub fn validate_enterprise_acceptance_plan(plan: &EnterpriseAcceptancePlan) -> CoreResult<()> {
    if plan.schema_version != ENTERPRISE_ACCEPTANCE_PLAN_SCHEMA_VERSION {
        return Err(CoreError::new(
            "ENTERPRISE_ACCEPTANCE_PLAN_SCHEMA_INVALID",
            "enterprise acceptance plan schema_version is not supported",
        ));
    }
    validate_required_ids(
        "acceptance check",
        "ENTERPRISE_ACCEPTANCE_CHECK_UNKNOWN",
        "ENTERPRISE_ACCEPTANCE_CHECK_DUPLICATE",
        "ENTERPRISE_ACCEPTANCE_CHECK_MISSING",
        &required_acceptance_check_ids(),
        plan.checklist.iter().map(|check| check.id.as_str()),
    )?;
    validate_required_ids(
        "security review scope",
        "ENTERPRISE_SECURITY_SCOPE_UNKNOWN",
        "ENTERPRISE_SECURITY_SCOPE_DUPLICATE",
        "ENTERPRISE_SECURITY_SCOPE_MISSING",
        &required_security_scope_ids(),
        plan.security_review_scope
            .iter()
            .map(|item| item.id.as_str()),
    )?;
    validate_required_ids(
        "compliance package item",
        "ENTERPRISE_COMPLIANCE_ITEM_UNKNOWN",
        "ENTERPRISE_COMPLIANCE_ITEM_DUPLICATE",
        "ENTERPRISE_COMPLIANCE_ITEM_MISSING",
        &required_compliance_item_ids(),
        plan.compliance_package.iter().map(|item| item.id.as_str()),
    )?;
    Ok(())
}

pub fn evaluate_enterprise_acceptance_report(
    report: &EnterpriseAcceptanceReport,
) -> CoreResult<EnterpriseAcceptanceDecision> {
    if report.schema_version != ENTERPRISE_ACCEPTANCE_REPORT_SCHEMA_VERSION {
        return Err(CoreError::new(
            "ENTERPRISE_ACCEPTANCE_REPORT_SCHEMA_INVALID",
            "enterprise acceptance report schema_version is not supported",
        ));
    }

    validate_required_ids(
        "scenario result",
        "ENTERPRISE_ACCEPTANCE_SCENARIO_UNKNOWN",
        "ENTERPRISE_ACCEPTANCE_SCENARIO_DUPLICATE",
        "ENTERPRISE_ACCEPTANCE_SCENARIO_MISSING",
        &required_acceptance_check_ids(),
        report
            .scenario_results
            .iter()
            .map(|result| result.id.as_str()),
    )?;
    validate_required_ids(
        "compliance review",
        "ENTERPRISE_COMPLIANCE_REVIEW_UNKNOWN",
        "ENTERPRISE_COMPLIANCE_REVIEW_DUPLICATE",
        "ENTERPRISE_COMPLIANCE_REVIEW_MISSING",
        &required_compliance_item_ids(),
        report
            .compliance_reviews
            .iter()
            .map(|review| review.id.as_str()),
    )?;
    validate_required_ids(
        "security review result",
        "ENTERPRISE_SECURITY_REVIEW_UNKNOWN",
        "ENTERPRISE_SECURITY_REVIEW_DUPLICATE",
        "ENTERPRISE_SECURITY_REVIEW_MISSING",
        &required_security_scope_ids(),
        report
            .security_review_results
            .iter()
            .map(|result| result.id.as_str()),
    )?;
    validate_report_evidence(
        "scenario evidence",
        "ENTERPRISE_ACCEPTANCE_EVIDENCE_UNKNOWN",
        "ENTERPRISE_ACCEPTANCE_EVIDENCE_DUPLICATE",
        "ENTERPRISE_ACCEPTANCE_EVIDENCE_MISSING",
        official_acceptance_checks()
            .into_iter()
            .map(|check| (check.id, check.evidence_required)),
        report
            .scenario_results
            .iter()
            .map(|result| (result.id.as_str(), result.evidence.as_slice())),
    )?;
    validate_report_evidence(
        "security review evidence",
        "ENTERPRISE_SECURITY_REVIEW_EVIDENCE_UNKNOWN",
        "ENTERPRISE_SECURITY_REVIEW_EVIDENCE_DUPLICATE",
        "ENTERPRISE_SECURITY_REVIEW_EVIDENCE_MISSING",
        official_security_review_scope()
            .into_iter()
            .map(|scope| (scope.id, scope.required_tests)),
        report
            .security_review_results
            .iter()
            .map(|result| (result.id.as_str(), result.evidence.as_slice())),
    )?;
    validate_report_evidence(
        "compliance evidence",
        "ENTERPRISE_COMPLIANCE_EVIDENCE_UNKNOWN",
        "ENTERPRISE_COMPLIANCE_EVIDENCE_DUPLICATE",
        "ENTERPRISE_COMPLIANCE_EVIDENCE_MISSING",
        official_compliance_package()
            .into_iter()
            .map(|item| (item.id, item.required_evidence)),
        report
            .compliance_reviews
            .iter()
            .map(|review| (review.id.as_str(), review.evidence.as_slice())),
    )?;

    let thresholds = official_enterprise_release_blocking_thresholds();
    let mut blockers = Vec::new();

    for result in &report.scenario_results {
        if !result.passed {
            blockers.push(format!(
                "enterprise acceptance scenario failed: {}",
                result.id
            ));
        }
    }

    for result in &report.security_review_results {
        if !result.passed {
            blockers.push(format!("security review scope failed: {}", result.id));
        }
    }

    let open_critical_high = report
        .security_findings
        .iter()
        .filter(|finding| {
            finding.status == SecurityFindingStatus::Open
                && matches!(
                    finding.severity,
                    SecurityFindingSeverity::Critical | SecurityFindingSeverity::High
                )
        })
        .count() as u32;
    if open_critical_high > thresholds.max_open_critical_high_security_findings {
        blockers.push(format!(
            "open critical/high security findings: {open_critical_high}"
        ));
    }

    for finding in &report.security_findings {
        if finding.status == SecurityFindingStatus::Open
            && finding.severity == SecurityFindingSeverity::Medium
            && thresholds.medium_findings_require_mitigation_owner_and_date
            && (finding
                .owner
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
                || finding
                    .mitigation
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                || finding
                    .target_date
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty())
        {
            blockers.push(format!(
                "medium security finding lacks mitigation/owner/date: {}",
                finding.id
            ));
        }
    }

    for review in &report.compliance_reviews {
        if !review.reviewed {
            blockers.push(format!(
                "compliance package item not reviewed: {}",
                review.id
            ));
        }
    }

    if !report.load_chaos_result.passed {
        blockers.push("load/chaos acceptance did not pass".to_string());
    }
    if report.load_chaos_result.reconnect_recovery_p95_ms > 30_000 {
        blockers.push("load/chaos reconnect recovery p95 exceeds 30s".to_string());
    }
    if !report.load_chaos_result.transport_fallback_verified {
        blockers.push("load/chaos transport fallback was not verified".to_string());
    }
    if report.supported_runner_versions.is_empty() {
        blockers.push("supported runner version compatibility is missing".to_string());
    }
    for version in &report.supported_runner_versions {
        if !version.passed {
            blockers.push(format!(
                "supported runner version compatibility failed: {}",
                version.version
            ));
        }
    }

    Ok(EnterpriseAcceptanceDecision {
        allowed: blockers.is_empty(),
        blockers,
        thresholds,
    })
}

pub fn official_acceptance_checks() -> Vec<EnterpriseAcceptanceCheck> {
    vec![
        check(
            "install",
            "Install runner",
            ["installer_log", "binary_version"],
        ),
        check("login", "Login runner", ["auth_event", "selected_org"]),
        check(
            "bind",
            "Bind project workspace",
            ["binding_id", "workspace_path"],
        ),
        check(
            "policy_enforce",
            "Policy enforcement",
            ["deny_case", "ask_case", "allow_case"],
        ),
        check(
            "approval",
            "Approval flow",
            ["approval_request", "decision_event"],
        ),
        check(
            "local_ai_workflow",
            "Local AI workflow",
            ["workflow_run_id", "local_tool_trace"],
        ),
        check(
            "playwright_local_http_db",
            "Playwright, local HTTP, and DB capability test",
            ["browser_result", "http_result", "db_result"],
        ),
        check(
            "audit_export",
            "Audit export",
            ["json_export", "csv_export", "redaction_sample"],
        ),
        check(
            "support_bundle",
            "Support bundle",
            ["bundle_manifest", "redaction_sample"],
        ),
        check(
            "update_rollback",
            "Update and rollback",
            ["signed_manifest", "rollback_decision"],
        ),
        check(
            "full_enterprise_acceptance",
            "Full enterprise acceptance on clean organization",
            ["clean_org_id", "suite_report"],
        ),
        check(
            "policy_bypass_attempts",
            "Policy bypass attempts",
            ["attempt_matrix", "denied_actions"],
        ),
        check(
            "workspace_escape_attempts",
            "Workspace escape attempts",
            ["escape_matrix", "blocked_paths"],
        ),
        check(
            "secret_leakage_scan",
            "Secret leakage scan",
            ["scan_report", "zero_leaks"],
        ),
        check(
            "update_tamper_test",
            "Update chain tamper test",
            ["tampered_manifest_rejected", "tampered_artifact_rejected"],
        ),
        check(
            "audit_export_completeness",
            "Audit export completeness",
            ["required_fields", "filter_coverage"],
        ),
        check(
            "retention_legal_hold",
            "Retention and legal hold",
            ["retention_policy", "legal_hold_case"],
        ),
        check(
            "data_classification_review",
            "Data classification review",
            ["classification_matrix", "customer_package_link"],
        ),
    ]
}

pub fn official_security_review_scope() -> Vec<SecurityReviewScopeItem> {
    vec![
        scope("runner_auth", "Runner auth", ["token_expiry", "revocation"]),
        scope("protocol", "Protocol", ["replay", "ordering", "fallback"]),
        scope(
            "policy_bypass",
            "Policy bypass",
            ["capability_mismatch", "path_spoofing"],
        ),
        scope(
            "workspace_sandbox",
            "Workspace sandbox",
            ["path_traversal", "symlink_escape"],
        ),
        scope(
            "artifact_leakage",
            "Artifact leakage",
            ["metadata_redaction", "content_policy"],
        ),
        scope(
            "update_chain",
            "Update chain",
            ["manifest_signature", "artifact_signature"],
        ),
    ]
}

pub fn official_compliance_package() -> Vec<CompliancePackageItem> {
    vec![
        compliance("data_flow", "Data flow", ["diagram", "processor_notes"]),
        compliance("retention", "Retention", ["defaults", "tenant_overrides"]),
        compliance("audit_fields", "Audit fields", ["schema", "sample_export"]),
        compliance(
            "admin_controls",
            "Admin controls",
            ["managed_policy", "fleet_controls"],
        ),
        compliance("security_faq", "Security FAQ", ["customer_faq"]),
        compliance(
            "data_classification",
            "Data classification",
            ["classification_table"],
        ),
        compliance(
            "legal_hold_behavior",
            "Legal hold behavior",
            ["hold_case", "release_case"],
        ),
    ]
}

pub fn official_enterprise_release_blocking_thresholds() -> EnterpriseReleaseBlockingThresholds {
    EnterpriseReleaseBlockingThresholds {
        max_open_critical_high_security_findings: 0,
        medium_findings_require_mitigation_owner_and_date: true,
        update_chain_tamper_test_must_pass: true,
        workspace_escape_tests_must_pass: true,
        secret_leakage_scan_must_pass: true,
        policy_bypass_tests_must_pass: true,
        retention_legal_hold_must_be_documented: true,
    }
}

fn required_acceptance_check_ids() -> BTreeSet<String> {
    official_acceptance_checks()
        .into_iter()
        .map(|check| check.id)
        .collect()
}

fn required_security_scope_ids() -> BTreeSet<String> {
    official_security_review_scope()
        .into_iter()
        .map(|scope| scope.id)
        .collect()
}

fn required_compliance_item_ids() -> BTreeSet<String> {
    official_compliance_package()
        .into_iter()
        .map(|item| item.id)
        .collect()
}

fn validate_required_ids<'a>(
    label: &str,
    unknown_code: &'static str,
    duplicate_code: &'static str,
    missing_code: &'static str,
    required: &BTreeSet<String>,
    ids: impl IntoIterator<Item = &'a str>,
) -> CoreResult<BTreeSet<String>> {
    let mut observed = BTreeSet::new();
    for id in ids {
        if !required.contains(id) {
            return Err(CoreError::new(
                unknown_code,
                format!("unknown {label}: {id}"),
            ));
        }
        if !observed.insert(id.to_string()) {
            return Err(CoreError::new(
                duplicate_code,
                format!("duplicate {label}: {id}"),
            ));
        }
    }
    for id in required {
        if !observed.contains(id) {
            return Err(CoreError::new(
                missing_code,
                format!("missing required {label}: {id}"),
            ));
        }
    }
    Ok(observed)
}

fn validate_report_evidence<'a>(
    label: &str,
    unknown_code: &'static str,
    duplicate_code: &'static str,
    missing_code: &'static str,
    required_by_id: impl IntoIterator<Item = (String, Vec<String>)>,
    observed_by_id: impl IntoIterator<Item = (&'a str, &'a [String])>,
) -> CoreResult<()> {
    let required_by_id = required_by_id
        .into_iter()
        .map(|(id, evidence)| (id, evidence.into_iter().collect::<BTreeSet<_>>()))
        .collect::<std::collections::BTreeMap<_, _>>();

    for (id, observed_values) in observed_by_id {
        let required = required_by_id.get(id).ok_or_else(|| {
            CoreError::new(unknown_code, format!("unknown {label} parent id: {id}"))
        })?;
        let mut observed = BTreeSet::new();
        for value in observed_values {
            if !required.contains(value) {
                return Err(CoreError::new(
                    unknown_code,
                    format!("unknown {label}: {id}.{value}"),
                ));
            }
            if !observed.insert(value.as_str()) {
                return Err(CoreError::new(
                    duplicate_code,
                    format!("duplicate {label}: {id}.{value}"),
                ));
            }
        }
        for required_value in required {
            if !observed.contains(required_value.as_str()) {
                return Err(CoreError::new(
                    missing_code,
                    format!("missing required {label}: {id}.{required_value}"),
                ));
            }
        }
    }
    Ok(())
}

fn check<const N: usize>(
    id: &str,
    title: &str,
    evidence_required: [&str; N],
) -> EnterpriseAcceptanceCheck {
    EnterpriseAcceptanceCheck {
        id: id.to_string(),
        title: title.to_string(),
        evidence_required: evidence_required.into_iter().map(str::to_string).collect(),
    }
}

fn scope<const N: usize>(
    id: &str,
    title: &str,
    required_tests: [&str; N],
) -> SecurityReviewScopeItem {
    SecurityReviewScopeItem {
        id: id.to_string(),
        title: title.to_string(),
        required_tests: required_tests.into_iter().map(str::to_string).collect(),
    }
}

fn compliance<const N: usize>(
    id: &str,
    title: &str,
    required_evidence: [&str; N],
) -> CompliancePackageItem {
    CompliancePackageItem {
        id: id.to_string(),
        title: title.to_string(),
        required_evidence: required_evidence.into_iter().map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_plan_covers_acceptance_security_and_compliance_scope() {
        let plan = official_enterprise_acceptance_plan();

        validate_enterprise_acceptance_plan(&plan).unwrap();
        assert!(plan
            .checklist
            .iter()
            .any(|check| check.id == "full_enterprise_acceptance"));
        assert!(plan
            .checklist
            .iter()
            .any(|check| check.id == "playwright_local_http_db"));
        assert!(plan
            .security_review_scope
            .iter()
            .any(|scope| scope.id == "policy_bypass"));
        assert!(plan
            .compliance_package
            .iter()
            .any(|item| item.id == "legal_hold_behavior"));
        assert_eq!(
            0,
            plan.release_blocking_thresholds
                .max_open_critical_high_security_findings
        );
    }

    #[test]
    fn complete_enterprise_acceptance_report_passes() {
        let decision = evaluate_enterprise_acceptance_report(&complete_report()).unwrap();

        assert!(decision.allowed);
        assert!(decision.blockers.is_empty());
    }

    #[test]
    fn report_rejects_missing_duplicate_and_unknown_scenarios() {
        let mut missing = complete_report();
        missing.scenario_results.pop();
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_SCENARIO_MISSING",
            evaluate_enterprise_acceptance_report(&missing)
                .unwrap_err()
                .code
        );

        let mut duplicate = complete_report();
        duplicate
            .scenario_results
            .push(duplicate.scenario_results[0].clone());
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_SCENARIO_DUPLICATE",
            evaluate_enterprise_acceptance_report(&duplicate)
                .unwrap_err()
                .code
        );

        let mut unknown = complete_report();
        unknown.scenario_results[0].id = "unknown".to_string();
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_SCENARIO_UNKNOWN",
            evaluate_enterprise_acceptance_report(&unknown)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn report_rejects_incomplete_or_invalid_scenario_evidence() {
        let mut missing = complete_report();
        missing
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "install")
            .unwrap()
            .evidence = vec!["installer_log".to_string()];
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_EVIDENCE_MISSING",
            evaluate_enterprise_acceptance_report(&missing)
                .unwrap_err()
                .code
        );

        let mut duplicate = complete_report();
        duplicate
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "install")
            .unwrap()
            .evidence = vec![
            "installer_log".to_string(),
            "binary_version".to_string(),
            "binary_version".to_string(),
        ];
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_EVIDENCE_DUPLICATE",
            evaluate_enterprise_acceptance_report(&duplicate)
                .unwrap_err()
                .code
        );

        let mut unknown = complete_report();
        unknown
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "install")
            .unwrap()
            .evidence
            .push("generic_evidence".to_string());
        assert_eq!(
            "ENTERPRISE_ACCEPTANCE_EVIDENCE_UNKNOWN",
            evaluate_enterprise_acceptance_report(&unknown)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn report_rejects_missing_security_scope_evidence() {
        let mut missing_scope = complete_report();
        missing_scope.security_review_results.pop();
        assert_eq!(
            "ENTERPRISE_SECURITY_REVIEW_MISSING",
            evaluate_enterprise_acceptance_report(&missing_scope)
                .unwrap_err()
                .code
        );

        let mut incomplete = complete_report();
        incomplete
            .security_review_results
            .iter_mut()
            .find(|result| result.id == "runner_auth")
            .unwrap()
            .evidence = vec!["token_expiry".to_string()];
        assert_eq!(
            "ENTERPRISE_SECURITY_REVIEW_EVIDENCE_MISSING",
            evaluate_enterprise_acceptance_report(&incomplete)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn report_rejects_incomplete_compliance_evidence() {
        let mut report = complete_report();
        report
            .compliance_reviews
            .iter_mut()
            .find(|review| review.id == "data_flow")
            .unwrap()
            .evidence = vec!["diagram".to_string()];

        assert_eq!(
            "ENTERPRISE_COMPLIANCE_EVIDENCE_MISSING",
            evaluate_enterprise_acceptance_report(&report)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn security_findings_and_required_security_tests_block_signoff() {
        let mut report = complete_report();
        report.security_findings.push(EnterpriseSecurityFinding {
            id: "finding-1".to_string(),
            severity: SecurityFindingSeverity::High,
            status: SecurityFindingStatus::Open,
            owner: None,
            mitigation: None,
            target_date: None,
        });
        report
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "policy_bypass_attempts")
            .unwrap()
            .passed = false;
        report
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "workspace_escape_attempts")
            .unwrap()
            .passed = false;
        report
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "secret_leakage_scan")
            .unwrap()
            .passed = false;
        report
            .scenario_results
            .iter_mut()
            .find(|result| result.id == "update_tamper_test")
            .unwrap()
            .passed = false;

        let decision = evaluate_enterprise_acceptance_report(&report).unwrap();

        assert!(!decision.allowed);
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("open critical/high")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("policy_bypass_attempts")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("workspace_escape_attempts")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("secret_leakage_scan")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("update_tamper_test")));
    }

    #[test]
    fn medium_findings_require_documented_mitigation_owner_and_date() {
        let mut report = complete_report();
        report.security_findings.push(EnterpriseSecurityFinding {
            id: "finding-medium".to_string(),
            severity: SecurityFindingSeverity::Medium,
            status: SecurityFindingStatus::Open,
            owner: Some("security".to_string()),
            mitigation: None,
            target_date: Some("2026-07-15".to_string()),
        });

        let decision = evaluate_enterprise_acceptance_report(&report).unwrap();

        assert!(!decision.allowed);
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("medium security finding")));
    }

    #[test]
    fn compliance_load_compatibility_and_evidence_are_release_blocking() {
        let mut report = complete_report();
        report
            .compliance_reviews
            .iter_mut()
            .find(|review| review.id == "legal_hold_behavior")
            .unwrap()
            .reviewed = false;
        report
            .security_review_results
            .iter_mut()
            .find(|result| result.id == "protocol")
            .unwrap()
            .passed = false;
        report.load_chaos_result.passed = false;
        report.load_chaos_result.reconnect_recovery_p95_ms = 31_000;
        report.load_chaos_result.transport_fallback_verified = false;
        report.supported_runner_versions[0].passed = false;

        let decision = evaluate_enterprise_acceptance_report(&report).unwrap();

        assert!(!decision.allowed);
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("legal_hold_behavior")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("protocol")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("load/chaos")));
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("compatibility failed")));
    }

    fn complete_report() -> EnterpriseAcceptanceReport {
        EnterpriseAcceptanceReport {
            schema_version: ENTERPRISE_ACCEPTANCE_REPORT_SCHEMA_VERSION.to_string(),
            scenario_results: official_acceptance_checks()
                .into_iter()
                .map(|check| EnterpriseScenarioResult {
                    id: check.id,
                    passed: true,
                    evidence: check.evidence_required,
                })
                .collect(),
            security_review_results: official_security_review_scope()
                .into_iter()
                .map(|scope| SecurityReviewResult {
                    id: scope.id,
                    passed: true,
                    evidence: scope.required_tests,
                })
                .collect(),
            security_findings: vec![EnterpriseSecurityFinding {
                id: "finding-medium-documented".to_string(),
                severity: SecurityFindingSeverity::Medium,
                status: SecurityFindingStatus::Open,
                owner: Some("security".to_string()),
                mitigation: Some("documented compensating control".to_string()),
                target_date: Some("2026-07-15".to_string()),
            }],
            compliance_reviews: official_compliance_package()
                .into_iter()
                .map(|item| ComplianceReviewResult {
                    id: item.id,
                    reviewed: true,
                    evidence: item.required_evidence,
                })
                .collect(),
            load_chaos_result: LoadChaosAcceptanceResult {
                passed: true,
                max_concurrent_runners: 10_000,
                reconnect_recovery_p95_ms: 20_000,
                transport_fallback_verified: true,
            },
            supported_runner_versions: vec![SupportedRunnerVersionResult {
                version: "1.0.0".to_string(),
                passed: true,
            }],
        }
    }
}
