use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

pub const OPERATIONAL_READINESS_PLAN_SCHEMA_VERSION: &str =
    "loomex.runner.operationalReadinessPlan/v1";
pub const OPERATIONAL_READINESS_REPORT_SCHEMA_VERSION: &str =
    "loomex.runner.operationalReadinessReport/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalMetric {
    pub name: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
    pub timestamp_epoch_ms: u64,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct OperationalMetricsRecorder {
    metrics: Vec<OperationalMetric>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloKind {
    SuccessRatio,
    LatencyP95,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SloDefinition {
    pub id: String,
    pub description: String,
    pub kind: SloKind,
    pub target_percent: Option<f64>,
    pub max_p95_ms: Option<u64>,
    pub window_days: u32,
    pub metric: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SloObservation {
    pub slo_id: String,
    pub total: u64,
    pub good: u64,
    pub samples_ms: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SloResult {
    pub slo_id: String,
    pub passed: bool,
    pub observed_percent: Option<f64>,
    pub observed_p95_ms: Option<u64>,
    pub error_budget_burn_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBudgetBurn {
    pub slo_id: String,
    #[serde(rename = "burnPercent7d")]
    pub burn_percent_7d: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardQuery {
    pub id: String,
    pub title: String,
    pub query: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRule {
    pub id: String,
    pub description: String,
    pub metric: String,
    pub threshold: f64,
    pub window_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalAlert {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Runbook {
    pub id: String,
    pub title: String,
    pub trigger: String,
    pub drill_steps: Vec<String>,
    pub success_criteria: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunbookDrillResult {
    pub runbook_id: String,
    pub passed: bool,
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityPlan {
    pub expected_runner_connections: u64,
    pub max_streams_per_pod: u64,
    pub recommended_pods: u64,
    pub reconnect_storm_multiplier: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalReadinessPlan {
    pub schema_version: String,
    pub slos: Vec<SloDefinition>,
    pub required_metrics: Vec<String>,
    pub dashboards: Vec<DashboardQuery>,
    pub alerts: Vec<AlertRule>,
    pub runbooks: Vec<Runbook>,
    pub capacity_plan: CapacityPlan,
    pub error_budget_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalReadinessReport {
    pub schema_version: String,
    pub slo_results: Vec<SloResult>,
    pub error_budget_burn: Vec<ErrorBudgetBurn>,
    pub open_critical_or_high_security_findings: u32,
    pub update_chain_tamper_test_passed: bool,
    pub workspace_escape_tests_passed: bool,
    pub secret_leakage_scan_passed: bool,
    pub policy_bypass_tests_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseGateDecision {
    pub allowed: bool,
    pub blockers: Vec<String>,
    pub alerts: Vec<OperationalAlert>,
}

impl OperationalMetricsRecorder {
    pub fn record_runner_connected(&mut self, transport: &str, timestamp_epoch_ms: u64) {
        self.push(
            "runner_stream_connect_total",
            1.0,
            timestamp_epoch_ms,
            [("result", "success"), ("transport", transport)],
        );
        self.push("runner_active_total", 1.0, timestamp_epoch_ms, []);
    }

    pub fn record_runner_disconnected(&mut self, reason: &str, timestamp_epoch_ms: u64) {
        self.push(
            "runner_disconnected_total",
            1.0,
            timestamp_epoch_ms,
            [("reason", reason)],
        );
    }

    pub fn record_tool_call(
        &mut self,
        capability: &str,
        success: bool,
        latency_ms: u64,
        timestamp_epoch_ms: u64,
    ) {
        self.push(
            "local_tool_call_total",
            1.0,
            timestamp_epoch_ms,
            [
                ("capability", capability),
                ("result", if success { "success" } else { "failure" }),
            ],
        );
        self.push(
            "workflow_local_dispatch_latency_ms",
            latency_ms as f64,
            timestamp_epoch_ms,
            [("capability", capability)],
        );
    }

    pub fn record_stream_failure(&mut self, transport: &str, timestamp_epoch_ms: u64) {
        self.push(
            "runner_stream_connect_total",
            1.0,
            timestamp_epoch_ms,
            [("result", "failure"), ("transport", transport)],
        );
    }

    pub fn record_policy_deny(&mut self, capability: &str, timestamp_epoch_ms: u64) {
        self.push(
            "policy_denied_total",
            1.0,
            timestamp_epoch_ms,
            [("capability", capability)],
        );
    }

    pub fn record_approval_timeout(&mut self, timestamp_epoch_ms: u64) {
        self.push("approval_timeout_total", 1.0, timestamp_epoch_ms, []);
    }

    pub fn record_transport_fallback(&mut self, timestamp_epoch_ms: u64) {
        self.push("transport_fallback_total", 1.0, timestamp_epoch_ms, []);
    }

    pub fn record_trace_upload(&mut self, success: bool, timestamp_epoch_ms: u64) {
        self.push(
            "trace_upload_total",
            1.0,
            timestamp_epoch_ms,
            [("result", if success { "success" } else { "failure" })],
        );
    }

    pub fn metrics(&self) -> &[OperationalMetric] {
        &self.metrics
    }

    fn push<const N: usize>(
        &mut self,
        name: &str,
        value: f64,
        timestamp_epoch_ms: u64,
        labels: [(&str, &str); N],
    ) {
        self.metrics.push(OperationalMetric {
            name: name.to_string(),
            value,
            labels: labels
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            timestamp_epoch_ms,
        });
    }
}

pub fn official_operational_readiness_plan(
    expected_runner_connections: u64,
) -> OperationalReadinessPlan {
    OperationalReadinessPlan {
        schema_version: OPERATIONAL_READINESS_PLAN_SCHEMA_VERSION.to_string(),
        slos: official_slos(),
        required_metrics: vec![
            "runner_active_total".to_string(),
            "runner_disconnected_total".to_string(),
            "local_tool_call_total".to_string(),
            "policy_denied_total".to_string(),
            "approval_timeout_total".to_string(),
            "transport_fallback_total".to_string(),
            "trace_upload_total".to_string(),
            "run_validation_api_total".to_string(),
        ],
        dashboards: official_dashboard_queries(),
        alerts: official_alert_rules(),
        runbooks: official_runbooks(),
        capacity_plan: capacity_plan_for_runner_connections(expected_runner_connections, 2_000),
        error_budget_rules: vec![
            "burn > 50% monthly budget in 7 days blocks risky rollout".to_string(),
            "security regression blocks release regardless of SLO".to_string(),
            "trace upload SLO breach blocks enterprise release promotion".to_string(),
        ],
    }
}

pub fn validate_operational_readiness_plan(plan: &OperationalReadinessPlan) -> CoreResult<()> {
    if plan.schema_version != OPERATIONAL_READINESS_PLAN_SCHEMA_VERSION {
        return Err(CoreError::new(
            "OPERATIONAL_READINESS_SCHEMA_INVALID",
            "operational readiness plan schema_version is not supported",
        ));
    }
    let required_slos = BTreeSet::from([
        "runner_stream_connect_success",
        "workflow_local_dispatch_latency_p95",
        "stream_reconnect_recovery_p95",
        "approval_delivery_latency_p95",
        "trace_upload_success",
        "run_validation_api_availability",
    ]);
    let observed_slos = plan
        .slos
        .iter()
        .map(|slo| slo.id.as_str())
        .collect::<BTreeSet<_>>();
    if !required_slos.is_subset(&observed_slos) {
        return Err(CoreError::new(
            "OPERATIONAL_READINESS_SLOS_INCOMPLETE",
            "all enterprise runner SLOs must be present",
        ));
    }
    for metric in [
        "runner_active_total",
        "runner_disconnected_total",
        "local_tool_call_total",
        "policy_denied_total",
        "approval_timeout_total",
        "transport_fallback_total",
    ] {
        if !plan.required_metrics.iter().any(|item| item == metric) {
            return Err(CoreError::new(
                "OPERATIONAL_READINESS_METRICS_INCOMPLETE",
                format!("required metric missing: {metric}"),
            ));
        }
    }
    if plan.dashboards.is_empty() || plan.alerts.is_empty() || plan.runbooks.len() < 6 {
        return Err(CoreError::new(
            "OPERATIONAL_READINESS_OPERATIONS_INCOMPLETE",
            "dashboards, alerts, and runbooks are required",
        ));
    }
    Ok(())
}

pub fn official_slos() -> Vec<SloDefinition> {
    vec![
        success_slo(
            "runner_stream_connect_success",
            "runner stream connect success",
            99.5,
            "runner_stream_connect_total",
        ),
        latency_slo(
            "workflow_local_dispatch_latency_p95",
            "workflow local dispatch latency p95",
            2_000,
            "workflow_local_dispatch_latency_ms",
        ),
        latency_slo(
            "stream_reconnect_recovery_p95",
            "stream reconnect recovery p95",
            30_000,
            "stream_reconnect_recovery_ms",
        ),
        latency_slo(
            "approval_delivery_latency_p95",
            "approval delivery latency p95",
            3_000,
            "approval_delivery_latency_ms",
        ),
        success_slo(
            "trace_upload_success",
            "trace upload success",
            99.9,
            "trace_upload_total",
        ),
        success_slo(
            "run_validation_api_availability",
            "run validation API availability",
            99.9,
            "run_validation_api_total",
        ),
    ]
}

pub fn evaluate_slo(
    definition: &SloDefinition,
    observation: &SloObservation,
) -> CoreResult<SloResult> {
    if observation.slo_id != definition.id {
        return Err(CoreError::new(
            "SLO_OBSERVATION_MISMATCH",
            "SLO observation id does not match definition",
        ));
    }
    match definition.kind {
        SloKind::SuccessRatio => {
            if observation.total == 0 {
                return Err(CoreError::new(
                    "SLO_OBSERVATION_EMPTY",
                    "SLO observation total must be greater than zero",
                ));
            }
            let observed = (observation.good as f64 / observation.total as f64) * 100.0;
            let target = definition.target_percent.unwrap_or(100.0);
            let budget = (100.0 - target).max(0.0001);
            let bad_percent = 100.0 - observed;
            Ok(SloResult {
                slo_id: definition.id.clone(),
                passed: observed >= target,
                observed_percent: Some(round2(observed)),
                observed_p95_ms: None,
                error_budget_burn_percent: round2((bad_percent / budget) * 100.0),
            })
        }
        SloKind::LatencyP95 => {
            let p95 = percentile_ceil(&observation.samples_ms, 95).ok_or_else(|| {
                CoreError::new("SLO_OBSERVATION_EMPTY", "latency SLO requires samples")
            })?;
            let max_p95 = definition.max_p95_ms.unwrap_or(u64::MAX);
            Ok(SloResult {
                slo_id: definition.id.clone(),
                passed: p95 <= max_p95,
                observed_percent: None,
                observed_p95_ms: Some(p95),
                error_budget_burn_percent: if p95 <= max_p95 { 0.0 } else { 100.0 },
            })
        }
    }
}

pub fn evaluate_operational_alerts(metrics: &[OperationalMetric]) -> Vec<OperationalAlert> {
    let stream_failures = metrics
        .iter()
        .filter(|metric| {
            metric.name == "runner_stream_connect_total"
                && metric
                    .labels
                    .get("result")
                    .is_some_and(|value| value == "failure")
        })
        .count();
    let mut alerts = Vec::new();
    if stream_failures >= 5 {
        alerts.push(OperationalAlert {
            rule_id: "stream_failure_threshold".to_string(),
            severity: "page".to_string(),
            message: "Runner stream failures exceeded threshold".to_string(),
        });
    }
    alerts
}

pub fn evaluate_release_gate(
    report: &OperationalReadinessReport,
) -> CoreResult<ReleaseGateDecision> {
    if report.schema_version != OPERATIONAL_READINESS_REPORT_SCHEMA_VERSION {
        return Err(CoreError::new(
            "OPERATIONAL_READINESS_REPORT_SCHEMA_INVALID",
            "operational readiness report schema_version is not supported",
        ));
    }
    validate_release_gate_report_coverage(report)?;
    let mut blockers = Vec::new();
    let mut alerts = Vec::new();
    for result in &report.slo_results {
        if !result.passed {
            blockers.push(format!("SLO failed: {}", result.slo_id));
        }
    }
    for burn in &report.error_budget_burn {
        if burn.burn_percent_7d > 50.0 {
            blockers.push(format!("error budget burn over 50%: {}", burn.slo_id));
            alerts.push(OperationalAlert {
                rule_id: "error_budget_burn_7d".to_string(),
                severity: "blocker".to_string(),
                message: format!(
                    "{} burned {:.1}% of monthly budget in 7 days",
                    burn.slo_id, burn.burn_percent_7d
                ),
            });
        }
    }
    if report.open_critical_or_high_security_findings > 0 {
        blockers.push("critical/high security findings are open".to_string());
    }
    for (passed, label) in [
        (
            report.update_chain_tamper_test_passed,
            "update chain tamper test",
        ),
        (
            report.workspace_escape_tests_passed,
            "workspace escape tests",
        ),
        (report.secret_leakage_scan_passed, "secret leakage scan"),
        (report.policy_bypass_tests_passed, "policy bypass tests"),
    ] {
        if !passed {
            blockers.push(format!("{label} did not pass"));
        }
    }
    Ok(ReleaseGateDecision {
        allowed: blockers.is_empty(),
        blockers,
        alerts,
    })
}

fn validate_release_gate_report_coverage(report: &OperationalReadinessReport) -> CoreResult<()> {
    let required_slos = official_slos()
        .into_iter()
        .map(|slo| slo.id)
        .collect::<BTreeSet<_>>();
    let slo_ids = validate_report_ids(
        "SLO result",
        "OPERATIONAL_READINESS_REPORT_SLO_UNKNOWN",
        "OPERATIONAL_READINESS_REPORT_SLO_DUPLICATE",
        &required_slos,
        report
            .slo_results
            .iter()
            .map(|result| result.slo_id.as_str()),
    )?;
    let burn_ids = validate_report_ids(
        "error budget burn",
        "OPERATIONAL_READINESS_REPORT_ERROR_BUDGET_UNKNOWN",
        "OPERATIONAL_READINESS_REPORT_ERROR_BUDGET_DUPLICATE",
        &required_slos,
        report
            .error_budget_burn
            .iter()
            .map(|burn| burn.slo_id.as_str()),
    )?;

    for required in &required_slos {
        if !slo_ids.contains(required) {
            return Err(CoreError::new(
                "OPERATIONAL_READINESS_REPORT_SLO_MISSING",
                format!("missing required SLO result: {required}"),
            ));
        }
        if !burn_ids.contains(required) {
            return Err(CoreError::new(
                "OPERATIONAL_READINESS_REPORT_ERROR_BUDGET_MISSING",
                format!("missing required error budget burn data: {required}"),
            ));
        }
    }
    Ok(())
}

fn validate_report_ids<'a>(
    label: &str,
    unknown_code: &'static str,
    duplicate_code: &'static str,
    required_slos: &BTreeSet<String>,
    ids: impl IntoIterator<Item = &'a str>,
) -> CoreResult<BTreeSet<String>> {
    let mut observed = BTreeSet::new();
    for id in ids {
        if !required_slos.contains(id) {
            return Err(CoreError::new(
                unknown_code,
                format!("unknown {label} id: {id}"),
            ));
        }
        if !observed.insert(id.to_string()) {
            return Err(CoreError::new(
                duplicate_code,
                format!("duplicate {label} id: {id}"),
            ));
        }
    }
    Ok(observed)
}

pub fn capacity_plan_for_runner_connections(
    expected_runner_connections: u64,
    max_streams_per_pod: u64,
) -> CapacityPlan {
    let max_streams_per_pod = max_streams_per_pod.max(1);
    let reconnect_storm_multiplier = 1.5;
    let required = ((expected_runner_connections as f64 * reconnect_storm_multiplier)
        / max_streams_per_pod as f64)
        .ceil() as u64;
    CapacityPlan {
        expected_runner_connections,
        max_streams_per_pod,
        recommended_pods: required.max(1),
        reconnect_storm_multiplier,
    }
}

pub fn runbook_drill_result(runbook: &Runbook, evidence: &[String]) -> RunbookDrillResult {
    let observed = evidence.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let missing = runbook
        .success_criteria
        .iter()
        .filter(|criterion| !observed.contains(criterion.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    RunbookDrillResult {
        runbook_id: runbook.id.clone(),
        passed: missing.is_empty(),
        missing_evidence: missing,
    }
}

pub fn official_dashboard_queries() -> Vec<DashboardQuery> {
    vec![
        dashboard(
            "runner_fleet_health",
            "Runner fleet health",
            "runner_active_total, runner_disconnected_total",
        ),
        dashboard(
            "local_execution",
            "Local execution success and latency",
            "local_tool_call_total by capability and workflow_local_dispatch_latency_ms p95",
        ),
        dashboard(
            "policy_approval",
            "Policy denies and approval timeouts",
            "policy_denied_total, approval_timeout_total",
        ),
        dashboard(
            "transport",
            "Transport fallback and reconnect",
            "transport_fallback_total, stream_reconnect_recovery_ms",
        ),
        dashboard(
            "trace_validation",
            "Trace upload and run validation API",
            "trace_upload_total, run_validation_api_total",
        ),
    ]
}

pub fn official_alert_rules() -> Vec<AlertRule> {
    vec![
        alert(
            "stream_failure_threshold",
            "runner stream failure threshold",
            "runner_stream_connect_total{result=failure}",
            5.0,
            5,
        ),
        alert(
            "error_budget_burn_7d",
            "7-day error budget burn blocks rollout",
            "error_budget_burn_percent_7d",
            50.0,
            10_080,
        ),
        alert(
            "policy_deny_spike",
            "policy deny spike after rollout",
            "policy_denied_total",
            100.0,
            15,
        ),
        alert(
            "approval_timeout_spike",
            "approval timeout spike",
            "approval_timeout_total",
            20.0,
            15,
        ),
        alert(
            "trace_upload_failure",
            "trace upload SLO breach",
            "trace_upload_total{result=failure}",
            1.0,
            30,
        ),
    ]
}

pub fn official_runbooks() -> Vec<Runbook> {
    vec![
        runbook(
            "grpc_outage",
            "gRPC outage",
            "gRPC connect success drops or ingress probe fails",
            [
                "grpc_ingress_failure_detected",
                "fallback_or_reconnect_validated",
                "customer_impact_assessed",
            ],
        ),
        runbook(
            "auth_outage",
            "Auth outage",
            "runner auth failures spike",
            [
                "auth_error_rate_confirmed",
                "token_issue_path_checked",
                "customer_impact_assessed",
            ],
        ),
        runbook(
            "policy_misconfiguration",
            "Policy misconfiguration",
            "policy deny spike after policy rollout",
            [
                "policy_change_identified",
                "rollback_or_fix_applied",
                "audit_export_attached",
            ],
        ),
        runbook(
            "update_rollout_failure",
            "Update rollout failure",
            "update failure alerts fire",
            [
                "bad_manifest_or_artifact_identified",
                "rollout_paused",
                "rollback_manifest_verified",
            ],
        ),
        runbook(
            "trace_storage_growth",
            "Trace storage growth",
            "trace storage grows faster than plan",
            [
                "growth_rate_confirmed",
                "retention_policy_checked",
                "customer_impact_assessed",
            ],
        ),
        runbook(
            "support_escalation",
            "Support escalation",
            "customer-impacting runner incident",
            [
                "support_bundle_requested",
                "audit_export_attached",
                "owner_assigned",
            ],
        ),
    ]
}

fn success_slo(id: &str, description: &str, target_percent: f64, metric: &str) -> SloDefinition {
    SloDefinition {
        id: id.to_string(),
        description: description.to_string(),
        kind: SloKind::SuccessRatio,
        target_percent: Some(target_percent),
        max_p95_ms: None,
        window_days: 30,
        metric: metric.to_string(),
    }
}

fn latency_slo(id: &str, description: &str, max_p95_ms: u64, metric: &str) -> SloDefinition {
    SloDefinition {
        id: id.to_string(),
        description: description.to_string(),
        kind: SloKind::LatencyP95,
        target_percent: None,
        max_p95_ms: Some(max_p95_ms),
        window_days: 30,
        metric: metric.to_string(),
    }
}

fn dashboard(id: &str, title: &str, query: &str) -> DashboardQuery {
    DashboardQuery {
        id: id.to_string(),
        title: title.to_string(),
        query: query.to_string(),
    }
}

fn alert(
    id: &str,
    description: &str,
    metric: &str,
    threshold: f64,
    window_minutes: u32,
) -> AlertRule {
    AlertRule {
        id: id.to_string(),
        description: description.to_string(),
        metric: metric.to_string(),
        threshold,
        window_minutes,
    }
}

fn runbook<const N: usize>(
    id: &str,
    title: &str,
    trigger: &str,
    success_criteria: [&str; N],
) -> Runbook {
    Runbook {
        id: id.to_string(),
        title: title.to_string(),
        trigger: trigger.to_string(),
        drill_steps: vec![
            "confirm alert and customer impact".to_string(),
            "inspect dashboard and logs".to_string(),
            "execute mitigation or rollback".to_string(),
            "attach audit/support evidence".to_string(),
        ],
        success_criteria: success_criteria.into_iter().map(str::to_string).collect(),
    }
}

fn percentile_ceil(samples: &[u64], percentile: u64) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted.get(rank.saturating_sub(1)).copied()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_emitted_for_connect_disconnect_and_tool_results() {
        let mut recorder = OperationalMetricsRecorder::default();

        recorder.record_runner_connected("grpc", 1_000);
        recorder.record_runner_disconnected("shutdown", 2_000);
        recorder.record_tool_call("shell.exec", true, 120, 3_000);
        recorder.record_tool_call("git.diff", false, 240, 4_000);

        let names = recorder
            .metrics()
            .iter()
            .map(|metric| metric.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"runner_stream_connect_total"));
        assert!(names.contains(&"runner_active_total"));
        assert!(names.contains(&"runner_disconnected_total"));
        assert_eq!(
            2,
            recorder
                .metrics()
                .iter()
                .filter(|metric| metric.name == "local_tool_call_total")
                .count()
        );
        assert!(recorder.metrics().iter().any(|metric| {
            metric.name == "local_tool_call_total"
                && metric
                    .labels
                    .get("capability")
                    .is_some_and(|value| value == "git.diff")
                && metric
                    .labels
                    .get("result")
                    .is_some_and(|value| value == "failure")
        }));
    }

    #[test]
    fn stream_failure_alert_fires_at_threshold() {
        let mut recorder = OperationalMetricsRecorder::default();
        for index in 0..5 {
            recorder.record_stream_failure("grpc", index);
        }

        let alerts = evaluate_operational_alerts(recorder.metrics());

        assert_eq!("stream_failure_threshold", alerts[0].rule_id);
        assert_eq!("page", alerts[0].severity);
    }

    #[test]
    fn dashboard_queries_and_readiness_plan_validate() {
        let plan = official_operational_readiness_plan(10_000);

        validate_operational_readiness_plan(&plan).unwrap();
        assert!(plan
            .dashboards
            .iter()
            .any(|dashboard| dashboard.id == "runner_fleet_health"));
        assert!(plan
            .required_metrics
            .iter()
            .any(|metric| metric == "transport_fallback_total"));
    }

    #[test]
    fn grpc_outage_runbook_drill_requires_evidence() {
        let runbook = official_runbooks()
            .into_iter()
            .find(|runbook| runbook.id == "grpc_outage")
            .unwrap();

        let failed = runbook_drill_result(&runbook, &["grpc_ingress_failure_detected".to_string()]);
        let passed = runbook_drill_result(
            &runbook,
            &[
                "grpc_ingress_failure_detected".to_string(),
                "fallback_or_reconnect_validated".to_string(),
                "customer_impact_assessed".to_string(),
            ],
        );

        assert!(!failed.passed);
        assert_eq!(2, failed.missing_evidence.len());
        assert!(passed.passed);
    }

    #[test]
    fn capacity_plan_accounts_for_reconnect_storm() {
        let plan = capacity_plan_for_runner_connections(10_000, 2_000);

        assert_eq!(8, plan.recommended_pods);
        assert_eq!(1.5, plan.reconnect_storm_multiplier);
    }

    #[test]
    fn slo_calculation_evaluates_success_ratio_and_latency_p95() {
        let connect = official_slos()
            .into_iter()
            .find(|slo| slo.id == "runner_stream_connect_success")
            .unwrap();
        let latency = official_slos()
            .into_iter()
            .find(|slo| slo.id == "workflow_local_dispatch_latency_p95")
            .unwrap();

        let connect_result = evaluate_slo(
            &connect,
            &SloObservation {
                slo_id: connect.id.clone(),
                total: 1_000,
                good: 996,
                samples_ms: vec![],
            },
        )
        .unwrap();
        let latency_result = evaluate_slo(
            &latency,
            &SloObservation {
                slo_id: latency.id.clone(),
                total: 0,
                good: 0,
                samples_ms: vec![100, 200, 400, 1_900, 1_950, 2_100],
            },
        )
        .unwrap();

        assert!(connect_result.passed);
        assert_eq!(Some(99.6), connect_result.observed_percent);
        assert!(!latency_result.passed);
        assert_eq!(Some(2_100), latency_result.observed_p95_ms);
    }

    #[test]
    fn error_budget_burn_blocks_release_gate() {
        let mut report = complete_passing_report();
        report
            .error_budget_burn
            .iter_mut()
            .find(|burn| burn.slo_id == "runner_stream_connect_success")
            .unwrap()
            .burn_percent_7d = 55.0;

        let decision = evaluate_release_gate(&report).unwrap();

        assert!(!decision.allowed);
        assert!(decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("error budget burn")));
        assert_eq!("error_budget_burn_7d", decision.alerts[0].rule_id);
    }

    #[test]
    fn release_gate_rejects_missing_duplicate_and_unknown_report_entries() {
        let empty = OperationalReadinessReport {
            schema_version: OPERATIONAL_READINESS_REPORT_SCHEMA_VERSION.to_string(),
            slo_results: vec![],
            error_budget_burn: vec![],
            open_critical_or_high_security_findings: 0,
            update_chain_tamper_test_passed: true,
            workspace_escape_tests_passed: true,
            secret_leakage_scan_passed: true,
            policy_bypass_tests_passed: true,
        };
        assert_eq!(
            "OPERATIONAL_READINESS_REPORT_SLO_MISSING",
            evaluate_release_gate(&empty).unwrap_err().code
        );

        let mut missing_budget = complete_passing_report();
        missing_budget.error_budget_burn.pop();
        assert_eq!(
            "OPERATIONAL_READINESS_REPORT_ERROR_BUDGET_MISSING",
            evaluate_release_gate(&missing_budget).unwrap_err().code
        );

        let mut duplicate = complete_passing_report();
        duplicate
            .slo_results
            .push(duplicate.slo_results.first().unwrap().clone());
        assert_eq!(
            "OPERATIONAL_READINESS_REPORT_SLO_DUPLICATE",
            evaluate_release_gate(&duplicate).unwrap_err().code
        );

        let mut unknown = complete_passing_report();
        unknown.slo_results[0].slo_id = "unknown_slo".to_string();
        assert_eq!(
            "OPERATIONAL_READINESS_REPORT_SLO_UNKNOWN",
            evaluate_release_gate(&unknown).unwrap_err().code
        );
    }

    fn complete_passing_report() -> OperationalReadinessReport {
        let slo_results = official_slos()
            .into_iter()
            .map(|slo| SloResult {
                slo_id: slo.id,
                passed: true,
                observed_percent: Some(100.0),
                observed_p95_ms: Some(1),
                error_budget_burn_percent: 0.0,
            })
            .collect::<Vec<_>>();
        let error_budget_burn = slo_results
            .iter()
            .map(|result| ErrorBudgetBurn {
                slo_id: result.slo_id.clone(),
                burn_percent_7d: 0.0,
            })
            .collect::<Vec<_>>();

        OperationalReadinessReport {
            schema_version: OPERATIONAL_READINESS_REPORT_SCHEMA_VERSION.to_string(),
            slo_results,
            error_budget_burn,
            open_critical_or_high_security_findings: 0,
            update_chain_tamper_test_passed: true,
            workspace_escape_tests_passed: true,
            secret_leakage_scan_passed: true,
            policy_bypass_tests_passed: true,
        }
    }
}
