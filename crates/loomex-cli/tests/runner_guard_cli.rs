use std::{
    fs,
    path::PathBuf,
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

use loomex_core::{read_runner_runtime_guard, runner_runtime_guard_path};
use serde_json::Value;

#[test]
fn compiled_cli_start_guard_can_be_stopped_by_later_cli_process() {
    let binary = env!("CARGO_BIN_EXE_loomex");
    let root = temp_root("start-stop-guard");
    let config_path = root.join("config.toml");
    let binding_id = format!("binding_cli_start_stop_{}", process::id());
    fs::create_dir_all(&root).unwrap();
    fs::write(&config_path, config_doc(&binding_id)).unwrap();

    let start = Command::new(binary)
        .env("LOOMEX_CONFIG_PATH", &config_path)
        .arg("--json")
        .args(["runner", "start"])
        .output()
        .unwrap();
    assert!(
        start.status.success(),
        "start failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );
    let start_json: Value = serde_json::from_slice(&start.stdout).unwrap();
    assert_eq!("loomex.cli.runnerStart/v1", start_json["schemaVersion"]);

    let guard_path = runner_runtime_guard_path(&config_path, &binding_id);
    let guard = read_runner_runtime_guard(&guard_path).unwrap().unwrap();
    assert_eq!("loomex-cli", guard.surface);
    assert_eq!(binding_id, guard.binding_id);

    let stop = Command::new(binary)
        .env("LOOMEX_CONFIG_PATH", &config_path)
        .arg("--json")
        .args(["runner", "stop"])
        .output()
        .unwrap();
    assert!(
        stop.status.success(),
        "stop failed: stdout={} stderr={}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
    let stop_json: Value = serde_json::from_slice(&stop.stdout).unwrap();
    assert_eq!("loomex.cli.runnerStop/v1", stop_json["schemaVersion"]);
    assert!(!guard_path.exists());

    let _ = fs::remove_dir_all(root);
}

fn config_doc(binding_id: &str) -> String {
    format!(
        r#"configVersion = 1
selectedProfile = "default"

[profiles."default"]
serverUrl = "https://loomex.app"
bindingId = "{binding_id}"
"#
    )
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("loomex-cli-{label}-{}-{nanos}", process::id()))
}
