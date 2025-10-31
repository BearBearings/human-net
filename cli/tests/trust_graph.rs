use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use std::path::PathBuf;
use tempfile::tempdir;

fn bin_path(name: &str) -> PathBuf {
    if let Ok(path) = std::env::var(format!("CARGO_BIN_EXE_{name}")) {
        return PathBuf::from(path);
    }
    let mut base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.push("..");
    base.push("target");
    base.push("debug");
    if cfg!(windows) {
        base.push(format!("{name}.exe"));
    } else {
        base.push(name);
    }
    base
}

#[test]
fn trust_cli_roundtrip() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let home = temp.path();

    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "create", "alice", "--yes"])
        .assert()
        .success();

    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "use", "alice"])
        .assert()
        .success();

    // First link
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args([
            "trust",
            "link",
            "derive",
            "--to",
            "did:hn:bob",
            "--based-on",
            "contract:bike-001",
            "--confidence",
            "0.8",
        ])
        .assert()
        .success();

    // Verify list output (JSON)
    let list_output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["trust", "link", "list", "--output", "json"])
        .output()?;
    assert!(list_output.status.success());
    let stdout = String::from_utf8(list_output.stdout.clone())?;
    assert!(!stdout.trim().is_empty(), "link list produced empty output");
    let list_json: Value = serde_json::from_slice(&list_output.stdout)?;
    assert_eq!(list_json["count"].as_u64().unwrap(), 1);

    // Min-links enforcement should fail with only one link
    let fail_output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args([
            "trust",
            "reputation",
            "compute",
            "--target",
            "did:hn:bob",
            "--min-links",
            "2",
        ])
        .output()?;
    assert!(!fail_output.status.success());

    // Second link, different evidence/context
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args([
            "trust",
            "link",
            "derive",
            "--to",
            "did:hn:bob",
            "--based-on",
            "receipt:002",
            "--confidence",
            "0.9",
            "--context",
            "micropay",
        ])
        .assert()
        .success();

    // Compute reputation
    let rep_output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args([
            "trust",
            "reputation",
            "compute",
            "--target",
            "did:hn:bob",
            "--policy-ref",
            "policy/local",
            "--output",
            "json",
        ])
        .output()?;
    assert!(rep_output.status.success());
    let rep_json: Value = serde_json::from_slice(&rep_output.stdout)?;
    assert!(rep_json["command"]
        .as_str()
        .unwrap()
        .ends_with("trust.reputation.compute"));
    assert!(rep_json["path"].as_str().is_some());

    // Reputation list contains deterministic aggregate
    let list_rep = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["trust", "reputation", "list", "--output", "json"])
        .output()?;
    assert!(list_rep.status.success());
    let list_rep_json: Value = serde_json::from_slice(&list_rep.stdout)?;
    let entries = list_rep_json["reputation"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let aggregate = &entries[0]["aggregate"];
    assert_eq!(aggregate["count"].as_u64().unwrap(), 2);
    let avg = aggregate["avg_confidence"].as_f64().unwrap();
    assert!((avg - 0.85).abs() < 1e-6);

    // Links should be sorted for determinism
    let links = entries[0]["links"].as_array().unwrap();
    let sorted = links
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect::<Vec<_>>();
    let mut manual = sorted.clone();
    manual.sort();
    assert_eq!(sorted, manual);

    Ok(())
}
