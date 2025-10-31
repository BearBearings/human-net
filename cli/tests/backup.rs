use anyhow::Result;
use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use std::fs;
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
fn backup_create_verify_and_restore_roundtrip() -> Result<()> {
    let home = tempdir()?;

    // Create identity and minimal vault content.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home.path())
        .args(["id", "create", "alice", "--yes"])
        .assert()
        .success();
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home.path())
        .args(["id", "use", "alice"])
        .assert()
        .success();

    let personal_dir = home.path().join("personal").join("docs");
    fs::create_dir_all(&personal_dir)?;
    fs::write(personal_dir.join("note.txt"), b"hello backup")?;
    let config_dir = home.path().join("config");
    fs::create_dir_all(&config_dir)?;
    fs::write(config_dir.join("settings.toml"), b"mode=\"friends\"")?;

    let output_path = home.path().join("backup.json");

    let create = AssertCommand::new(bin_path("vault"))
        .env("HN_HOME", home.path())
        .args([
            "backup",
            "create",
            "--alias",
            "alice",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()?;
    assert!(
        create.status.success(),
        "backup create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let verify = AssertCommand::new(bin_path("vault"))
        .env("HN_HOME", home.path())
        .args([
            "backup",
            "verify",
            "--alias",
            "alice",
            "--path",
            output_path.to_str().unwrap(),
        ])
        .output()?;
    assert!(
        verify.status.success(),
        "backup verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // Validate structure: ensure JSON contains ciphertext and entries.
    let value: Value = serde_json::from_slice(&fs::read(&output_path)?)?;
    assert_eq!(
        value["owner"].as_str(),
        Some(resolve_did(home.path())?.as_str())
    );
    assert!(value["ciphertext"].as_str().is_some(), "ciphertext missing");
    assert!(
        value["entries"]
            .as_array()
            .map(|entries| !entries.is_empty())
            .unwrap_or(false),
        "entries array empty"
    );

    let restore_dir = home.path().join("restore");
    let restore = AssertCommand::new(bin_path("vault"))
        .env("HN_HOME", home.path())
        .args([
            "backup",
            "restore",
            "--alias",
            "alice",
            "--path",
            output_path.to_str().unwrap(),
            "--into",
            restore_dir.to_str().unwrap(),
        ])
        .output()?;
    assert!(
        restore.status.success(),
        "backup restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );

    let restored_note = fs::read_to_string(restore_dir.join("personal/docs/note.txt"))?;
    assert_eq!(restored_note, "hello backup");
    let restored_settings = fs::read_to_string(restore_dir.join("config/settings.toml"))?;
    assert_eq!(restored_settings.trim(), "mode=\"friends\"");

    Ok(())
}

fn resolve_did(home: &std::path::Path) -> Result<String> {
    let output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "get", "--output", "json"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to resolve DID: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    Ok(value["identity"]["did"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing identity did"))?
        .to_string())
}
