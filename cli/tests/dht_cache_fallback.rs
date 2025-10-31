use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

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
fn resolve_uses_cache_when_http_unreachable() -> anyhow::Result<()> {
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

    let discovery_port = free_port();
    let mut discovery = Command::new(bin_path("hn-discovery"))
        .env("HN_HOME", home)
        .args([
            "--home",
            home.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{discovery_port}"),
            "--no-mdns",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn discovery");

    let health_url = format!("http://127.0.0.1:{discovery_port}/healthz");
    for _ in 0..20 {
        if ureq::get(&health_url).call().ok().is_some() {
            break;
        }
        sleep(Duration::from_millis(100));
    }

    let presence_url = "http://127.0.0.1:65535/.well-known/hn/presence";
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .env(
            "HN_DISCOVERY_URL",
            format!("http://127.0.0.1:{discovery_port}"),
        )
        .args([
            "discover",
            "publish",
            "--merkle-root",
            "demo-merkle",
            "--endpoint",
            "presence=http://127.0.0.1:65535/.well-known/hn/presence",
            "--dht",
            "--presence-url",
            presence_url,
        ])
        .assert()
        .success();

    let output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "get", "--output", "json"])
        .output()?;
    assert!(output.status.success());
    let parsed: Value = serde_json::from_slice(&output.stdout)?;
    let did = parsed["identity"]["did"].as_str().unwrap().to_string();

    let resolve = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .env(
            "HN_DISCOVERY_URL",
            format!("http://127.0.0.1:{discovery_port}"),
        )
        .args(["discover", "resolve", "--cache-fallback", &did])
        .output()?;
    let stdout = String::from_utf8(resolve.stdout)?;
    assert!(resolve.status.success(), "{}", stdout);
    assert!(stdout.contains("using cached copy"));

    let _ = discovery.kill();
    let _ = discovery.wait();

    Ok(())
}
