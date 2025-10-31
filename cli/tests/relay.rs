use anyhow::{anyhow, Context};
use assert_cmd::Command as AssertCommand;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use hn_cli::identity::IdentityVault;
use hn_mcp::{McpConfig, McpMode, PeerConfig};
use serde_json::Value;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;
use ureq;

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

struct ServerHandle {
    child: Child,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn relay_push_expires_after_policy_ttl() -> anyhow::Result<()> {
    let relay_home = tempdir()?;
    let client_home = tempdir()?;

    // Prepare relay identity and MCP server.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", relay_home.path())
        .args(["id", "create", "relay", "--yes"])
        .assert()
        .success();
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", relay_home.path())
        .args(["id", "use", "relay"])
        .assert()
        .success();
    let relay_did = resolve_did(relay_home.path())?;

    // Prepare mobile client identity.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", client_home.path())
        .args(["id", "create", "alice", "--yes"])
        .assert()
        .success();
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", client_home.path())
        .args(["id", "use", "alice"])
        .assert()
        .success();
    let client_did = resolve_did(client_home.path())?;
    let client_vault = IdentityVault::new(client_home.path().to_path_buf())?;
    let client_identity = client_vault.load_identity("alice")?;
    let client_public_key = Base64.encode(client_identity.keys.verifying_key().to_bytes());

    configure_relay(relay_home.path(), &client_did, &client_public_key, 2)?;

    let port = allocate_port()?;
    let _server = spawn_relay_server(relay_home.path(), port, 2)?;

    // Publish presence advertising the relay.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", client_home.path())
        .args([
            "discover",
            "publish",
            "--alias",
            "alice",
            "--merkle-root",
            "demo-merkle-root",
            "--endpoint",
            "mcp=http://127.0.0.1:97733",
            "--endpoint",
            "presence=http://127.0.0.1:97733/.well-known/hn/presence",
            "--relay",
            &format!("{}=http://127.0.0.1:{}", relay_did, port),
            "--ttl-seconds",
            "30",
        ])
        .assert()
        .success();

    // Register relay host and push presence.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", client_home.path())
        .args([
            "mcp",
            "relay",
            "register",
            &relay_did,
            "--url",
            &format!("http://127.0.0.1:{port}"),
        ])
        .assert()
        .success();

    let push_output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", client_home.path())
        .args(["mcp", "relay", "push", "--to", &relay_did])
        .output()?;
    assert!(
        push_output.status.success(),
        "relay push failed: {}",
        String::from_utf8_lossy(&push_output.stderr)
    );
    let push_stdout = String::from_utf8(push_output.stdout)?;
    assert!(
        push_stdout.contains("Relay retention ends"),
        "expected relay retention message, got: {push_stdout}"
    );

    let relay_endpoint = format!("http://127.0.0.1:{port}/relay/{client_did}/presence");

    // Presence should be available immediately after push.
    match ureq::get(&relay_endpoint).call() {
        Ok(response) => {
            assert_eq!(response.status(), 200);
            let doc: Value = response
                .into_json()
                .map_err(|err| anyhow!("failed to parse relay presence: {err}"))?;
            assert_eq!(
                doc.get("did").and_then(|v| v.as_str()),
                Some(client_did.as_str())
            );
        }
        Err(err) => return Err(anyhow!("relay presence fetch failed: {err}")),
    }

    sleep(Duration::from_secs(3));

    // After TTL the relay should return 404 and purge the cached presence.
    match ureq::get(&relay_endpoint).call() {
        Err(ureq::Error::Status(404, _)) => {}
        Ok(resp) => {
            return Err(anyhow!(
                "relay presence unexpectedly returned {}",
                resp.status()
            ))
        }
        Err(err) => return Err(anyhow!("unexpected relay error: {err}")),
    }

    Ok(())
}

fn configure_relay(
    home: &Path,
    client_did: &str,
    client_public_key: &str,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let mut config = McpConfig::for_home(home);
    config.mode = McpMode::Public;
    config.relay_ttl_seconds = ttl_secs;
    config.allow = vec![PeerConfig {
        did: client_did.to_string(),
        public_key: client_public_key.to_string(),
    }];
    let json = serde_json::to_string_pretty(&config)?;
    fs::write(home.join("mcp.json"), json)
        .with_context(|| format!("failed to write relay config at {}", home.display()))?;
    Ok(())
}

fn spawn_relay_server(home: &Path, port: u16, ttl_secs: u64) -> anyhow::Result<ServerHandle> {
    let mut command = Command::new(bin_path("hn"));
    let mut child = command
        .env("HN_HOME", home)
        .env("HN_DISABLE_FEDERATION_WORKER", "1")
        .args([
            "mcp",
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--mode",
            "public",
            "--relay-ttl",
            &ttl_secs.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn relay MCP server")?;

    match wait_for_health(port) {
        Ok(()) => Ok(ServerHandle { child }),
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(err)
        }
    }
}

fn wait_for_health(port: u16) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{port}/healthz");
    for _ in 0..30 {
        match ureq::get(&url).call() {
            Ok(response) if response.status() == 200 => return Ok(()),
            Ok(_) | Err(_) => sleep(Duration::from_millis(100)),
        }
    }
    Err(anyhow!("MCP server on port {port} did not become healthy"))
}

fn allocate_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn resolve_did(home: &Path) -> anyhow::Result<String> {
    let output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "get", "--output", "json"])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to resolve DID: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let did = value
        .get("identity")
        .and_then(|ident| ident.get("did"))
        .and_then(|did| did.as_str())
        .ok_or_else(|| anyhow!("identity did missing from response"))?;
    Ok(did.to_string())
}
