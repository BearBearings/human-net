use anyhow::anyhow;
use assert_cmd::Command as AssertCommand;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use hn_cli::discovery::{generate_presence_doc, save_presence_doc};
use hn_cli::identity::IdentityVault;
use hn_cli::services::federation::FederationRoster;
use hn_cli::shard::{create_index, ShardIndexEntry};
use hn_mcp::federation::FederatedIndexSlice;
use hn_mcp::{McpStorage, PublishArtifact, PublishRequest};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
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

struct NodeContext {
    home: PathBuf,
    did: String,
    base_url: String,
    presence_path: PathBuf,
    roster_path: PathBuf,
}

#[test]
fn federation_refresh_fetches_remote_index() -> anyhow::Result<()> {
    let alice_temp = tempdir()?;
    let bob_temp = tempdir()?;

    let alice_port = allocate_port()?;
    let bob_port = allocate_port()?;

    let alice = initialise_node(alice_temp.path(), "alice", alice_port)?;
    let bob = initialise_node(bob_temp.path(), "bob", bob_port)?;

    // Start Bob first so Alice can pull from it.
    let _bob_server = spawn_mcp_server(&bob, bob_port)?;
    let _alice_server = spawn_mcp_server(&alice, alice_port)?;

    // Register Bob as federation peer for Alice.
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", &alice.home)
        .args(["mcp", "federate", "add", &bob.did, &bob.base_url])
        .assert()
        .success();

    // First refresh should fetch entries.
    let refresh_output = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", &alice.home)
        .args(["mcp", "federate", "refresh"])
        .output()?;
    assert!(refresh_output.status.success());
    let refresh_stdout = String::from_utf8(refresh_output.stdout)?;
    assert!(
        refresh_stdout.contains("fetched 1 entries"),
        "unexpected refresh output: {refresh_stdout}"
    );

    // Cache directory should contain a slice for Bob.
    let cache_dir = alice
        .home
        .join("cache")
        .join("federation")
        .join(sanitize_component(&bob.did));
    assert!(
        cache_dir.exists(),
        "expected cache directory {:?} to exist",
        cache_dir
    );
    let slice_path = find_slice(&cache_dir)?;
    let slice_bytes = fs::read(&slice_path)?;
    let slice: FederatedIndexSlice = serde_json::from_slice(&slice_bytes)?;
    assert_eq!(slice.publisher, bob.did);
    assert_eq!(slice.entries.len(), 1);

    // Federation roster should retain cursor + ETag.
    let roster = FederationRoster::load(&alice.roster_path)?;
    let peer = roster
        .peers
        .iter()
        .find(|peer| peer.did == bob.did)
        .expect("peer not found in roster");
    assert!(peer.cursor.is_some(), "expected cursor to be recorded");
    assert!(
        peer.etag.is_some(),
        "expected canonical hash (etag) to be recorded"
    );

    // Second refresh should be a no-op.
    let refresh_again = AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", &alice.home)
        .args(["mcp", "federate", "refresh"])
        .output()?;
    assert!(refresh_again.status.success());
    let stdout2 = String::from_utf8(refresh_again.stdout)?;
    assert!(
        stdout2.contains("up-to-date"),
        "expected up-to-date message, got: {stdout2}"
    );

    Ok(())
}

fn initialise_node(home: &Path, alias: &str, port: u16) -> anyhow::Result<NodeContext> {
    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "create", alias, "--yes"])
        .assert()
        .success();

    AssertCommand::new(bin_path("hn"))
        .env("HN_HOME", home)
        .args(["id", "use", alias])
        .assert()
        .success();

    let vault = IdentityVault::new(home.to_path_buf())?;
    let record = vault.load_identity(alias)?;
    let signing_key = record.keys.signing_key();
    let did = record.profile.id.clone();

    let artifact_path = format!("shards/{alias}.json");
    let artifact_body = serde_json::to_vec(&json!({
        "id": format!("shard:{alias}:sample"),
        "owner": did,
        "alias": alias,
    }))?;
    let artifact_digest = blake3::hash(&artifact_body).to_hex().to_string();

    let entry = ShardIndexEntry {
        kind: "shard".to_string(),
        id: format!("shard:{alias}:sample"),
        path: artifact_path.clone(),
        digest: artifact_digest,
        metadata: None,
    };

    let generated_at = OffsetDateTime::now_utc();
    let index = create_index(&did, signing_key, generated_at, vec![entry])?;
    let index_value = serde_json::to_value(&index)?;
    let mcp_index: hn_mcp::ShardIndex = serde_json::from_value(index_value)?;

    let artifact = PublishArtifact {
        path: artifact_path,
        content: Base64.encode(&artifact_body),
    };

    let storage_path = home.join("mcp").join("storage");
    let storage = McpStorage::new(storage_path)?;
    storage.apply_publish(PublishRequest {
        index: mcp_index,
        artifacts: vec![artifact],
    })?;

    let base_url = format!("http://127.0.0.1:{port}");
    let presence_url = format!("{base_url}/presence");
    let mut endpoints = BTreeMap::new();
    endpoints.insert("mcp".to_string(), base_url.clone());
    endpoints.insert("presence".to_string(), presence_url.clone());

    let presence_doc = generate_presence_doc(
        &vault,
        alias,
        endpoints,
        index.merkle_root.clone(),
        None,
        Vec::new(),
        Duration::from_secs(600),
    )?;
    let presence_path = save_presence_doc(home, alias, &presence_doc)?;

    let roster_path = FederationRoster::roster_path(home);

    Ok(NodeContext {
        home: home.to_path_buf(),
        did,
        base_url,
        presence_path,
        roster_path,
    })
}

fn spawn_mcp_server(node: &NodeContext, port: u16) -> anyhow::Result<ServerHandle> {
    let mut command = Command::new(bin_path("hn"));
    let mut child = command
        .env("HN_HOME", &node.home)
        .env("HN_DISABLE_FEDERATION_WORKER", "1")
        .args([
            "mcp",
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--presence-path",
            node.presence_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    match wait_for_health(port) {
        Ok(_) => Ok(ServerHandle { child }),
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

fn sanitize_component(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let trimmed = sanitized.trim_matches('-').to_lowercase();
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed
    }
}

fn find_slice(cache_dir: &Path) -> anyhow::Result<PathBuf> {
    for entry in fs::read_dir(cache_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let file_name = entry.file_name();
            if let Some(name) = file_name.to_str() {
                if name.starts_with("index-") && name.ends_with(".json") {
                    return Ok(entry.path());
                }
            }
        }
    }
    Err(anyhow!(
        "no federated slice found under {}",
        cache_dir.display()
    ))
}
