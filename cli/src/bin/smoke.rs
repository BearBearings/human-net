use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

#[derive(Parser, Debug)]
#[command(name = "hn smoke", about = "Run Human.Net smoke tests.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate the M1 identity + discovery flow (Alice/Bob LAN discovery).
    #[command(alias = "M1")]
    M1,

    /// Run the M3 exchange flow (offer → contract → shard replay).
    #[command(alias = "M3")]
    M3,

    /// Aggregate M4 Reach & Agency smoke tests (S1–S4).
    #[command(alias = "M4")]
    M4,

    /// Exercise the M5 local federation flow (multi-node DHT + MCP).
    #[command(name = "m5", alias = "M5")]
    M5,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::M1 => run_m1(),
        Commands::M3 => run_m3(),
        Commands::M4 => run_m4(),
        Commands::M5 => run_m5(),
    }
}

fn run_m1() -> Result<()> {
    let hn = resolve_hn_binary()?;

    let alice_dir = TempDir::new().context("failed to create temp dir for alice")?;
    let bob_dir = TempDir::new().context("failed to create temp dir for bob")?;

    let mut alice_started = false;
    let mut bob_started = false;

    let result = (|| -> Result<()> {
        // Alice setup
        run(
            &hn,
            alice_dir.path(),
            &[
                "id",
                "create",
                "alice",
                "--capability",
                "unit:offer",
                "--endpoint",
                "discovery=hn+mdns://alice.local",
                "--yes",
                "-o",
                "json",
            ],
        )?;
        run(&hn, alice_dir.path(), &["id", "use", "alice", "-o", "json"])?;
        run(
            &hn,
            alice_dir.path(),
            &["service", "start", "discovery", "-o", "json"],
        )?;
        alice_started = true;
        wait_for_service_ready(&hn, alice_dir.path())?;

        // Bob setup
        run(
            &hn,
            bob_dir.path(),
            &[
                "id",
                "create",
                "bob",
                "--capability",
                "unit:offer",
                "--endpoint",
                "discovery=hn+mdns://bob.local",
                "--yes",
                "-o",
                "json",
            ],
        )?;
        run(&hn, bob_dir.path(), &["id", "use", "bob", "-o", "json"])?;
        run(
            &hn,
            bob_dir.path(),
            &["service", "start", "discovery", "-o", "json"],
        )?;
        bob_started = true;
        wait_for_service_ready(&hn, bob_dir.path())?;

        // Wait a bit for discovery announcements
        sleep(Duration::from_secs(1));

        wait_for_peer(&hn, alice_dir.path(), "bob")?;
        wait_for_peer(&hn, bob_dir.path(), "alice")?;

        println!("M1 smoke test passed: Alice and Bob discovered each other.");
        Ok(())
    })();

    if alice_started {
        let _ = run(
            &hn,
            alice_dir.path(),
            &["service", "stop", "discovery", "-o", "json"],
        );
    }
    if bob_started {
        let _ = run(
            &hn,
            bob_dir.path(),
            &["service", "stop", "discovery", "-o", "json"],
        );
    }

    result
}

fn run_m3() -> Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let script = repo_root.join("tooling/scripts/m3-test.sh");
    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&repo_root)
        .status()
        .with_context(|| format!("failed to execute {}", script.display()))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "m3 smoke test failed with status {:?}",
            status.code()
        ))
    }
}

fn run_m4() -> Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let scripts = [
        "tooling/scripts/m4-s1-test.sh",
        "tooling/scripts/m4-s2-test.sh",
        "tooling/scripts/m4-s3-test.sh",
        "tooling/scripts/m4-s4-test.sh",
    ];

    for script in &scripts {
        let path = repo_root.join(script);
        println!("→ Running {}", script);
        let status = Command::new("bash")
            .arg(&path)
            .current_dir(&repo_root)
            .status()
            .with_context(|| format!("failed to execute {}", path.display()))?;
        if !status.success() {
            return Err(anyhow!("{} failed with status {:?}", script, status.code()));
        }
    }

    println!("M4 aggregate smoke passed: all S1–S4 scripts succeeded.");
    Ok(())
}

fn run_m5() -> Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let script = repo_root.join("tooling/scripts/m5-smoke.sh");
    if !script.exists() {
        return Err(anyhow!(
            "m5 smoke script not found at {}; please update tooling/scripts/m5-smoke.sh",
            script.display()
        ));
    }
    println!("→ Running {}", script.display());
    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&repo_root)
        .status()
        .with_context(|| format!("failed to execute {}", script.display()))?;
    if status.success() {
        println!("M5 local federation smoke passed.");
        Ok(())
    } else {
        Err(anyhow!("m5 smoke failed with status {:?}", status.code()))
    }
}

fn wait_for_peer(hn: &Path, home: &Path, expected_alias: &str) -> Result<()> {
    for _ in 0..12 {
        let output = run(hn, home, &["peer", "list", "-o", "json"])?;
        let resp: PeerListResponse =
            serde_json::from_slice(&output.stdout).context("failed to parse peer list response")?;
        if resp
            .peers
            .iter()
            .any(|peer| peer.alias.eq_ignore_ascii_case(expected_alias))
        {
            return Ok(());
        }
        sleep(Duration::from_millis(500));
    }
    Err(anyhow!(
        "peer '{}' did not appear in discovery list for {:?}",
        expected_alias,
        home
    ))
}

fn wait_for_service_ready(hn: &Path, home: &Path) -> Result<()> {
    for _ in 0..120 {
        let output = match run(hn, home, &["service", "status", "-o", "json"]) {
            Ok(output) => output,
            Err(_) => {
                sleep(Duration::from_millis(500));
                continue;
            }
        };
        let resp: ServiceStatusResponse = match serde_json::from_slice(&output.stdout) {
            Ok(resp) => resp,
            Err(_) => {
                sleep(Duration::from_millis(500));
                continue;
            }
        };

        let target = resp
            .http
            .or_else(|| resp.listen.clone().map(normalize_listen));

        if resp.running {
            return Ok(());
        }

        if let Some(target) = target {
            if probe_health(&target).is_ok() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(500));
    }
    Err(anyhow!(
        "discovery service did not become ready for {:?}",
        home
    ))
}

fn run(hn: &Path, home: &Path, args: &[&str]) -> Result<Output> {
    let output = Command::new(hn)
        .args(args)
        .env("HN_HOME", home)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .with_context(|| format!("failed to execute {:?} {:?}", hn, args))?;

    if output.status.success() {
        Ok(output)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!(
            "command {:?} {:?} failed: {}",
            hn,
            args,
            stderr.trim()
        ))
    }
}

fn resolve_hn_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve smoke binary path")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("failed to determine smoke binary directory"))?;
    let name = if cfg!(windows) { "hn.exe" } else { "hn" };
    let candidate = dir.join(name);
    if candidate.exists() {
        Ok(candidate)
    } else if let Ok(env_dir) = std::env::var("HN_BIN_DIR") {
        let env_path = Path::new(&env_dir).join(name);
        if env_path.exists() {
            Ok(env_path)
        } else {
            Err(anyhow!(
                "could not find hn binary; searched {} and {}",
                candidate.display(),
                env_path.display()
            ))
        }
    } else {
        Err(anyhow!(
            "could not find hn binary next to smoke binary at {}",
            candidate.display()
        ))
    }
}

#[derive(Debug, Deserialize)]
struct PeerListResponse {
    peers: Vec<PeerInfo>,
}

#[derive(Debug, Deserialize)]
struct PeerInfo {
    alias: String,
    #[allow(dead_code)]
    did: String,
    #[allow(dead_code)]
    addresses: Vec<String>,
    #[allow(dead_code)]
    endpoints: Vec<String>,
    #[allow(dead_code)]
    capabilities: Vec<String>,
    #[allow(dead_code)]
    last_seen: Value,
}

#[derive(Debug, Deserialize)]
struct ServiceStatusResponse {
    running: bool,
    #[allow(dead_code)]
    listen: Option<String>,
    #[allow(dead_code)]
    alias: Option<String>,
    #[serde(default)]
    http: Option<String>,
}

fn probe_health(http: &str) -> Result<()> {
    let url = format!("http://{}/healthz", http);
    let response = ureq::get(&url).call().map_err(|err| anyhow!("{}", err))?;
    if (200..=299).contains(&response.status()) {
        Ok(())
    } else {
        Err(anyhow!(
            "health check returned status {}",
            response.status()
        ))
    }
}

fn normalize_listen(listen: String) -> String {
    if let Ok(addr) = listen.parse::<std::net::SocketAddr>() {
        match addr.ip() {
            std::net::IpAddr::V4(v4) if v4.is_unspecified() => {
                format!("127.0.0.1:{}", addr.port())
            }
            std::net::IpAddr::V6(v6) if v6.is_unspecified() => {
                format!("[::1]:{}", addr.port())
            }
            _ => listen,
        }
    } else {
        listen
    }
}
