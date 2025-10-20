use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::services::discovery::{logs_tail, DiscoveryState};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use time::OffsetDateTime;

#[derive(Parser, Debug)]
#[command(
    name = "hn service",
    author = "Human.Net",
    version,
    about = "Control local Human.Net services."
)]
struct Cli {
    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        default_value_t = OutputFormat::Text,
        global = true
    )]
    output: OutputFormat,

    #[arg(long = "dry-run", global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start a service (M1: discovery only).
    Start {
        #[command(subcommand)]
        service: ServiceSelector,
    },
    /// Stop a running service.
    Stop {
        #[command(subcommand)]
        service: ServiceSelector,
    },
    /// Show status information.
    Status {
        #[command(subcommand)]
        service: Option<ServiceSelector>,
    },
    /// Tail service logs.
    Logs {
        #[command(subcommand)]
        service: LogsSelector,

        /// Number of log lines to show.
        #[arg(short = 'n', long = "lines", default_value_t = 100)]
        lines: usize,
    },
    /// Stop and clean up service state.
    Reset {
        #[command(subcommand)]
        service: ResetSelector,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ServiceSelector {
    /// Discovery service (mDNS + health endpoint).
    Discovery(DiscoveryArgs),
}

#[derive(Args, Debug, Clone, Default)]
struct DiscoveryArgs {
    /// Override listen address for discovery HTTP API.
    #[arg(long = "listen", value_name = "HOST:PORT")]
    listen: Option<String>,

    /// Override peer TTL in seconds.
    #[arg(long = "peer-ttl", value_name = "SECONDS")]
    peer_ttl: Option<u64>,
}

#[derive(Subcommand, Debug, Clone)]
enum ResetSelector {
    /// Reset discovery service state.
    Discovery(ResetDiscoveryArgs),
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum LogsSelector {
    /// Discovery service (mDNS + health endpoint).
    Discovery,
}

#[derive(Args, Debug, Clone, Default)]
struct ResetDiscoveryArgs {
    /// Remove discovery logs from the node home.
    #[arg(long = "purge-logs")]
    purge_logs: bool,
}

struct CommandContext {
    output: OutputFormat,
    dry_run: bool,
}

impl CommandContext {
    fn read_mode(&self) -> &'static str {
        if self.dry_run {
            "dry_run"
        } else {
            "execute"
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = CommandContext {
        output: cli.output,
        dry_run: cli.dry_run,
    };

    let home = ensure_home_dir()?;
    let output = match cli.command {
        Commands::Start { service } => handle_start(&ctx, &home, service),
        Commands::Stop { service } => handle_stop(&ctx, &home, service),
        Commands::Status { service } => handle_status(&ctx, &home, service),
        Commands::Logs { service, lines } => handle_logs(&ctx, &home, service, lines),
        Commands::Reset { service } => handle_reset(&ctx, &home, service),
    }?;

    output.render(ctx.output)?;
    Ok(())
}

fn handle_start(
    ctx: &CommandContext,
    home: &PathBuf,
    selector: ServiceSelector,
) -> Result<CommandOutput> {
    match selector {
        ServiceSelector::Discovery(opts) => start_discovery(ctx, home, opts),
    }
}

fn handle_stop(
    ctx: &CommandContext,
    home: &PathBuf,
    selector: ServiceSelector,
) -> Result<CommandOutput> {
    match selector {
        ServiceSelector::Discovery(_) => stop_discovery(ctx, home),
    }
}

fn handle_status(
    ctx: &CommandContext,
    home: &PathBuf,
    selector: Option<ServiceSelector>,
) -> Result<CommandOutput> {
    match selector.unwrap_or(ServiceSelector::Discovery(DiscoveryArgs::default())) {
        ServiceSelector::Discovery(_) => status_discovery(ctx, home),
    }
}

fn handle_logs(
    ctx: &CommandContext,
    home: &PathBuf,
    selector: LogsSelector,
    lines: usize,
) -> Result<CommandOutput> {
    match selector {
        LogsSelector::Discovery => logs_discovery(ctx, home, lines),
    }
}

fn handle_reset(
    ctx: &CommandContext,
    home: &PathBuf,
    selector: ResetSelector,
) -> Result<CommandOutput> {
    match selector {
        ResetSelector::Discovery(args) => reset_discovery(ctx, home, args),
    }
}

fn resolve_active_node(home: &PathBuf) -> Result<(IdentityVault, String, PathBuf)> {
    let vault = IdentityVault::new(home.clone())
        .context("failed to open identity vault; run `hn id` first")?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>` first"))?;
    let node_home = vault.node_home(&active.alias)?;
    Ok((vault, active.alias, node_home))
}

fn start_discovery(
    ctx: &CommandContext,
    home: &PathBuf,
    opts: DiscoveryArgs,
) -> Result<CommandOutput> {
    if ctx.dry_run {
        return Ok(CommandOutput::new(
            "Dry-run: would start discovery service",
            json!({
                "command": "start",
                "service": "discovery",
                "mode": ctx.read_mode(),
            }),
        ));
    }

    let (_vault, alias, node_home) = resolve_active_node(home)?;

    let listen_addr: SocketAddr = if let Some(listen) = opts.listen {
        listen
            .parse()
            .context("invalid --listen address; expected host:port")?
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), find_available_port()?)
    };
    let peer_ttl = opts.peer_ttl.unwrap_or(180);

    if let Some(state) = DiscoveryState::load(&node_home)? {
        if state.is_running() {
            bail!("discovery service already running (pid {})", state.pid);
        } else {
            DiscoveryState::remove(&node_home)?;
        }
    }

    let state_dir = DiscoveryState::state_dir(&node_home)?;
    let logs_dir = DiscoveryState::logs_dir(&node_home)?;
    let timestamp = OffsetDateTime::now_utc();
    let log_path = logs_dir.join(format!("discovery-{}.log", timestamp.unix_timestamp()));
    let log_file = File::create(&log_path)
        .with_context(|| format!("failed to create log file {}", log_path.display()))?;

    let binary = resolve_discovery_binary()?;

    let mut command = Command::new(&binary);
    command
        .env("HN_HOME", home)
        .arg("--listen")
        .arg(listen_addr.to_string())
        .arg("--peer-ttl")
        .arg(peer_ttl.to_string())
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file.try_clone()?))
        .stdin(Stdio::null())
        .current_dir(&state_dir);

    let child = command.spawn().with_context(|| {
        format!(
            "failed to launch discovery daemon using binary {}",
            binary.display()
        )
    })?;
    let pid = child.id();

    let state = DiscoveryState {
        pid,
        listen: listen_addr.to_string(),
        log_path: log_path.to_string_lossy().to_string(),
        alias: alias.clone(),
        started_at: timestamp,
    };
    state.save(&node_home)?;

    Ok(CommandOutput::new(
        format!(
            "Started discovery service for '{alias}' (pid {pid}, listening on {})",
            listen_addr
        ),
        json!({
            "command": "start",
            "service": "discovery",
            "mode": ctx.read_mode(),
            "pid": pid,
            "listen": listen_addr,
            "log_path": state.log_path,
            "started_at": timestamp,
            "alias": alias,
        }),
    ))
}

fn stop_discovery(ctx: &CommandContext, home: &PathBuf) -> Result<CommandOutput> {
    if ctx.dry_run {
        return Ok(CommandOutput::new(
            "Dry-run: would stop discovery service",
            json!({
                "command": "stop",
                "service": "discovery",
                "mode": ctx.read_mode(),
            }),
        ));
    }

    let (_vault, alias, node_home) = resolve_active_node(home)?;

    let Some(state) = stop_discovery_process(&node_home, &alias)? else {
        bail!("discovery service is not running for '{alias}'");
    };

    Ok(CommandOutput::new(
        format!("Stopped discovery service for '{alias}'"),
        json!({
            "command": "stop",
            "service": "discovery",
            "mode": ctx.read_mode(),
            "alias": state.alias,
        }),
    ))
}

fn status_discovery(ctx: &CommandContext, home: &PathBuf) -> Result<CommandOutput> {
    let (_vault, alias, node_home) = resolve_active_node(home)?;

    let Some(mut state) = DiscoveryState::load(&node_home)? else {
        return Ok(CommandOutput::new(
            format!("Discovery service is not running for '{alias}'"),
            json!({
                "command": "status",
                "service": "discovery",
                "mode": ctx.read_mode(),
                "running": false,
                "alias": alias,
            }),
        ));
    };
    if state.alias.is_empty() {
        state.alias = alias.clone();
    }

    let status = fetch_health(&state);
    let running = status.is_ok();

    let payload = json!({
        "command": "status",
        "service": "discovery",
        "mode": ctx.read_mode(),
        "running": running,
        "pid": state.pid,
        "listen": state.listen,
        "started_at": state.started_at,
        "alias": state.alias,
        "http": state.http_base().ok(),
        "health": status.ok(),
    });

    let message = if running {
        format!(
            "Discovery service for '{}' running (pid {}, listen {})",
            state.alias, state.pid, state.listen
        )
    } else {
        format!(
            "Discovery service for '{}' not reachable; last known pid {} (listen {})",
            state.alias, state.pid, state.listen
        )
    };

    Ok(CommandOutput::new(message, payload))
}

fn logs_discovery(ctx: &CommandContext, home: &PathBuf, lines: usize) -> Result<CommandOutput> {
    let (_vault, alias, node_home) = resolve_active_node(home)?;

    let Some(mut state) = DiscoveryState::load(&node_home)? else {
        bail!("discovery service has not been started yet for '{alias}'");
    };
    if state.alias.is_empty() {
        state.alias = alias;
    }
    let log_path = PathBuf::from(&state.log_path);
    if !log_path.exists() {
        bail!("log file {} does not exist", log_path.display());
    }

    let tail = logs_tail(&log_path, lines).unwrap_or_default();
    if ctx.output == OutputFormat::Text {
        for line in &tail {
            println!("{}", line);
        }
    }

    Ok(CommandOutput::new(
        format!(
            "Last {} lines from discovery logs for '{}' ({})",
            lines,
            state.alias,
            log_path.display()
        ),
        json!({
            "command": "logs",
            "service": "discovery",
            "mode": ctx.read_mode(),
            "lines": tail,
            "log_path": log_path,
            "alias": state.alias,
        }),
    ))
}

fn reset_discovery(
    ctx: &CommandContext,
    home: &PathBuf,
    args: ResetDiscoveryArgs,
) -> Result<CommandOutput> {
    if ctx.dry_run {
        return Ok(CommandOutput::new(
            "Dry-run: would reset discovery service",
            json!({
                "command": "reset",
                "service": "discovery",
                "mode": "dry_run",
            }),
        ));
    }

    let (_vault, alias, node_home) = resolve_active_node(home)?;
    let stopped = stop_discovery_process(&node_home, &alias)?;

    let services_dir = node_home.join("services").join("discovery");
    let state_path = services_dir.join("service.json");
    if state_path.exists() {
        fs::remove_file(&state_path)
            .with_context(|| format!("failed to remove {}", state_path.display()))?;
    }
    if args.purge_logs {
        let logs_dir = services_dir.join("logs");
        if logs_dir.exists() {
            fs::remove_dir_all(&logs_dir)
                .with_context(|| format!("failed to remove {}", logs_dir.display()))?;
        }
    }

    let message = if stopped.is_some() {
        format!("Reset discovery service for '{alias}' (service stopped)")
    } else {
        format!("Reset discovery service for '{alias}'")
    };

    Ok(CommandOutput::new(
        message,
        json!({
            "command": "reset",
            "service": "discovery",
            "mode": ctx.read_mode(),
            "alias": alias,
            "stopped": stopped.is_some(),
            "purge_logs": args.purge_logs,
        }),
    ))
}

fn stop_discovery_process(
    node_home: &Path,
    fallback_alias: &str,
) -> Result<Option<DiscoveryState>> {
    let Some(mut state) = DiscoveryState::load(node_home)? else {
        return Ok(None);
    };
    if state.alias.is_empty() {
        state.alias = fallback_alias.to_string();
    }

    let pid = state.pid as i32;
    let target = Pid::from_raw(pid);

    match kill(target, Some(Signal::SIGTERM)) {
        Ok(_) => {}
        Err(nix::errno::Errno::ESRCH) => {
            DiscoveryState::remove(node_home)?;
            return Ok(Some(state));
        }
        Err(err) => bail!("failed to signal discovery process: {err}"),
    }

    let mut attempts = 0;
    loop {
        sleep(Duration::from_millis(200));
        attempts += 1;
        match kill(target, None) {
            Ok(_) => {
                if attempts > 25 {
                    break;
                }
                continue;
            }
            Err(nix::errno::Errno::ESRCH) => break,
            Err(err) => bail!("failed to check discovery process: {err}"),
        }
    }

    if kill(target, None).is_ok() {
        let _ = kill(target, Some(Signal::SIGKILL));
    }

    DiscoveryState::remove(node_home)?;
    Ok(Some(state))
}

fn find_available_port() -> Result<u16> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("failed to allocate ephemeral port")?;
    let port = listener
        .local_addr()
        .context("failed to read ephemeral port")?
        .port();
    drop(listener);
    Ok(port)
}

fn resolve_discovery_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("HN_DISCOVERY_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let current = std::env::current_exe().context("failed to resolve current executable")?;
    let dir = current
        .parent()
        .context("failed to determine executable directory")?;

    #[cfg(windows)]
    let binary_name = "hn-discovery.exe";
    #[cfg(not(windows))]
    let binary_name = "hn-discovery";

    let debug_candidate = dir.join(binary_name);
    if debug_candidate.exists() {
        return Ok(debug_candidate);
    }

    if let Some(parent) = dir.parent() {
        let release_candidate = parent.join("release").join(binary_name);
        if release_candidate.exists() {
            return Ok(release_candidate);
        }
    }

    Err(anyhow!(
        "Could not locate 'hn-discovery' binary. Run `cargo build -p hn-discovery` first or set HN_DISCOVERY_BIN"
    ))
}

fn fetch_health(state: &DiscoveryState) -> Result<HealthResponse> {
    let base = state.http_base()?;
    let url = format!("http://{}/healthz", base);
    let response = ureq::get(&url)
        .call()
        .map_err(|err| anyhow!("failed to contact discovery service at {}: {}", url, err))?;

    if !(200..=299).contains(&response.status()) {
        bail!(
            "discovery service returned status {} for {}",
            response.status(),
            url
        );
    }

    let health: HealthResponse = response.into_json()?;
    Ok(health)
}

#[derive(Debug, Deserialize, Serialize)]
struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub peer_count: usize,
    pub self_alias: String,
    pub self_did: String,
}
