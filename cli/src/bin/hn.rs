use std::env;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const SUBCOMMANDS: &[&str] = &[
    "id", "doc", "service", "peer", "policy", "view", "contract", "event", "gc", "shard", "state",
    "smoke", "audit", "mcp",
];

fn main() {
    let mut args = env::args().skip(1);
    let Some(subcommand) = args.next() else {
        print_usage();
        exit(1);
    };

    if subcommand == "-h" || subcommand == "--help" || subcommand == "help" {
        print_usage();
        exit(0);
    }

    if subcommand == "--version" || subcommand == "-V" {
        println!("hn {}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    if !SUBCOMMANDS.contains(&subcommand.as_str()) {
        eprintln!("unknown subcommand '{subcommand}'\n");
        print_usage();
        exit(1);
    }

    let binary = match resolve_binary(&subcommand) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            exit(1);
        }
    };

    let status = Command::new(&binary)
        .args(args)
        .status()
        .unwrap_or_else(|err| {
            eprintln!("failed to execute '{}': {err}", binary.display());
            exit(1);
        });

    let code = status.code().unwrap_or(1);
    exit(code);
}

fn print_usage() {
    eprintln!("Usage: hn <subcommand> [args]\n");
    eprintln!("Available subcommands:");
    for cmd in SUBCOMMANDS {
        eprintln!("  {cmd}");
    }
    eprintln!("\nRun 'hn <subcommand> --help' for details.");
}

fn resolve_binary(subcommand: &str) -> Result<PathBuf, String> {
    if let Ok(custom) = env::var("HN_BIN_DIR") {
        let candidate = Path::new(&custom).join(bin_name(subcommand));
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let current =
        env::current_exe().map_err(|err| format!("failed to resolve executable: {err}"))?;
    if let Some(dir) = current.parent() {
        let candidate = dir.join(bin_name(subcommand));
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "could not locate binary '{}' (build the project with `cargo build --bins` or set HN_BIN_DIR)",
        subcommand
    ))
}

fn bin_name(subcommand: &str) -> String {
    if cfg!(windows) {
        format!("{subcommand}.exe")
    } else {
        subcommand.to_string()
    }
}
