use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::Confirm;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use time::OffsetDateTime;

use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::policy::{
    GateMode, PolicyDecision, PolicyDocument, PolicyEvaluator, PolicyGate, PolicyStore,
};

#[derive(Parser, Debug)]
#[command(
    name = "hn policy",
    author = "Human.Net",
    version,
    about = "Inspect and update local consent policy."
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

    #[arg(short = 'y', long = "yes", global = true)]
    assume_yes: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print the active policy document.
    Get,
    /// Apply one or more changes to the policy document.
    Patch {
        /// Update the spend cap (maps to gate `spend.max_eur`).
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,

        /// Update a gate mode: `gate=allow|deny|prompt`.
        #[arg(long = "mode", value_name = "GATE=MODE")]
        mode: Vec<String>,

        /// Override a gate condition rule expression: `gate=expr`.
        #[arg(long = "condition", value_name = "GATE=RULE")]
        condition: Vec<String>,

        /// Set or update a gate banner message: `gate=text`.
        #[arg(long = "banner", value_name = "GATE=MESSAGE")]
        banner: Vec<String>,

        /// Clear an existing gate banner.
        #[arg(long = "clear-banner", value_name = "GATE")]
        clear_banner: Vec<String>,

        /// Enable auditing for the specified gate.
        #[arg(long = "audit", value_name = "GATE")]
        audit: Vec<String>,

        /// Disable auditing for the specified gate.
        #[arg(long = "no-audit", value_name = "GATE")]
        no_audit: Vec<String>,
    },
    /// Evaluate whether a doc write would be allowed.
    EvaluateDoc {
        /// Doc type identifier (e.g. folder@1).
        #[arg(long = "type", value_name = "TYPE")]
        doc_type: String,

        /// Path to the doc JSON payload.
        #[arg(long = "file", value_name = "PATH")]
        file: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ModeSetting {
    Allow,
    Deny,
    Prompt,
}

impl From<ModeSetting> for GateMode {
    fn from(value: ModeSetting) -> Self {
        match value {
            ModeSetting::Allow => GateMode::Allow,
            ModeSetting::Deny => GateMode::Deny,
            ModeSetting::Prompt => GateMode::Prompt,
        }
    }
}

struct CommandContext {
    output: OutputFormat,
    dry_run: bool,
    assume_yes: bool,
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
        assume_yes: cli.assume_yes,
    };

    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let store = PolicyStore::new(&vault)?;

    let output = match cli.command {
        Commands::Get => handle_get(&ctx, &store),
        Commands::Patch {
            set,
            mode,
            condition,
            banner,
            clear_banner,
            audit,
            no_audit,
        } => handle_patch(
            &ctx,
            &store,
            &vault,
            &set,
            &mode,
            &condition,
            &banner,
            &clear_banner,
            &audit,
            &no_audit,
        ),
        Commands::EvaluateDoc { doc_type, file } => {
            handle_evaluate_doc(&ctx, &vault, &store, doc_type, file)
        }
    }?;

    output.render(ctx.output)?;
    Ok(())
}

fn handle_get(ctx: &CommandContext, store: &PolicyStore) -> Result<CommandOutput> {
    let policy = store.load()?;
    let value = serde_json::to_value(&policy)?;
    Ok(CommandOutput::new(
        "Current policy document",
        json!({
            "command": "get",
            "mode": ctx.read_mode(),
            "policy": value,
        }),
    ))
}

fn handle_patch(
    ctx: &CommandContext,
    store: &PolicyStore,
    vault: &IdentityVault,
    set: &[String],
    mode: &[String],
    condition: &[String],
    banner: &[String],
    clear_banner: &[String],
    audit: &[String],
    no_audit: &[String],
) -> Result<CommandOutput> {
    let mut policy = store.load()?;
    let mut changes: Vec<String> = Vec::new();

    for entry in set {
        apply_set(entry, &mut policy, &mut changes)?;
    }

    for entry in mode {
        let (gate, mode) = parse_key_value(entry)?;
        let mode_value = parse_mode(&mode)?;
        ensure_gate(&mut policy, &gate).mode = mode_value.into();
        changes.push(format!("gate '{}' mode -> {:?}", gate, mode_value));
    }

    for entry in condition {
        let (gate, rule) = parse_key_value(entry)?;
        ensure_gate(&mut policy, &gate).conditions = Some(rule.clone());
        changes.push(format!("gate '{}' condition -> {}", gate, rule));
    }

    for entry in banner {
        let (gate, text) = parse_key_value(entry)?;
        ensure_gate(&mut policy, &gate).banner = Some(text.clone());
        policy.banners.insert(gate.clone(), text.clone());
        changes.push(format!("gate '{}' banner -> set", gate));
    }

    for gate in clear_banner {
        let gate = gate.trim();
        ensure_gate(&mut policy, gate).banner = None;
        policy.banners.remove(gate);
        changes.push(format!("gate '{}' banner -> cleared", gate));
    }

    for gate in audit {
        let gate = gate.trim();
        ensure_gate(&mut policy, gate).audit = true;
        changes.push(format!("gate '{}' audit -> true", gate));
    }

    for gate in no_audit {
        let gate = gate.trim();
        ensure_gate(&mut policy, gate).audit = false;
        changes.push(format!("gate '{}' audit -> false", gate));
    }

    if changes.is_empty() {
        return Ok(CommandOutput::new(
            "No changes to apply",
            json!({
                "command": "patch",
                "mode": ctx.read_mode(),
                "changes": [],
                "policy": serde_json::to_value(&policy)?,
            }),
        ));
    }

    if ctx.dry_run {
        return Ok(CommandOutput::new(
            format!("Dry-run: would apply {} change(s)", changes.len()),
            json!({
                "command": "patch",
                "mode": "dry_run",
                "changes": changes,
                "policy": serde_json::to_value(&policy)?,
            }),
        ));
    }

    ensure_confirmation(ctx, "Apply policy changes?")?;

    let previous_version = policy.version;
    policy.version = policy.version.saturating_add(1);
    policy.last_applied = OffsetDateTime::now_utc();
    policy.applied_by = vault.active_identity()?.map(|active| active.did);

    store.save(&policy)?;

    Ok(CommandOutput::new(
        format!("Applied {} policy change(s)", changes.len()),
        json!({
            "command": "patch",
            "mode": "execute",
            "changes": changes,
            "policy": serde_json::to_value(&policy)?,
            "previous_version": previous_version,
            "new_version": policy.version,
        }),
    ))
}

fn handle_evaluate_doc(
    ctx: &CommandContext,
    vault: &IdentityVault,
    store: &PolicyStore,
    doc_type: String,
    file: Option<PathBuf>,
) -> Result<CommandOutput> {
    let content = if let Some(path) = file {
        let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?
    } else {
        serde_json::json!({})
    };

    let decision = PolicyEvaluator::doc_write_decision(vault, store.alias(), &doc_type, &content)?;
    let payload = json!({
        "command": "evaluate_doc",
        "mode": ctx.read_mode(),
        "doc_type": doc_type,
        "decision": match &decision {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny(_) => "deny",
        },
        "reason": match &decision {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny(reason) => Some(reason.clone()),
        },
    });

    let message = match decision {
        PolicyDecision::Allow => "doc.write allowed".to_string(),
        PolicyDecision::Deny(reason) => format!("doc.write denied: {reason}"),
    };

    Ok(CommandOutput::new(message, payload))
}

fn apply_set(entry: &str, policy: &mut PolicyDocument, changes: &mut Vec<String>) -> Result<()> {
    let (key, value) = parse_key_value(entry)?;
    match key.as_str() {
        "max_spend_eur" => {
            let limit: f64 = value
                .parse()
                .map_err(|_| anyhow!("invalid numeric value for max_spend_eur: {}", value))?;
            let gate = ensure_gate(policy, "spend.max_eur");
            gate.conditions = Some(format!("value <= {}", limit));
            gate.mode = GateMode::Prompt;
            changes.push(format!("spend.max_eur condition -> value <= {}", limit));
        }
        other => {
            bail!("unsupported --set key '{}'; expected max_spend_eur", other);
        }
    }
    Ok(())
}

fn parse_key_value(input: &str) -> Result<(String, String)> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| anyhow!("invalid argument '{}'; expected key=value", input))?;
    let key = key.trim();
    if key.is_empty() {
        bail!("key cannot be empty in '{}'", input);
    }
    Ok((key.to_string(), value.trim().to_string()))
}

fn parse_mode(value: &str) -> Result<ModeSetting> {
    ModeSetting::from_str(value, true).map_err(|err| anyhow!("{}", err))
}

fn ensure_gate<'a>(policy: &'a mut PolicyDocument, gate: &str) -> &'a mut PolicyGate {
    policy
        .gates
        .entry(gate.to_string())
        .or_insert_with(hn_cli::policy::PolicyGate::default)
}

fn ensure_confirmation(ctx: &CommandContext, prompt: &str) -> Result<()> {
    if ctx.dry_run || ctx.assume_yes {
        return Ok(());
    }
    let confirmed = Confirm::new().with_prompt(prompt).interact()?;
    if confirmed {
        Ok(())
    } else {
        bail!("operation aborted by user")
    }
}
