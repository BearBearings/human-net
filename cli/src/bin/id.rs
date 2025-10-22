use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::Confirm;
use rpassword::prompt_password;
use serde_json::{json, Value};

type EndpointsMap = HashMap<String, Value>;

use hn_cli::home::ensure_home_dir;
use hn_cli::identity::{
    BuiltinVerifier, IdentityBundle, IdentityVault, IdentityVerificationEntry, VerificationRequest,
    VerificationResult,
};
use hn_cli::output::{CommandOutput, OutputFormat};
use time::{Duration, OffsetDateTime};

#[derive(Parser, Debug)]
#[command(
    name = "hn id",
    author = "Human.Net",
    version,
    about = "Manage local Human.Net identities (L1–L3)."
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
    /// Create a new DID and associated profile.
    Create {
        /// Alias used to reference the identity locally.
        alias: String,

        /// Capability entries to attach to the profile (repeatable).
        #[arg(long = "capability", value_name = "NAME")]
        capabilities: Vec<String>,

        /// Endpoint entries in the form `name=url` (repeatable).
        #[arg(long = "endpoint", value_name = "KEY=VALUE")]
        endpoints: Vec<String>,
    },
    /// Mark an existing identity as the active one.
    Use {
        /// Alias or DID to activate.
        target: String,
    },
    /// Retrieve details for a specific identity.
    Get {
        /// Alias or DID to inspect (defaults to active identity).
        #[arg(value_name = "ALIAS|DID")]
        target: Option<String>,

        /// Include credential stub metadata.
        #[arg(long)]
        with_credentials: bool,
    },
    /// List all stored identities.
    List {
        /// Include inactive identities.
        #[arg(long)]
        include_archived: bool,
    },
    /// Verify DID document integrity and refresh L2 credentials.
    Verify {
        /// Alias or DID (defaults to active identity).
        #[arg(value_name = "ALIAS|DID")]
        target: Option<String>,

        /// Verification provider to use (mock-entra, mock-didkit).
        #[arg(long, value_name = "NAME", default_value = "mock-entra")]
        provider: String,

        /// Force re-fetch even if cache is still fresh.
        #[arg(long)]
        force: bool,

        /// Skip remote provider call; run integrity checks only.
        #[arg(long)]
        skip_credentials: bool,
    },
    /// Show verification cache status.
    Status {
        /// Alias or DID (defaults to active identity).
        #[arg(value_name = "ALIAS|DID")]
        target: Option<String>,

        /// Limit to a specific verification provider.
        #[arg(long, value_name = "NAME")]
        provider: Option<String>,
    },
    /// Export an identity bundle that can be recovered elsewhere.
    Export {
        /// Alias or DID to export.
        target: String,

        /// Output file path; stdout if omitted.
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<PathBuf>,

        /// Passphrase used to encrypt the export bundle.
        #[arg(long = "password", value_name = "PASS")]
        password: Option<String>,
    },
    /// Recover an identity bundle into the local vault.
    Recover {
        /// Path to the exported bundle file.
        bundle: PathBuf,

        /// Override alias during recovery.
        #[arg(long = "alias", value_name = "ALIAS")]
        alias: Option<String>,

        /// Passphrase used to decrypt the bundle.
        #[arg(long = "password", value_name = "PASS")]
        password: Option<String>,
    },
    /// Delete an identity from the local vault.
    Delete {
        /// Alias or DID to remove (omit when using --all).
        #[arg(value_name = "ALIAS|DID", conflicts_with = "all")]
        target: Option<String>,

        /// Remove every identity.
        #[arg(long = "all")]
        all: bool,

        /// Also delete the node home directory.
        #[arg(long = "purge-node")]
        purge_node: bool,
    },
}

struct CommandContext {
    output: OutputFormat,
    dry_run: bool,
    assume_yes: bool,
}

impl CommandContext {
    fn result_mode(&self) -> ExecutionMode {
        if self.dry_run {
            ExecutionMode::DryRun
        } else {
            ExecutionMode::Execute
        }
    }

    fn read_mode(&self) -> &'static str {
        if self.dry_run {
            "dry_run"
        } else {
            "execute"
        }
    }
}

#[derive(Copy, Clone)]
enum ExecutionMode {
    DryRun,
    Execute,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = CommandContext {
        output: cli.output,
        dry_run: cli.dry_run,
        assume_yes: cli.assume_yes,
    };

    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home)?;

    let output = match cli.command {
        Commands::Create {
            alias,
            capabilities,
            endpoints,
        } => handle_create(&ctx, &vault, alias, capabilities, endpoints),
        Commands::Use { target } => handle_use(&ctx, &vault, target),
        Commands::Get {
            target,
            with_credentials,
        } => handle_get(&ctx, &vault, target, with_credentials),
        Commands::List { include_archived } => handle_list(&ctx, &vault, include_archived),
        Commands::Verify {
            target,
            provider,
            force,
            skip_credentials,
        } => handle_verify(&ctx, &vault, target, provider, force, skip_credentials),
        Commands::Status { target, provider } => handle_status(&ctx, &vault, target, provider),
        Commands::Export {
            target,
            file,
            password,
        } => handle_export(&ctx, &vault, target, file, password),
        Commands::Recover {
            bundle,
            alias,
            password,
        } => handle_recover(&ctx, &vault, bundle, alias, password),
        Commands::Delete {
            target,
            all,
            purge_node,
        } => handle_delete(&ctx, &vault, target, all, purge_node),
    }?;

    output.render(ctx.output)?;
    Ok(())
}

fn handle_create(
    ctx: &CommandContext,
    vault: &IdentityVault,
    alias: String,
    capabilities: Vec<String>,
    endpoints_raw: Vec<String>,
) -> Result<CommandOutput> {
    let endpoints = parse_endpoints(&endpoints_raw)?;
    let record = if ctx.dry_run {
        vault.prepare_identity(&alias, capabilities.clone(), endpoints.clone())?
    } else {
        ensure_confirmation(ctx, &format!("Create identity '{alias}'?"))?;
        vault.create_identity(&alias, capabilities.clone(), endpoints.clone())?
    };

    let mode = ctx.result_mode();
    let message = match mode {
        ExecutionMode::DryRun => {
            format!("Dry-run: would create identity '{}'", record.profile.alias)
        }
        ExecutionMode::Execute => format!("Created identity '{}'", record.profile.alias),
    };
    Ok(CommandOutput::new(
        message,
        json!({
            "command": "create",
            "mode": mode.as_str(),
            "identity": {
                "alias": record.profile.alias,
                "did": record.profile.id,
                "capabilities": record.profile.capabilities,
                "endpoints": record.profile.endpoints,
            }
        }),
    ))
}

fn handle_use(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: String,
) -> Result<CommandOutput> {
    let alias = resolve_alias(vault, &target)?;

    if ctx.dry_run {
        return Ok(CommandOutput::new(
            format!("Dry-run: would activate identity '{alias}'"),
            json!({
                "command": "use",
                "mode": "dry_run",
                "alias": alias,
            }),
        ));
    }
    vault.set_active_identity(&alias)?;
    Ok(CommandOutput::new(
        format!("Activated identity '{alias}'"),
        json!({
            "command": "use",
            "mode": "execute",
            "alias": alias,
        }),
    ))
}

fn handle_get(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: Option<String>,
    with_credentials: bool,
) -> Result<CommandOutput> {
    let alias = match target {
        Some(target) => resolve_alias(vault, &target)?,
        None => vault
            .active_identity()?
            .map(|active| active.alias)
            .context("no active identity; specify an alias or DID")?,
    };
    let record = vault.load_identity(&alias)?;

    let mut identity_value = json!({
        "alias": record.profile.alias,
        "did": record.profile.id,
        "capabilities": record.profile.capabilities,
        "endpoints": record.profile.endpoints,
        "created_at": record.profile.created_at,
        "updated_at": record.profile.updated_at,
    });
    if let Some(obj) = identity_value.as_object_mut() {
        obj.insert(
            "hpke".into(),
            json!({
                "public_key": record.keys.hpke_public_key_base64(),
                "suite": "X25519HkdfSha256",
            }),
        );
    }
    if with_credentials {
        if let Some(obj) = identity_value.as_object_mut() {
            obj.insert(
                "verification".into(),
                serde_json::to_value(&record.profile.verification)?,
            );
        }
    }

    Ok(CommandOutput::new(
        format!("Identity '{alias}'"),
        json!({
            "command": "get",
            "mode": ctx.read_mode(),
            "identity": identity_value,
            "with_credentials": with_credentials,
        }),
    ))
}

fn handle_list(
    ctx: &CommandContext,
    vault: &IdentityVault,
    _include_archived: bool,
) -> Result<CommandOutput> {
    let entries = vault.list_identities()?;
    if ctx.output == OutputFormat::Text {
        for entry in &entries {
            let marker = if entry.active { "*" } else { "-" };
            println!("{} {} ({})", marker, entry.alias, entry.did);
        }
    }
    let payload = entries
        .iter()
        .map(|entry| {
            json!({
                "alias": entry.alias,
                "did": entry.did,
                "updated_at": entry.updated_at,
                "active": entry.active,
            })
        })
        .collect::<Vec<_>>();

    Ok(CommandOutput::new(
        format!("{} identities found", entries.len()),
        json!({
            "command": "list",
            "mode": ctx.read_mode(),
            "identities": payload,
        }),
    ))
}

fn handle_verify(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: Option<String>,
    provider: String,
    force: bool,
    skip_credentials: bool,
) -> Result<CommandOutput> {
    let alias = match target {
        Some(target) => resolve_alias(vault, &target)?,
        None => vault
            .active_identity()?
            .map(|active| active.alias)
            .context("no active identity; specify an alias or DID")?,
    };
    let mut record = vault.load_identity(&alias)?;

    let computed_did = record.keys.did();
    let doc_did_match = record.did_document.id == computed_did;
    let profile_did_match = record.profile.id == computed_did;
    let canonical = record.did_document.canonical_hash()?;
    let stored_hash = record.canonical_hash.clone();
    let canonical_match = stored_hash.as_deref() == Some(canonical.as_str());

    let provider_trimmed = provider.trim().to_string();
    let refresh_window = Duration::hours(6);
    let refresh_hint = record.profile.verification.needs_refresh(
        &provider_trimmed,
        OffsetDateTime::now_utc(),
        refresh_window,
    );

    let (verification_details, message) = if skip_credentials {
        let detail = json!({
            "skipped": true,
            "requested_provider": provider_trimmed,
            "force": force,
            "refresh_window_seconds": refresh_window.whole_seconds(),
            "refresh_needed": refresh_hint,
            "dry_run": ctx.dry_run,
        });
        (
            detail,
            format!("Integrity check for '{alias}' (provider skipped)"),
        )
    } else {
        let builtin = BuiltinVerifier::from_str(&provider_trimmed).with_context(|| {
            let supported = BuiltinVerifier::all()
                .iter()
                .map(|candidate| candidate.name())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "unknown verification provider '{}'; available: {}",
                provider_trimmed, supported
            )
        })?;
        let verifier = builtin.build();
        let existing_entry = record.profile.verification.entry(builtin.name()).cloned();
        let request =
            VerificationRequest::new(record.profile.alias.clone(), record.profile.id.clone())
                .with_existing(existing_entry.clone())
                .force_refresh(force);
        let VerificationResult {
            entry,
            proof,
            refreshed,
        } = verifier.verify(&request)?;
        let persisted = !ctx.dry_run && refreshed;
        if persisted {
            vault.record_verification(&mut record, entry.clone(), proof.clone())?;
        }
        let mut detail = serde_json::to_value(&entry)?;
        if let Some(obj) = detail.as_object_mut() {
            obj.insert("requested_provider".into(), json!(provider_trimmed));
            obj.insert("refreshed".into(), json!(refreshed));
            obj.insert("persisted".into(), json!(persisted));
            obj.insert("force".into(), json!(force));
            obj.insert("dry_run".into(), json!(ctx.dry_run));
            obj.insert(
                "refresh_window_seconds".into(),
                json!(refresh_window.whole_seconds()),
            );
            obj.insert("refresh_needed".into(), json!(refresh_hint));
            if let Some(existing) = existing_entry {
                obj.insert("existing_entry".into(), serde_json::to_value(existing)?);
            }
            if let Some(proof) = proof.as_ref() {
                obj.insert("proof_summary".into(), proof.summary());
            }
        }

        let provider_display = entry.provider.clone();
        let msg = if ctx.dry_run {
            if refreshed {
                format!(
                    "Dry-run: would verify '{}' via {} and store credential",
                    alias, provider_display
                )
            } else {
                format!(
                    "Dry-run: verification cache still valid for '{}' via {}",
                    alias, provider_display
                )
            }
        } else if refreshed {
            format!("Verified '{}' via {}", alias, provider_display)
        } else {
            format!(
                "Verification cache still valid for '{}' via {}",
                alias, provider_display
            )
        };
        (detail, msg)
    };

    let payload = json!({
        "command": "verify",
        "mode": ctx.read_mode(),
        "alias": alias,
        "checks": {
            "did_document_match": doc_did_match,
            "profile_did_match": profile_did_match,
            "canonical_hash_match": canonical_match,
            "provider_invoked": !skip_credentials,
        },
        "verification": verification_details,
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_status(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: Option<String>,
    provider_filter: Option<String>,
) -> Result<CommandOutput> {
    let alias = match target {
        Some(target) => resolve_alias(vault, &target)?,
        None => vault
            .active_identity()?
            .map(|active| active.alias)
            .context("no active identity; specify an alias or DID")?,
    };
    let record = vault.load_identity(&alias)?;
    let ledger = &record.profile.verification;
    let policy_facts = ledger.to_policy_facts();
    let filtered_policy_facts: Vec<_> = policy_facts
        .iter()
        .filter(|fact| {
            provider_filter
                .as_ref()
                .map(|p| fact.provider.eq_ignore_ascii_case(p))
                .unwrap_or(true)
        })
        .cloned()
        .collect();

    let entries: Vec<&IdentityVerificationEntry> = match provider_filter.as_ref() {
        Some(filter) => ledger
            .entries
            .iter()
            .filter(|entry| entry.provider.eq_ignore_ascii_case(filter))
            .collect(),
        None => ledger.entries.iter().collect(),
    };

    if ctx.output == OutputFormat::Text {
        if entries.is_empty() {
            println!("No verification entries recorded.");
        } else {
            for entry in &entries {
                println!(
                    "{} -> {} (verified {})",
                    entry.provider, entry.issuer, entry.verified_at
                );
                println!("  proof {} ({})", entry.proof_id, entry.format);
                if let Some(exp) = entry.expires_at {
                    println!("  expires {}", exp);
                }
            }
            if !filtered_policy_facts.is_empty() {
                println!("Policy facts:");
                for fact in &filtered_policy_facts {
                    println!(
                        "  {} -> {} (valid_until: {:?})",
                        fact.provider, fact.proof_id, fact.valid_until
                    );
                }
            }
        }
    }

    let list = entries
        .iter()
        .map(|entry| {
            json!({
                "provider": entry.provider,
                "issuer": entry.issuer,
                "proof_id": entry.proof_id,
                "format": entry.format,
                "verified_at": entry.verified_at,
                "expires_at": entry.expires_at,
            })
        })
        .collect::<Vec<_>>();

    let message = if entries.is_empty() {
        if let Some(filter) = provider_filter.as_ref() {
            format!(
                "No verification entries found for '{}' using provider '{}'",
                alias, filter
            )
        } else {
            format!("No verification entries found for '{}'", alias)
        }
    } else {
        let label = if entries.len() == 1 {
            "entry"
        } else {
            "entries"
        };
        format!(
            "Verification status for '{}' ({} {})",
            alias,
            entries.len(),
            label
        )
    };

    let mut payload = json!({
        "command": "status",
        "mode": ctx.read_mode(),
        "alias": alias,
        "provider_filter": provider_filter,
        "entries": list,
        "policy_facts": filtered_policy_facts,
        "all_policy_facts": policy_facts,
    });

    if let Some(last) = ledger.last_refreshed_at {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("last_refreshed_at".into(), json!(last));
        }
    }

    Ok(CommandOutput::new(message, payload))
}

fn handle_export(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: String,
    file: Option<PathBuf>,
    password: Option<String>,
) -> Result<CommandOutput> {
    let alias = resolve_alias(vault, &target)?;
    let record = vault.load_identity(&alias)?;
    let passphrase = if ctx.dry_run {
        password.unwrap_or_else(|| "dry-run-placeholder".to_string())
    } else {
        read_passphrase(password, true)?
    };
    let bundle = IdentityBundle::from_identity(&record, &passphrase)?;

    let file_string = file.as_ref().map(|p| p.display().to_string());

    if ctx.dry_run {
        return Ok(CommandOutput::new(
            format!("Dry-run: would export identity '{alias}'"),
            json!({
                "command": "export",
                "mode": "dry_run",
                "alias": alias,
                "output": file_string,
            }),
        ));
    }

    ensure_confirmation(ctx, &format!("Export identity '{alias}'?"))?;
    if let Some(path) = file.as_ref() {
        if path.exists() && !ctx.assume_yes {
            ensure_confirmation(
                ctx,
                &format!("File '{}' exists. Overwrite?", path.display()),
            )?;
        }
        bundle.write_to_path(path)?;
        return Ok(CommandOutput::new(
            format!("Exported identity '{alias}' to {}", path.display()),
            json!({
                "command": "export",
                "mode": "execute",
                "alias": alias,
                "file": path.display().to_string(),
            }),
        ));
    }

    let rendered = bundle.to_pretty_json()?;
    let bundle_json: Value = serde_json::from_str(&rendered)?;
    Ok(CommandOutput::new(
        format!("Exported identity '{alias}' bundle:\n{rendered}"),
        json!({
            "command": "export",
            "mode": "execute",
            "alias": alias,
            "file": null,
            "bundle": bundle_json,
        }),
    ))
}

fn handle_recover(
    ctx: &CommandContext,
    vault: &IdentityVault,
    bundle_path: PathBuf,
    alias_override: Option<String>,
    password: Option<String>,
) -> Result<CommandOutput> {
    let bundle = IdentityBundle::from_path(&bundle_path)?;
    let passphrase = if ctx.dry_run {
        password.unwrap_or_else(|| "dry-run-placeholder".to_string())
    } else {
        read_passphrase(password, false)?
    };
    let secret = bundle.decrypt_secret(&passphrase)?;
    let alias = alias_override
        .clone()
        .unwrap_or_else(|| bundle.profile.alias.clone());

    if ctx.dry_run {
        vault.prepare_import_identity(&bundle, secret, alias_override.as_deref())?;
        return Ok(CommandOutput::new(
            format!("Dry-run: would recover identity '{alias}'"),
            json!({
                "command": "recover",
                "mode": "dry_run",
                "alias": alias,
            }),
        ));
    }

    ensure_confirmation(ctx, &format!("Recover identity '{alias}'?"))?;
    let record = vault.import_identity(&bundle, secret, alias_override.as_deref())?;
    Ok(CommandOutput::new(
        format!("Recovered identity '{}'", record.profile.alias),
        json!({
            "command": "recover",
            "mode": "execute",
            "alias": record.profile.alias,
            "did": record.profile.id,
        }),
    ))
}

fn parse_endpoints(entries: &[String]) -> Result<EndpointsMap> {
    let mut map = HashMap::new();
    for entry in entries {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid endpoint '{}'; expected key=value", entry))?;
        let key = key.trim();
        if key.is_empty() {
            bail!("endpoint key cannot be empty");
        }
        map.insert(key.to_string(), Value::String(value.trim().to_string()));
    }
    Ok(map)
}

fn resolve_alias(vault: &IdentityVault, target: &str) -> Result<String> {
    if target.starts_with("did:") {
        if let Some(alias) = vault.alias_for_did(target)? {
            return Ok(alias);
        }
        bail!("no identity found for DID {target}");
    }
    if vault.alias_exists(target)? {
        Ok(target.to_string())
    } else {
        bail!("identity '{target}' not found")
    }
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

fn read_passphrase(option: Option<String>, confirm: bool) -> Result<String> {
    if let Some(pass) = option {
        return Ok(pass);
    }
    let first = prompt_password("Passphrase: ")?;
    if confirm {
        let second = prompt_password("Confirm passphrase: ")?;
        if first != second {
            bail!("passphrase confirmation mismatch");
        }
    }
    Ok(first)
}

fn handle_delete(
    ctx: &CommandContext,
    vault: &IdentityVault,
    target: Option<String>,
    all: bool,
    purge_node: bool,
) -> Result<CommandOutput> {
    if ctx.dry_run {
        return Ok(CommandOutput::new(
            "Dry-run: would delete identity",
            json!({
                "command": "delete",
                "mode": "dry_run",
                "target": target,
                "all": all,
            }),
        ));
    }

    if all {
        let identities = vault.list_identities()?;
        if identities.is_empty() {
            return Ok(CommandOutput::new(
                "No identities to delete",
                json!({
                    "command": "delete",
                    "mode": ctx.read_mode(),
                    "deleted": [],
                }),
            ));
        }

        let aliases = identities
            .iter()
            .map(|entry| entry.alias.clone())
            .collect::<Vec<_>>();
        for alias in &aliases {
            vault.delete_identity(alias, purge_node)?;
        }
        return Ok(CommandOutput::new(
            format!("Deleted {} identities", aliases.len()),
            json!({
                "command": "delete",
                "mode": ctx.read_mode(),
                "deleted": aliases,
                "purge_node": purge_node,
            }),
        ));
    }

    let target = target.ok_or_else(|| anyhow!("must supply an identity to delete"))?;
    let alias = resolve_alias(vault, &target)?;
    vault.delete_identity(&alias, purge_node)?;

    Ok(CommandOutput::new(
        format!("Deleted identity '{alias}'"),
        json!({
            "command": "delete",
            "mode": ctx.read_mode(),
            "deleted": [alias],
            "purge_node": purge_node,
        }),
    ))
}

impl ExecutionMode {
    fn as_str(&self) -> &'static str {
        match self {
            ExecutionMode::DryRun => "dry_run",
            ExecutionMode::Execute => "execute",
        }
    }
}
