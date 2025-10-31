use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use hn_cli::discovery::dht::{build_presence_url, store_hint, suggested_dns_record, to_json};
use hn_cli::discovery::{
    fetch_dht_hint, fetch_presence, fetch_presence_with_retry, generate_presence_doc,
    load_presence_docs, load_presence_hints, publish_dht_hint, resolve_presence_endpoint,
    save_presence_doc, save_presence_hint, PresenceDoc, PresenceRelay,
};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use serde_json::json;
use time::OffsetDateTime;

#[derive(Parser, Debug)]
#[command(
    name = "hn discover",
    author = "Human.Net",
    version,
    about = "Manage WAN discovery and presence hints."
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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Publish a signed presence@2 document for this vault.
    Publish(PublishArgs),
    /// List stored presence documents (local or remote hints).
    List(ListArgs),
    /// Import a remote presence document (hint) from disk.
    Import(ImportArgs),
    /// Refresh a remote presence@2 document via HTTP and cache the hint.
    Refresh(RefreshArgs),
    /// Resolve a peer via DHT/DNS and fetch its presence.
    Resolve(ResolveArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Publish(args) => handle_publish(args)?,
        Commands::List(args) => handle_list(args)?,
        Commands::Import(args) => handle_import(args)?,
        Commands::Refresh(args) => handle_refresh(args)?,
        Commands::Resolve(args) => handle_resolve(args)?,
    };
    output.render(cli.output)?;
    Ok(())
}

#[derive(Args, Debug)]
struct PublishArgs {
    /// Alias whose identity should sign the presence document (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Current index Merkle root for this vault (e.g. from `hn shard publish`).
    #[arg(long = "merkle-root", value_name = "HASH")]
    merkle_root: String,

    /// Optional Merkle proof blob (base64).
    #[arg(long = "proof", value_name = "BASE64")]
    proof: Option<String>,

    /// Endpoint entries `name=url` (repeatable).
    #[arg(long = "endpoint", value_name = "KEY=URL", num_args = 0.., action = clap::ArgAction::Append)]
    endpoints: Vec<String>,

    /// Relay entries `host=url[@RFC3339]` (repeatable).
    #[arg(long = "relay", value_name = "HOST=URL[@RFC3339]", num_args = 0.., action = clap::ArgAction::Append)]
    relays: Vec<String>,

    /// TTL in seconds (default 600).
    #[arg(long = "ttl-seconds", default_value_t = 600)]
    ttl_seconds: u64,

    /// Also publish a DHT hint referencing the latest presence document.
    #[arg(long = "dht")]
    publish_dht: bool,

    /// Print the suggested DNS TXT record when --dht is used.
    #[arg(long = "dns-txt", requires = "publish_dht")]
    dns_txt: bool,

    /// Override presence URL stored in the DHT hint.
    #[arg(long = "presence-url", value_name = "URL")]
    presence_url: Option<String>,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Alias whose local presence docs should be listed.
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// List cached hints (remote peers) instead of local publications.
    #[arg(long = "hints")]
    hints: bool,
}

#[derive(Args, Debug)]
struct ImportArgs {
    /// Path to a presence@2 JSON document.
    #[arg(long = "file", value_name = "PATH")]
    file: PathBuf,
}

#[derive(Args, Debug)]
struct RefreshArgs {
    /// DID whose presence should be fetched.
    #[arg(long = "did", value_name = "DID")]
    did: String,

    /// Explicit URL to fetch presence from (overrides cached endpoints).
    #[arg(long = "url", value_name = "URL")]
    url: Option<String>,

    /// Endpoint key to look up in cached presence docs when --url is omitted.
    #[arg(long = "endpoint", default_value = "presence")]
    endpoint: String,
}

#[derive(Args, Debug)]
struct ResolveArgs {
    /// DID whose presence should be resolved via DHT/DNS.
    #[arg(value_name = "DID")]
    did: String,

    /// Skip DHT resolution (DNS only).
    #[arg(long = "no-dht")]
    no_dht: bool,

    /// Hint lookup only (do not fetch presence document).
    #[arg(long = "hint-only")]
    hint_only: bool,

    /// Fall back to cached presence docs when HTTP fetch fails.
    #[arg(long = "cache-fallback")]
    cache_fallback: bool,
}

fn handle_publish(args: PublishArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = match args.alias {
        Some(alias) => alias,
        None => {
            vault
                .active_identity()?
                .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
                .alias
        }
    };

    let endpoints = parse_endpoints(args.endpoints)?;
    let relays = parse_relays(args.relays)?;
    let doc = generate_presence_doc(
        &vault,
        &alias,
        endpoints.clone(),
        args.merkle_root.clone(),
        args.proof.clone(),
        relays,
        Duration::from_secs(args.ttl_seconds.max(60)),
    )?;
    let path = save_presence_doc(&home, &alias, &doc)?;

    let mut payload = json!({
        "command": "discover.publish",
        "alias": alias,
        "path": path,
        "presence": &doc,
    });
    let mut message_lines = vec![format!("Published presence document {}", doc.id)];
    let mut dns_txt_payload: Option<serde_json::Value> = None;

    if args.publish_dht {
        let presence_url = build_presence_url(&doc, args.presence_url.clone())?;
        match publish_dht_hint(&doc, Some(presence_url.clone())) {
            Ok(Some(hint)) => {
                let hint_path = store_hint(&home, &hint)?;
                let mut dht_payload = json!({
                    "hint": to_json(&hint),
                    "hint_path": hint_path.to_string_lossy(),
                    "presence_url": presence_url,
                });
                if let Some((name, value)) = suggested_dns_record(&hint.did, &presence_url) {
                    let record = json!({ "name": name, "value": value });
                    dht_payload["dns_txt"] = record.clone();
                    dns_txt_payload = Some(record);
                    if args.dns_txt {
                        message_lines.push(format!("Add DNS TXT record: {} {}", name, value));
                    }
                }
                payload["dht"] = dht_payload;
                message_lines.push("DHT hint stored.".to_string());
            }
            Ok(None) => {}
            Err(err) => {
                return Err(anyhow!("failed to publish DHT hint: {err}"));
            }
        }
    }

    if args.dns_txt && dns_txt_payload.is_none() {
        message_lines.push("No DNS TXT record could be derived from the presence URL".to_string());
    }

    let message = message_lines.join("\n");

    Ok(CommandOutput::new(message, payload))
}

fn handle_list(args: ListArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let docs = if args.hints {
        load_presence_hints(&home)?
    } else {
        let vault = IdentityVault::new(home.clone())?;
        let alias = match args.alias {
            Some(alias) => alias,
            None => {
                vault
                    .active_identity()?
                    .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
                    .alias
            }
        };
        load_presence_docs(&home, &alias)?
    };

    let message = if docs.is_empty() {
        if args.hints {
            "No presence hints stored".to_string()
        } else {
            "No local presence documents stored".to_string()
        }
    } else {
        format!("{} presence document(s)", docs.len())
    };

    let payload = json!({
        "command": "discover.list",
        "scope": if args.hints { "hints" } else { "local" },
        "presence": docs,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_import(args: ImportArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let data = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;
    let doc: PresenceDoc = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;
    let path = save_presence_hint(&home, &doc)?;

    let payload = json!({
        "command": "discover.import",
        "path": path,
        "presence": doc,
    });
    Ok(CommandOutput::new(
        format!(
            "Imported presence hint for {}",
            payload["presence"]["did"].as_str().unwrap_or("<unknown>")
        ),
        payload,
    ))
}

fn handle_refresh(args: RefreshArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let (prior_hint, url) = match args.url {
        Some(url) => (None, url),
        None => {
            let (doc, url) = resolve_presence_endpoint(&home, &args.did, &args.endpoint)?
                .ok_or_else(|| {
                    anyhow!(
                        "no cached presence endpoint '{}' for {}; use --url to override",
                        args.endpoint,
                        args.did
                    )
                })?;
            (Some(doc), url)
        }
    };

    let fetched = fetch_presence(&url)?;
    let path = save_presence_hint(&home, &fetched)?;

    let payload = json!({
        "command": "discover.refresh",
        "did": args.did,
        "url": url,
        "presence": fetched,
        "path": path,
        "prior_hint": prior_hint,
    });

    Ok(CommandOutput::new(
        format!(
            "Refreshed presence for {}",
            payload["did"].as_str().unwrap_or("<unknown>")
        ),
        payload,
    ))
}

fn handle_resolve(args: ResolveArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?
        .canonicalize()
        .unwrap_or_else(|_| ensure_home_dir().expect("home dir"));

    let mut dht_hint = None;
    let mut hint_path: Option<PathBuf> = None;
    let mut hint_expired = false;
    let mut presence_doc: Option<PresenceDoc> = None;
    let mut presence_path: Option<PathBuf> = None;
    let mut resolved_url: Option<String> = None;
    let mut fetch_error: Option<anyhow::Error> = None;
    let mut cache_used = false;

    if !args.no_dht {
        if let Some(hint) = fetch_dht_hint(&args.did)? {
            hint_expired = hint.expires_at <= OffsetDateTime::now_utc();
            let path = store_hint(&home, &hint)?;
            hint_path = Some(path);

            let presence = if args.hint_only {
                None
            } else {
                match fetch_presence_with_retry(&hint.presence_url, 3, Duration::from_millis(500)) {
                    Ok(doc) => Some(doc),
                    Err(err) => {
                        let context_err = err.context(format!(
                            "failed to fetch presence via DHT hint ({})",
                            hint.presence_url
                        ));
                        if args.cache_fallback {
                            fetch_error = Some(context_err);
                            None
                        } else {
                            return Err(context_err);
                        }
                    }
                }
            };

            if let Some(doc) = presence {
                let cid = doc.canonical_hash()?;
                if cid != hint.presence_cid {
                    return Err(anyhow!(
                        "presence hash mismatch (hint={}, computed={})",
                        hint.presence_cid,
                        cid
                    ));
                }
                let stored = save_presence_hint(&home, &doc)?;
                presence_path = Some(stored);
                resolved_url = Some(hint.presence_url.clone());
                presence_doc = Some(doc);
            }

            dht_hint = Some(hint);
        }
    }

    if presence_doc.is_none() && !args.hint_only {
        if let Some((doc, url)) = resolve_presence_endpoint(&home, &args.did, "presence")? {
            if let Some(hint) = &dht_hint {
                let cid = doc.canonical_hash()?;
                if cid != hint.presence_cid {
                    return Err(anyhow!(
                        "cached presence hash mismatch (hint={}, cached={})",
                        hint.presence_cid,
                        cid
                    ));
                }
            }
            cache_used = true;
            resolved_url = Some(url.clone());
            presence_doc = Some(doc);
        }
    }

    let fetch_error_string = fetch_error.as_ref().map(|err| format!("{:#}", err));

    let cache_from_failure = cache_used && fetch_error.is_some();

    if presence_doc.is_none() {
        if let Some(err) = fetch_error {
            return Err(err);
        }
    }

    let payload = json!({
        "command": "discover.resolve",
        "did": args.did,
        "hint": dht_hint.as_ref().map(|hint| to_json(hint)),
        "hint_path": hint_path.as_ref().map(|path| path.to_string_lossy().to_string()),
        "hint_expired": dht_hint.as_ref().map(|_| hint_expired).unwrap_or(false),
        "presence": presence_doc,
        "presence_path": presence_path.as_ref().map(|path| path.to_string_lossy().to_string()),
        "resolved_url": resolved_url.clone(),
        "cached_url": resolved_url,
        "fallback_used": cache_used,
        "fetch_error": fetch_error_string,
    });

    let message = if dht_hint.is_some() && hint_expired {
        "DHT hint located but expired; ask publisher to refresh".to_string()
    } else if cache_from_failure {
        "Resolved presence via cached endpoints (HTTP fetch failed; using cached copy)".to_string()
    } else if cache_used {
        "Resolved presence via cached endpoints".to_string()
    } else {
        match (&dht_hint, &presence_doc) {
            (Some(_), Some(_)) => "Resolved presence via DHT".to_string(),
            (Some(_), None) if args.hint_only => "DHT hint located (no presence fetch)".to_string(),
            (Some(_), None) => "DHT hint cached; presence fetch skipped".to_string(),
            (None, Some(_)) => "Resolved presence via cached endpoints".to_string(),
            (None, None) => "No hint or presence found".to_string(),
        }
    };

    Ok(CommandOutput::new(message, payload))
}

fn parse_endpoints(entries: Vec<String>) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(anyhow!("endpoint must be key=value, got '{entry}'"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(anyhow!("endpoint must provide non-empty key and value"));
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

fn parse_relays(entries: Vec<String>) -> Result<Vec<PresenceRelay>> {
    use time::format_description::well_known::Rfc3339;

    let mut relays = Vec::new();
    for entry in entries {
        let Some((host, value)) = entry.split_once('=') else {
            return Err(anyhow!("relay must be host=url[@RFC3339], got '{entry}'"));
        };
        let host = host.trim();
        if host.is_empty() {
            return Err(anyhow!("relay host cannot be empty"));
        }

        let value = value.trim();
        if value.is_empty() {
            return Err(anyhow!("relay URL cannot be empty"));
        }

        let (url, expires_at) = if let Some((url_part, expires_part)) = value.rsplit_once('@') {
            if let Ok(ts) = OffsetDateTime::parse(expires_part, &Rfc3339) {
                (url_part.trim().to_string(), Some(ts))
            } else {
                return Err(anyhow!(
                    "invalid relay expiry timestamp '{}' (expected RFC3339)",
                    expires_part
                ));
            }
        } else {
            (value.to_string(), None)
        };

        if relays
            .iter()
            .any(|relay: &PresenceRelay| relay.host == host)
        {
            return Err(anyhow!("duplicate relay host '{}'", host));
        }

        relays.push(PresenceRelay {
            host: host.to_string(),
            url,
            expires_at,
        });
    }
    Ok(relays)
}
