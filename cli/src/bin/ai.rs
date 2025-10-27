use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::plan::{build_offer_plan_step, build_publish_plan_step, PlanStore};
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "hn ai", version, about = "Human.Net A1 assistant tooling.")]
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
    /// Generate a signed plan@1 from a natural prompt.
    Plan(PlanArgs),
    /// List stored plans for the active identity.
    List,
    /// Show a stored plan document.
    Show(PlanIdArgs),
    /// Dry-run a plan without executing actions.
    DryRun(PlanIdArgs),
    /// Execute a plan (currently behaves like dry-run).
    Run(PlanIdArgs),
}

#[derive(Args, Debug)]
struct PlanArgs {
    /// Natural language instruction for the assistant.
    prompt: String,

    /// Doc id referenced in the plan.
    #[arg(long = "doc", value_name = "DOC-ID")]
    doc: String,

    /// Audience DID included in the plan.
    #[arg(long = "audience", value_name = "DID")]
    audience: String,

    /// Capability requested (default read).
    #[arg(long = "capability", default_value = "read")]
    capability: String,
}

#[derive(Args, Debug)]
struct PlanIdArgs {
    /// Plan identifier to load.
    id: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Plan(args) => handle_plan(args)?,
        Commands::List => handle_list()?,
        Commands::Show(args) => handle_show(args)?,
        Commands::DryRun(args) => handle_dry_run(args, true)?,
        Commands::Run(args) => handle_dry_run(args, false)?,
    };
    output.render(cli.output)?;
    Ok(())
}

fn open_store() -> Result<PlanStore> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home)?;
    PlanStore::open(&vault)
}

fn handle_plan(args: PlanArgs) -> Result<CommandOutput> {
    let store = open_store()?;
    let mut steps = Vec::new();
    steps.push(build_offer_plan_step(
        &args.doc,
        &args.audience,
        &args.capability,
    ));
    steps.push(build_publish_plan_step());

    let plan = store.generate_plan(&args.prompt, steps)?;
    let path = store.save(&plan)?;

    let payload = json!({
        "command": "ai.plan",
        "path": path,
        "plan": plan,
    });

    Ok(CommandOutput::new(
        format!(
            "Plan '{}' created and signed",
            payload["plan"]["id"].as_str().unwrap_or("<unknown>")
        ),
        payload,
    ))
}

fn handle_list() -> Result<CommandOutput> {
    let store = open_store()?;
    let plans = store.list()?;
    let message = if plans.is_empty() {
        "No plans stored".to_string()
    } else {
        format!("{} plan(s) available", plans.len())
    };
    let payload = json!({
        "command": "ai.list",
        "plans": plans,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_show(args: PlanIdArgs) -> Result<CommandOutput> {
    let store = open_store()?;
    let plan = store.load(&args.id)?;
    let payload = json!({
        "command": "ai.show",
        "plan": plan,
    });
    Ok(CommandOutput::new(format!("Plan '{}'", args.id), payload))
}

fn handle_dry_run(args: PlanIdArgs, preview_only: bool) -> Result<CommandOutput> {
    let store = open_store()?;
    let plan = store.load(&args.id)?;
    plan.verify_signature(&store.verifying_key())?;
    let message = if preview_only {
        format!("Dry-run plan '{}' (no actions executed)", args.id)
    } else {
        format!(
            "Plan '{}' execution mode currently runs as dry-run; no actions taken",
            args.id
        )
    };
    let payload = json!({
        "command": if preview_only { "ai.dry-run" } else { "ai.run" },
        "plan": plan,
    });
    Ok(CommandOutput::new(message, payload))
}
