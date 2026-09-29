use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use decode_core::{decode_trace, DecodeRegistry};
use evidence::Report;
use solana_debug_rpc::{fetch_transaction_trace, RpcIngestConfig};
use std::{fs, path::PathBuf};
use trace::TransactionTrace;

#[derive(Debug, Parser)]
#[command(name = "solana-debug")]
#[command(about = "Private-first Solana transaction debugger")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect(InspectArgs),
    Replay(ReplayArgs),
    Capture(CaptureArgs),
    Trace,
    Explain,
    Experiment,
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    Github {
        #[command(subcommand)]
        command: GithubCommand,
    },
}

#[derive(Debug, Parser)]
struct InspectArgs {
    signature: Option<String>,
    #[arg(long)]
    tx_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Mode::Private)]
    mode: Mode,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, default_value = "confirmed")]
    commitment: String,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    no_llm: bool,
    #[arg(long)]
    idl: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ReplayArgs {
    bundle: PathBuf,
    #[arg(long, value_enum, default_value_t = ReplayEngine::Litesvm)]
    engine: ReplayEngine,
}

#[derive(Debug, Parser)]
struct CaptureArgs {
    signature: String,
    #[arg(long)]
    rpc_url: String,
    #[arg(long, default_value = "confirmed")]
    commitment: String,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    idl: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    Inspect { bundle: PathBuf },
    Verify { bundle: PathBuf },
}

#[derive(Debug, Subcommand)]
enum GithubCommand {
    Fix { bundle: PathBuf },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Private,
    Hybrid,
    Live,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReplayEngine {
    Litesvm,
    Mollusk,
    Validator,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Inspect(args) => inspect(args),
        Command::Capture(args) => capture(args),
        Command::Replay(args) => {
            println!(
                "Replay backend {:?} is scaffolded; bundle path: {}",
                args.engine,
                args.bundle.display()
            );
            Ok(())
        }
        Command::Trace
        | Command::Explain
        | Command::Experiment
        | Command::Bundle { .. }
        | Command::Github { .. } => {
            println!("Command scaffolded; implementation pending.");
            Ok(())
        }
    }
}

fn inspect(args: InspectArgs) -> Result<()> {
    if matches!(args.mode, Mode::Private) && args.signature.is_some() && args.tx_file.is_none() {
        anyhow::bail!("private signature mode requires --tx-file or a capture bundle; fetching a signature needs RPC");
    }

    let mut trace = match args.mode {
        Mode::Private => trace_from_file(args.tx_file)?,
        Mode::Hybrid | Mode::Live => {
            if let Some(tx_file) = args.tx_file {
                trace_from_file(Some(tx_file))?
            } else {
                let signature = args
                    .signature
                    .as_deref()
                    .context("inspect in hybrid/live mode requires <SIGNATURE> or --tx-file")?;
                let rpc_url = args
                    .rpc_url
                    .clone()
                    .context("--rpc-url is required when fetching by signature")?;
                let config = RpcIngestConfig::new(rpc_url, args.commitment.clone());
                fetch_transaction_trace(signature, &config)?
            }
        }
    };
    trace.validate()?;
    let registry = load_registry(args.idl.as_deref())?;
    let report = analyze_trace(&mut trace, &registry);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text_report(&report);
    }

    Ok(())
}

fn capture(args: CaptureArgs) -> Result<()> {
    let config = RpcIngestConfig::new(args.rpc_url.clone(), args.commitment.clone());
    let mut trace = fetch_transaction_trace(&args.signature, &config)?;
    trace.validate()?;

    let registry = load_registry(args.idl.as_deref())?;
    let report = analyze_trace(&mut trace, &registry);

    fs::create_dir_all(&args.out)
        .with_context(|| format!("failed to create capture dir {}", args.out.display()))?;
    write_json(args.out.join("trace.json"), &trace)?;
    write_json(args.out.join("report.json"), &report)?;
    let manifest = serde_json::json!({
        "schema": "solana-debug/capture@0.1",
        "signature": args.signature,
        "rpc_url": args.rpc_url,
        "commitment": args.commitment,
        "files": {
            "trace": "trace.json",
            "report": "report.json"
        },
        "capabilities": {
            "solana_rpc": true,
            "rpc_methods": ["getTransaction"],
            "wallet_keys": false,
            "transaction_sign": false,
            "transaction_send": false,
            "historical_state_complete": false
        }
    });
    write_json(args.out.join("manifest.json"), &manifest)?;

    println!("Captured {}", args.out.display());
    println!("  trace: {}", args.out.join("trace.json").display());
    println!("  report: {}", args.out.join("report.json").display());
    println!("  manifest: {}", args.out.join("manifest.json").display());
    Ok(())
}

fn load_registry(idl: Option<&std::path::Path>) -> Result<DecodeRegistry> {
    match idl {
        Some(path) => DecodeRegistry::load_anchor_idl_path(path)
            .with_context(|| format!("failed to load Anchor IDL {}", path.display())),
        None => Ok(DecodeRegistry::default()),
    }
}

fn analyze_trace(trace: &mut TransactionTrace, registry: &DecodeRegistry) -> Report {
    decode_trace(trace, registry);
    let findings = analyze::analyze(trace);
    Report::from_trace(trace, findings)
}

fn write_json(path: PathBuf, value: &impl serde::Serialize) -> Result<()> {
    let raw = serde_json::to_string_pretty(value)?;
    fs::write(&path, raw).with_context(|| format!("failed to write {}", path.display()))
}

fn trace_from_file(tx_file: Option<PathBuf>) -> Result<TransactionTrace> {
    let tx_file = tx_file
        .context("private mode expects --tx-file containing normalized TransactionTrace JSON")?;
    let raw = fs::read_to_string(&tx_file)
        .with_context(|| format!("failed to read {}", tx_file.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", tx_file.display()))
}

fn print_text_report(report: &Report) {
    println!("Transaction: {}", report.transaction.status.to_uppercase());
    println!("Version: {}", report.transaction.version);
    if let Some(slot) = report.transaction.slot {
        println!("Slot: {slot}");
    }
    if let Some(failure) = &report.failure {
        println!();
        println!("Failure");
        println!("  Invocation: {}", failure.invocation_id);
        println!("  Instruction: {}", failure.top_level_instruction);
        println!("  Program: {}", failure.program_id);
        if let Some(decoded) = &failure.decoded_instruction {
            println!("  Decoded: {}::{}", decoded.program, decoded.name);
        }
        if let Some(code) = &failure.error_code {
            println!("  Error code: {code}");
        }
        if let Some(message) = &failure.error_message {
            println!("  Error: {message}");
        }
        println!("  Accounts");
        if failure.accounts.is_empty() {
            println!("    none");
        } else {
            for account in &failure.accounts {
                println!(
                    "    [{}] {} signer={} writable={}",
                    account.index,
                    account.pubkey,
                    yes_no(account.is_signer),
                    yes_no(account.is_writable)
                );
            }
        }
        println!("  Logs");
        if failure.logs.is_empty() {
            println!("    none");
        } else {
            for log in &failure.logs {
                println!("    {log}");
            }
        }
    }
    println!();
    println!("Deterministic findings");
    if report.evidence.deterministic_findings.is_empty() {
        println!("  none");
    } else {
        for finding in &report.evidence.deterministic_findings {
            println!("  {}", finding.rule_id);
            for fact in &finding.facts {
                println!("    {} {}", fact.id, fact.statement);
            }
            println!("    Proof grade: {:?}", finding.proof);
        }
    }
}

fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}
