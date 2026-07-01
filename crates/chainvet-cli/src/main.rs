mod render;

use chainvet_core::util::error::Result;
use chainvet_orchestrator::{HybridBudget, ScanMode, scan};
use clap::{Parser, Subcommand, ValueEnum};

/// Hybrid Solidity smart-contract security analyzer.
#[derive(Parser)]
#[command(name = "chainvet", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a Solidity file or project for vulnerabilities.
    Scan(ScanArgs),
    /// Dump the intermediate representation (debug utility).
    Ir(IrArgs),
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Solidity file or project directory to analyze.
    pub path: String,

    /// Analysis mode.
    #[arg(short, long, value_enum, default_value_t = Mode::Hybrid)]
    pub mode: Mode,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Pretty)]
    pub format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Only report findings at or above this severity.
    #[arg(short = 's', long, value_enum, value_name = "SEVERITY")]
    pub min_severity: Option<Severity>,

    /// Suppress the banner.
    #[arg(short, long)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,

    /// Max fuzz epochs.
    #[arg(long, help_heading = "Hybrid tuning", value_name = "N")]
    epochs: Option<u32>,
    /// Fuzz time budget (ms).
    #[arg(
        long = "fuzz-time-ms",
        help_heading = "Hybrid tuning",
        value_name = "MS"
    )]
    fuzz_time_ms: Option<u64>,
    /// Overall wall-clock cap (ms).
    #[arg(
        long = "hard-cap-ms",
        help_heading = "Hybrid tuning",
        value_name = "MS"
    )]
    hard_cap_ms: Option<u64>,
    /// Fuzz iterations per epoch.
    #[arg(long = "fuzz-iters", help_heading = "Hybrid tuning", value_name = "N")]
    fuzz_iters: Option<usize>,
    /// Per-epoch fuzz time (ms).
    #[arg(
        long = "epoch-time-ms",
        help_heading = "Hybrid tuning",
        value_name = "MS"
    )]
    epoch_time_ms: Option<u64>,
    /// Symbolic execution timeout (ms).
    #[arg(
        long = "se-timeout-ms",
        help_heading = "Hybrid tuning",
        value_name = "MS"
    )]
    se_timeout_ms: Option<u64>,
    /// Symbolic execution max path depth.
    #[arg(long = "se-depth", help_heading = "Hybrid tuning", value_name = "N")]
    se_depth: Option<u32>,
    /// Max on-stall symbolic assists.
    #[arg(long = "se-assists", help_heading = "Hybrid tuning", value_name = "N")]
    se_assists: Option<u32>,
    /// Fuzz seed (for reproducible runs).
    #[arg(long, help_heading = "Hybrid tuning", value_name = "N")]
    seed: Option<u64>,
}

#[derive(clap::Args)]
struct IrArgs {
    /// Solidity file or project directory.
    path: String,
    /// IR dump format.
    #[arg(short, long, value_enum, default_value_t = IrFormat::Text)]
    format: IrFormat,
}

#[derive(Copy, Clone, ValueEnum)]
pub enum Mode {
    Static,
    Symbolic,
    Fuzzing,
    Hybrid,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Pretty,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Copy, Clone, ValueEnum)]
enum IrFormat {
    Text,
    Json,
    Tuple,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Ir(args) => run_ir(args),
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let scan_mode = match args.mode {
        Mode::Static => ScanMode::Static,
        Mode::Symbolic => ScanMode::Symbolic,
        Mode::Fuzzing => ScanMode::Fuzzing,
        Mode::Hybrid => ScanMode::Hybrid,
    };

    let mut budget = HybridBudget::default();
    if let Some(v) = args.epochs {
        budget.max_epochs = v;
    }
    if let Some(v) = args.fuzz_time_ms {
        budget.total_runtime_ms = v;
    }
    if let Some(v) = args.hard_cap_ms {
        budget.hard_cap_ms = v;
    }
    if let Some(v) = args.fuzz_iters {
        budget.fuzz_iters_per_epoch = v;
    }
    if let Some(v) = args.epoch_time_ms {
        budget.fuzz_epoch_ms = v;
    }
    if let Some(v) = args.se_timeout_ms {
        budget.se_timeout_ms = v;
    }
    if let Some(v) = args.se_depth {
        budget.se_max_depth = v;
    }
    if let Some(v) = args.se_assists {
        budget.max_se_assists = v;
    }
    if let Some(v) = args.seed {
        budget.fuzz_seed = v;
    }

    let output = chainvet_frontend::frontend::load_project(&args.path)?;
    let result = scan(&output, scan_mode, &budget)?;
    render::render(&result, &args)
}

fn run_ir(args: IrArgs) -> Result<()> {
    let output = chainvet_frontend::frontend::load_project(&args.path)?;
    let ir_module = chainvet_core::ir::lower_module(&output.ast);
    let fmt = match args.format {
        IrFormat::Text => chainvet_core::ir::DumpFormat::Text,
        IrFormat::Json => chainvet_core::ir::DumpFormat::Json,
        IrFormat::Tuple => chainvet_core::ir::DumpFormat::Tuple,
    };
    println!("{}", chainvet_core::ir::dump_module(&ir_module, fmt));
    Ok(())
}
