mod analysis;
mod frontend;
mod fuzzing;
mod hybrid;
mod meta;
mod report;
mod surfaced;
mod symbolic;

use chainvet_core::util::error::Error;
use chainvet_core::util::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalysisMode {
    Static,
    Symbolic,
    Fuzzing,
    Hybrid,
}

impl AnalysisMode {
    fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--static" => Some(Self::Static),
            "--symbolic" => Some(Self::Symbolic),
            "--fuzzing" => Some(Self::Fuzzing),
            "--hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "usage: chainvet [--static|--symbolic|--fuzzing|--hybrid] <path> [--json|--text|--format <json|text>] [--dump-ir <text|json|tuple>]\n\
         hybrid budget overrides: [--max-epochs N] [--total-runtime-ms N] [--hard-cap-ms N] [--fuzz-iters N] [--fuzz-epoch-ms N] [--se-timeout-ms N] [--se-max-depth N] [--max-se-assists N] [--fuzz-seed N]"
    );
}

fn parse_next<T>(value: Option<String>, flag: &str) -> Result<T>
where
    T: std::str::FromStr,
{
    let raw = value.ok_or_else(|| Error::msg(format!("missing value for {flag}")))?;
    raw.parse::<T>()
        .map_err(|_| Error::msg(format!("invalid value for {flag}: {raw}")))
}

fn run() -> Result<()> {
    let mut input = None;
    let mut format = report::OutputFormat::Text;
    let mut dump_ir = None;
    let mut mode = AnalysisMode::Static;
    let mut mode_flag = None::<&'static str>;
    let mut hybrid_budget = hybrid::HybridBudget::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(next_mode) = AnalysisMode::from_flag(&arg) {
            if let Some(existing_flag) = mode_flag {
                if mode != next_mode {
                    return Err(Error::msg(format!(
                        "multiple analysis modes provided: {existing_flag} and {arg}"
                    )));
                }
            } else {
                mode = next_mode;
                mode_flag = Some(match next_mode {
                    AnalysisMode::Static => "--static",
                    AnalysisMode::Symbolic => "--symbolic",
                    AnalysisMode::Fuzzing => "--fuzzing",
                    AnalysisMode::Hybrid => "--hybrid",
                });
            }
            continue;
        }

        match arg.as_str() {
            "--json" => format = report::OutputFormat::Json,
            "--text" => format = report::OutputFormat::Text,
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(Error::msg("missing value for --format"));
                };
                match value.as_str() {
                    "json" => format = report::OutputFormat::Json,
                    "text" => format = report::OutputFormat::Text,
                    _ => return Err(Error::msg(format!("unknown format: {value}"))),
                }
            }
            "--dump-ir" => {
                let Some(value) = args.next() else {
                    return Err(Error::msg("missing value for --dump-ir"));
                };
                let ir_format = match value.as_str() {
                    "json" => chainvet_core::ir::DumpFormat::Json,
                    "text" => chainvet_core::ir::DumpFormat::Text,
                    "tuple" => chainvet_core::ir::DumpFormat::Tuple,
                    _ => return Err(Error::msg(format!("unknown IR format: {value}"))),
                };
                dump_ir = Some(ir_format);
            }
            "--fuzz" => {
                if let Some(existing_flag) = mode_flag {
                    if mode != AnalysisMode::Fuzzing {
                        return Err(Error::msg(format!(
                            "multiple analysis modes provided: {existing_flag} and --fuzz"
                        )));
                    }
                } else {
                    mode = AnalysisMode::Fuzzing;
                    mode_flag = Some("--fuzz");
                }
            }
            "--max-epochs" => hybrid_budget.max_epochs = parse_next(args.next(), "--max-epochs")?,
            "--total-runtime-ms" => {
                hybrid_budget.total_runtime_ms = parse_next(args.next(), "--total-runtime-ms")?
            }
            "--hard-cap-ms" => {
                hybrid_budget.hard_cap_ms = parse_next(args.next(), "--hard-cap-ms")?
            }
            "--fuzz-iters" => {
                hybrid_budget.fuzz_iters_per_epoch = parse_next(args.next(), "--fuzz-iters")?
            }
            "--fuzz-epoch-ms" => {
                hybrid_budget.fuzz_epoch_ms = parse_next(args.next(), "--fuzz-epoch-ms")?
            }
            "--se-timeout-ms" => {
                hybrid_budget.se_timeout_ms = parse_next(args.next(), "--se-timeout-ms")?
            }
            "--se-max-depth" => {
                hybrid_budget.se_max_depth = parse_next(args.next(), "--se-max-depth")?
            }
            "--max-se-assists" => {
                hybrid_budget.max_se_assists = parse_next(args.next(), "--max-se-assists")?
            }
            "--fuzz-seed" => hybrid_budget.fuzz_seed = parse_next(args.next(), "--fuzz-seed")?,
            _ => {
                if arg.starts_with('-') {
                    return Err(Error::msg(format!("unknown flag: {arg}")));
                }
                if input.is_none() {
                    input = Some(arg);
                } else {
                    return Err(Error::msg("multiple input paths provided"));
                }
            }
        }
    }

    let Some(input) = input else {
        print_usage();
        return Ok(());
    };

    if dump_ir.is_some() && mode != AnalysisMode::Static {
        return Err(Error::msg("--dump-ir is only supported in --static mode"));
    }

    match mode {
        AnalysisMode::Static => {
            let output = frontend::load_project(&input)?;
            if let Some(format) = dump_ir {
                let ir_module = chainvet_core::ir::lower_module(&output.ast);
                let payload = chainvet_core::ir::dump_module(&ir_module, format);
                println!("{payload}");
                return Ok(());
            }
            report::print_report(&output, &input, format)?;
        }
        AnalysisMode::Symbolic => {
            let output = frontend::load_project(&input)?;
            symbolic::run(&output, format)?;
        }
        AnalysisMode::Fuzzing => {
            let output = frontend::load_project(&input)?;
            let config = fuzzing::types::FuzzConfig::default();
            fuzzing::run_fuzzer(&output, &config, format)?;
        }
        AnalysisMode::Hybrid => {
            let output = frontend::load_project(&input)?;
            hybrid::run_with_budget(&output, &hybrid_budget, format)?;
        }
    }

    Ok(())
}
