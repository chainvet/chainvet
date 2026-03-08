mod analysis;
mod cfg;

mod frontend;
mod fuzzing;
mod ir;
mod norm;
mod report;
mod ssa;
mod symbolic;
mod util;

use crate::util::error::Error;
use crate::util::error::Result;

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

    fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Symbolic => "symbolic",
            Self::Fuzzing => "fuzzing",
            Self::Hybrid => "hybrid",
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
        "usage: static-analyzer [--static|--symbolic|--fuzzing|--hybrid] <path> [--json|--text|--format <json|text>] [--dump-ir <text|json|tuple>]"
    );
}

fn run() -> Result<()> {
    let mut input = None;
    let mut format = report::OutputFormat::Text;
    let mut dump_ir = None;
    let mut mode = AnalysisMode::Static;
    let mut mode_flag = None::<&'static str>;
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
                    "json" => ir::DumpFormat::Json,
                    "text" => ir::DumpFormat::Text,
                    "tuple" => ir::DumpFormat::Tuple,
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
                let ir_module = ir::lower_module(&output.ast);
                let payload = ir::dump_module(&ir_module, format);
                println!("{payload}");
                return Ok(());
            }
            report::print_report(&output, format)?;
        }
        AnalysisMode::Symbolic => {
            let output = frontend::load_project(&input)?;
            symbolic::run(&output, format)?;
        }
        AnalysisMode::Fuzzing => {
            let output = frontend::load_project(&input)?;
            let config = fuzzing::types::FuzzConfig::default();
            fuzzing::run_fuzzer(&output.ast, &config);
        }
        AnalysisMode::Hybrid => {
            return Err(Error::msg(
                "hybrid mode placeholder: not implemented yet (planned static + symbolic + fuzzing pipeline)",
            ));
        }
    }

    Ok(())
}
