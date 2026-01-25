mod analysis;
mod cfg;

mod frontend;
mod ir;
mod norm;
mod report;
mod ssa;
mod util;
mod symbolic;
mod fuzzing;

use crate::util::error::Result;
use crate::util::error::Error;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut input = None;
    let mut format = report::OutputFormat::Text;
    let mut dump_ir = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = report::OutputFormat::Json,
            "--text" => format = report::OutputFormat::Text,
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
                    _ => return Err(Error::msg(format!("unknown IR format: {value}"))),
                };
                dump_ir = Some(ir_format);
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
        eprintln!(
            "usage: static-analyzer <path> [--json|--text|--format <json|text>] [--dump-ir <text|json>]"
        );
        return Ok(());
    };

    let output = frontend::load_project(&input)?;
    if let Some(format) = dump_ir {
        let ir_module = ir::lower_module(&output.ast);
        let payload = ir::dump_module(&ir_module, format);
        println!("{payload}");
        return Ok(());
    }
    report::print_report(&output, format)?;
    Ok(())
}
