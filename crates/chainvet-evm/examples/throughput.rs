//! Throughput comparison: IR interpreter vs revm, executing the *same* inputs.
//! The fidelity gap only matters relative to cost — coverage-guided fuzzing
//! lives on executions/second. This times both engines on one corpus so the
//! IR-vs-EVM decision can weigh fidelity against the throughput it would cost.
//!
//!   cargo run --release -p chainvet-evm --example throughput -- <path.sol>

use std::time::Instant;

use chainvet_core::{cfg, ir};
use chainvet_evm::{compile, replay_individual};
use chainvet_frontend::frontend;
use chainvet_fuzzing::fuzzing::executor::execute_individual;
use chainvet_fuzzing::fuzzing::runner::FuzzSession;
use chainvet_fuzzing::fuzzing::types::{build_dependency_map, extract_abis, FuzzConfig, Individual};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --release -p chainvet-evm --example throughput -- <path.sol>");
        std::process::exit(2);
    });

    let output = frontend::load_project(&path).expect("parse");
    let sources = frontend::collect_target_sources(&path).expect("sources");
    let compiled = compile(&sources).expect("compile");

    let ir_module = ir::lower_module(&output.ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let deps = build_dependency_map(&ir_module, &output.ast);
    let abis = extract_abis(&output.ast, &output.compiler);

    // Build a small corpus to run repeatedly.
    let config = FuzzConfig {
        seed: Some(1),
        max_duration_ms: Some(2000),
        ..Default::default()
    };
    let mut session = FuzzSession::new(&output, config);
    session.run_slice(&[], 2000, Some(2000));
    let corpus: Vec<Individual> =
        session.corpus().entries.iter().map(|e| e.individual.clone()).collect();

    // Pick the first (abi, compiled) pair that has a deployable match.
    let Some((abi, compiled_c)) = abis
        .iter()
        .find_map(|a| compiled.iter().find(|c| c.name == a.contract_name).map(|c| (a, c)))
    else {
        eprintln!("no compiled contract matched an ABI");
        std::process::exit(1);
    };
    let inputs: Vec<&Individual> = corpus
        .iter()
        .filter(|ind| {
            ind.transactions
                .first()
                .is_some_and(|tx| abi.functions.iter().any(|f| f.id == tx.function_id))
        })
        .collect();
    if inputs.is_empty() {
        eprintln!("no corpus inputs target the chosen contract");
        std::process::exit(1);
    }

    let reps = 2000usize;
    println!("== throughput: {path} ==");
    println!("corpus inputs cycled: {}, reps: {reps}\n", inputs.len());

    // IR interpreter.
    let t = Instant::now();
    let mut ir_execs = 0usize;
    for i in 0..reps {
        let ind = inputs[i % inputs.len()];
        let _ = execute_individual(ind, &output, &ir_module, &cfgs, abi, &deps);
        ir_execs += 1;
    }
    let ir_secs = t.elapsed().as_secs_f64();

    // revm (fresh deploy + sequence per individual, as fuzzing would need).
    let t = Instant::now();
    let mut evm_execs = 0usize;
    for i in 0..reps {
        let ind = inputs[i % inputs.len()];
        let _ = replay_individual(compiled_c, abi, ind);
        evm_execs += 1;
    }
    let evm_secs = t.elapsed().as_secs_f64();

    let ir_rate = ir_execs as f64 / ir_secs;
    let evm_rate = evm_execs as f64 / evm_secs;
    println!("IR  : {ir_rate:>12.0} execs/s  ({ir_secs:.3}s)");
    println!("EVM : {evm_rate:>12.0} execs/s  ({evm_secs:.3}s)");
    if ir_rate >= evm_rate {
        println!("\nIR is {:.2}x faster per execution than revm.", ir_rate / evm_rate);
    } else {
        println!("\nrevm is {:.2}x faster per execution than the IR interpreter.", evm_rate / ir_rate);
    }
}
