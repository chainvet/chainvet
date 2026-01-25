# Using M1–M3 in Each Analysis Mode (Static, Symbolic, Fuzzing)

This document teaches contributors how to use the M1/M2/M3 pipeline as the shared foundation for **static analysis**, **symbolic execution**, and **fuzzing**. The goal is one program model with multiple execution/analysis strategies.

## Shared foundation (applies to all modes)

Every mode starts the same way:
1) **Frontend** (M1 or M2) builds a `NormalizedAst`.
2) **IR/CFG/SSA** (M3) lowers it into analysis‑ready form.

This gives you:
- consistent function bodies
- explicit control flow
- explicit data dependencies
- stable IDs and spans for reporting

### Why this shared path matters
- Avoids duplicate parsers per analysis type.
- Guarantees consistent function/call mapping across engines.
- Makes cross‑mode results comparable (same spans, same IR).


## Static analysis usage

### How static analysis uses M1–M3
- **M1/M2:** parse source (full or partial).
- **M3:** generate IR/CFG/SSA.
- **Static engine:** run dataflow/taint/call‑graph + detector rules.

### Concrete data consumed
- **CFG:** reachability and structural checks (loops, branches).
- **SSA/def‑use:** data dependencies and taint propagation.
- **IR Places:** storage vs memory writes.

### Typical outputs
- Findings with spans and categories (reentrancy, access control, etc.).
- Function summaries for quick auditing.


## Symbolic execution usage

### How symbolic execution uses M1–M3
- **M1/M2:** parse source into normalized AST.
- **M3:** build IR/CFG/SSA.
- **Symbolic engine:** interpret IR instruction semantics with symbolic values.

### How to integrate
1) Use CFG to generate execution paths.
2) Use SSA to simplify symbolic expressions (single assignment).
3) Interpret IR ops (`Binary`, `Unary`, `Select`, `Load`, `Store`, `Call`, `Return`).
4) Maintain symbolic memory for storage vs memory (PlaceClass).
5) Emit solver constraints at branches and call sites.

### Why this works
- SSA eliminates the need to track variable reassignment chains.
- IR reduces Solidity syntax complexity to a small instruction set.
- Call options (gas/value/salt) can be turned into constraints.


## Fuzzing usage

### How fuzzing uses M1–M3
- **M1/M2:** parse input contracts.
- **M3:** IR/CFG/SSA.
- **Fuzzer:** uses CFG + call graph + IR to choose targets and inputs.

### How to integrate
1) Use the CFG and call graph to choose entrypoints.
2) Use IR to build harnesses (argument count, types, external calls).
3) Use summaries/SSA to pick state‑influencing functions.
4) Use call graph to prioritize reachable sensitive paths.

### Why this works
- Fuzzing needs structure to be efficient; CFG/IR gives that.
- SSA lets you quickly identify which inputs influence a branch.
- Shared spans let fuzzing findings align with static findings.


## Practical usage recipe (common)

1) Call frontend:
   - Full mode: `frontend::solc::load_via_solc`.
   - Partial mode: `frontend::parser::load_via_parser`.

2) Lower to IR:
   - `ir::lower::lower_module(&ast)`.

3) Build CFG:
   - `cfg::build_from_ir(&module)`.

4) Build SSA:
   - `ssa::build_ssa(&ast, &cfgs)`.

From here, choose your engine:
- Static: `analysis::run_*` (taint/call graph/detectors).
- Symbolic: interpret IR blocks with constraints.
- Fuzzing: build harnesses and feedback guided by CFG/SSA.


## Concrete examples

Below are small, end‑to‑end examples showing how a developer would actually wire M1–M3 into each mode. These are intentionally minimal so you can adapt them into real modules.

### Example A: Static analysis (taint + call graph + summaries)

```rust
use static_tool::{
    frontend, ir, cfg, ssa,
    analysis::{self, taint, summary, detectors},
};

fn run_static(path: &str) -> anyhow::Result<()> {
    // 1) Load with solc (falls back automatically if solc fails).
    let frontend_out = frontend::load_project(path)?;
    let ast = frontend_out.ast;

    // 2) IR + CFG + SSA
    let module = ir::lower_module(&ast);
    let cfgs = cfg::build_from_ir(&module);
    let ssa = ssa::build_ssa(&ast, &cfgs);

    // 3) Core analyses
    let call_graph = analysis::build_call_graph(&ast);
    let resolved_graph = analysis::resolve_call_graph(&ast, &call_graph);
    
    // Taint analysis
    let taint_results = taint::analyze(&ast, &cfgs);

    // Summarization
    let summaries = summary::summarize(&ast, &resolved_graph);

    // Detectors
    let findings = detectors::run_detectors(&ast, &call_graph);

    // 4) Use findings (print, store, or feed into detectors)
    println!("functions={} calls={}", ast.functions.len(), resolved_graph.edges.len());
    println!("tainted_functions={}", taint_results.len());
    println!("summaries={}", summaries.len());
    println!("findings={}", findings.len());
    Ok(())
}
```

### Example B: Symbolic execution (path exploration)

```rust
use static_tool::{frontend, ir, cfg, ssa};

fn run_symbolic(path: &str) -> anyhow::Result<()> {
    let frontend_out = frontend::load_project(path)?;
    let ast = frontend_out.ast;
    let module = ir::lower_module(&ast);
    let cfgs = cfg::build_from_ir(&module);
    let ssa = ssa::build_ssa(&ast, &cfgs);

    // Pseudocode: interpret each function with a symbolic engine.
    for func in &module.functions {
        let cfg = &cfgs[func.id as usize];
        let ssa_fn = &ssa[func.id as usize];

        let mut engine = SymbolicEngine::new(func, cfg, ssa_fn);
        engine.explore_paths(|path_state| {
            if path_state.is_error_state() {
                println!("bug at {:?}", path_state.span());
            }
        });
    }
    Ok(())
}

// Example engine stub (you would implement these).
struct SymbolicEngine<'a> { /* ... */ }
impl<'a> SymbolicEngine<'a> {
    fn new(_f: &'a ir::IrFunction, _c: &'a cfg::CfgFunction, _s: &'a ssa::SsaFunction) -> Self {
        Self { /* ... */ }
    }
    fn explore_paths<F: FnMut(PathState)>(&mut self, _on_path: F) {
        // Walk CFG, fork on branches, build constraints, call SMT.
    }
}
struct PathState { /* ... */ }
impl PathState {
    fn is_error_state(&self) -> bool { false }
    fn span(&self) -> Option<(u32, u32)> { None }
}
```

### Example C: Fuzzing (target selection + harness generation)

```rust
use static_tool::{frontend, ir, cfg, ssa};

fn run_fuzz(path: &str) -> anyhow::Result<()> {
    let frontend_out = frontend::load_project(path)?;
    let ast = frontend_out.ast;
    let module = ir::lower_module(&ast);
    let cfgs = cfg::build_from_ir(&module);
    let ssa = ssa::build_ssa(&ast, &cfgs);

    // Pick entrypoints (public/external functions).
    let entrypoints = ast.functions.iter().filter(|f| {
        matches!(f.visibility, crate::norm::Visibility::Public | crate::norm::Visibility::External)
    });

    for func in entrypoints {
        let cfg = &cfgs[func.id as usize];
        let ssa_fn = &ssa[func.id as usize];

        // Build a fuzz harness for this function.
        let harness = Harness::from_function(func, cfg, ssa_fn);
        harness.run_campaign(|input| {
            // Execute on EVM (or instrumented runtime) and record coverage.
            // Use CFG edges and SSA to bias mutations.
            let _ = input;
        });
    }
    Ok(())
}

struct Harness { /* ... */ }
impl Harness {
    fn from_function(
        _func: &crate::norm::Function,
        _cfg: &cfg::CfgFunction,
        _ssa: &ssa::SsaFunction,
    ) -> Self {
        Self { /* ... */ }
    }
    fn run_campaign<F: FnMut(Vec<u8>)>(&self, _mutate: F) {
        // Seed inputs, mutate, track coverage, shrink crashes.
    }
}
```


## Tips and gotchas

- If M2 (partial) is used, results should be tagged **partial** and confidence lowered.
- Fuzzing should still run on partial mode, but must treat types as unknown.
- Symbolic execution can still run on partial mode if you restrict to syntax‑level constraints.
- Always use spans from the normalized AST/IR for reporting.


## Summary

- M1 + M2 are frontends; M3 is the shared analysis model.
- Static, symbolic, and fuzzing engines all consume the same IR/CFG/SSA.
- This keeps the tool consistent, extensible, and easier to maintain.
