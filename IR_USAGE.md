# IR Usage Guide (Static / Symbolic / Fuzzing)

This document is for engine developers working on:

- Static analysis (`src/analysis`)
- Symbolic execution (`src/symbolic`)
- Fuzzing (`src/fuzzing`)

It explains how to consume the shared M3 model (IR/CFG/SSA) and how each mode should use it.

## Why This Matters

All modes should reason over the same program model so results are consistent:

1. Frontend (`solc` or parser fallback) builds `NormalizedAst`.
2. IR lowering builds `IrModule`.
3. CFG and SSA are built from IR/AST.

This avoids mode-specific parser behavior and makes findings comparable across engines.

## Core APIs You Will Use

```rust
use crate::{frontend, ir, cfg, ssa};

let output = frontend::load_project(path)?;    // Full or Partial frontend mode
let ast = &output.ast;

let ir_module = ir::lower_module(ast);         // M3 IR
let cfgs = cfg::build_from_ir(&ir_module);     // CFG from IR
let ssa_functions = ssa::build_ssa(ast, &cfgs);// SSA + def/use
```

Key files:

- `src/ir/mod.rs`: IR type system and opcodes (`IrInstr`, `IrValue`, `IrPlace`, `ControlKind`)
- `src/ir/lower.rs`: AST -> IR lowering semantics
- `src/cfg/mod.rs`: block splitting and control-flow edge construction
- `src/ssa/mod.rs`: SSA, phi insertion, def/use links

## IR Model (Tuple-Style Mental Model)

Rust uses enums, but this tuple view is useful while designing engines:

```text
# -- IR Instructions ---------------------------------------------------
("nop")
("eval", value)
("declare", [names], init?)                 # init optional
("assign", dest_var, src_value)
("store", dest_place, src_value)
("load", dest_var, src_place)
("binary", dest_var, op, lhs_value, rhs_value)
("unary", dest_var, op, expr_value, prefix_bool)
("call", [dest_vars], callee_value, [args], [call_options])
("select", dest_var, cond_value, then_value, else_value)
("emit", value)
("return", [values])
("control", control_kind)
("inline_asm", language?)                   # language optional

# -- Control Kinds -----------------------------------------------------
("if", cond_value)
("else")
("endif")
("loop", cond_value?)                       # cond optional
("endloop")
("break")
("continue")
("revert", value?)                          # value optional
("try")
("catch")
("endtry")

# -- Values ------------------------------------------------------------
("var", ("named", name))                    # IrVar::Named
("var", ("temp", id))                       # IrVar::Temp
("lit", kind, value)                        # norm::Literal
("unknown")

# -- Places ------------------------------------------------------------
("place_var", var, class)
("place_member", base_value, field, root?, class)
("place_index", base_value, index?, root?, class)

# class in {"storage", "memory", "unknown"}

# -- Call Options ------------------------------------------------------
("value", value_expr)
("gas", value_expr)
("salt", value_expr)
```

## Semantics You Should Treat As Canonical

- `Assign` writes to a variable (`IrVar`).
- `Store` writes to a place (`IrPlace`), often storage-sensitive.
- `Load` reads from a place into a variable.
- `Binary` and `Unary` normalize most expression operators.
- `Select` is ternary lowering.
- `Call.dest` can have 0, 1, or many destinations.
- `ControlKind` markers are structural; CFG turns them into real edges.
- `InlineAsm` and `Unknown` must be handled conservatively.

## How Static Analysis Uses IR Today

Current static pipeline combines AST-level and IR-level analyses:

- Call graph: `analysis::build_call_graph(ast)` (AST/meta-driven)
- Call resolution: `analysis::resolve_call_graph(ast, &graph)`
- Taint: `analysis::taint::analyze(ast, &cfgs)` (consumes IR instructions per CFG block)
- Summaries: `analysis::summary::summarize(ast, &resolved)`
- Detectors: `analysis::detectors::run_detectors(ast, &call_graph, &taint)`

Minimal static flow:

```rust
use crate::{analysis, cfg, ir};

let ir_module = ir::lower_module(ast);
let cfgs = cfg::build_from_ir(&ir_module);

let call_graph = analysis::build_call_graph(ast);
let resolved = analysis::resolve_call_graph(ast, &call_graph);
let taint = analysis::taint::analyze(ast, &cfgs);
let summaries = analysis::summary::summarize(ast, &resolved);
let findings = analysis::detectors::run_detectors(ast, &call_graph, &taint);
```

## How Symbolic Engine Should Use IR

`src/symbolic` is currently a skeleton; this is the intended consumption model.

State model recommendation:

- `env`: map `IrVar -> SymExpr`
- `storage`: map canonicalized storage place -> `SymExpr`
- `memory`: map canonicalized memory place -> `SymExpr`
- `path_constraints`: list of boolean constraints

Execution strategy:

1. Build `ir_module`, `cfgs`, `ssa_functions`.
2. Explore per function using CFG edges.
3. Execute instructions in each block:
   - `Assign`, `Binary`, `Unary`, `Select`: build symbolic expressions
   - `Load`/`Store`: read/write symbolic memory models
   - `Call`: model side effects or mark unknown effects
   - `ControlKind::If/Loop`: fork states with true/false constraints
4. Use SSA def/use to prune irrelevant symbols and simplify constraints.

Important details:

- Prefer CFG edges over raw `ControlKind` markers for control transitions.
- Treat `IrValue::Unknown` as unconstrained symbolic top value.
- For `PlaceClass::Unknown`, assume worst-case aliasing with storage.
- Treat `InlineAsm` as havoc (or function-level fallback) unless modeled.

### Instruction-by-Instruction Symbolic Semantics

This is the practical mapping symbolic developers usually need when implementing the interpreter.

#### Base helper: value evaluation

Before handling instructions, define:

- `eval(IrValue::Var(v)) -> env[v]` (or fresh symbolic variable if missing)
- `eval(IrValue::Literal(l)) -> concrete/symbolic constant`
- `eval(IrValue::Unknown) -> fresh unconstrained symbolic variable`

#### `Assign`, `Binary`, `Unary`, `Select` (the core expression builders)

`Assign`:

```text
v = eval(src)
env[dest] = v
```

Notes:

- `Assign` only writes `IrVar`.
- Storage-like writes do not use `Assign`; they use `Store`.

`Binary`:

```text
l = eval(lhs)
r = eval(rhs)
env[dest] = simplify(bin(op, l, r))
```

Examples:

- `op="+"` -> `l + r`
- `op="=="` -> `l == r`
- `op="&&"` -> `and(l, r)`

`Unary`:

```text
v = eval(expr)
env[dest] = simplify(unary(op, v, prefix))
```

Notes:

- In current lowering, `++/--` are mostly lowered into `Binary` + writeback (not left as `Unary`).
- `prefix` is still provided and should be preserved for exact semantics if needed.

`Select` (ternary):

```text
c = eval(cond)
t = eval(then_val)
e = eval(else_val)
env[dest] = ite(c, t, e)
```

Important:

- `Select` is expression-level choice (`ite`) and usually does not fork paths.
- Path forking is usually done at branch control (`ControlKind::If`, loop conditions).

#### Other instructions symbolic devs will use

`Declare`:

- Register named variables in `env`.
- If `init` is present, assign `eval(init)` to each declared variable as appropriate.
- If unknown, initialize conservatively (fresh symbolic).

`Load` / `Store`:

- Build a canonical key for `IrPlace` (`Var`/`Member`/`Index` + class + root/field/index).
- `Load`: `env[dest] = heap_read(place_key)`.
- `Store`: `heap_write(place_key, eval(src))`.
- Keep storage and memory separate when `PlaceClass` is known.
- If `PlaceClass::Unknown`, either:
  - write to both models conservatively, or
  - use a merged unknown heap model.

`Call`:

- Evaluate `callee`, `args`, and `options`.
- Decide a policy:
  - summary-based (preferred for precision), or
  - havoc (all affected state becomes unknown).
- For each destination in `dest`, assign returned symbolic values.
- Include call-option constraints when needed (`value`, `gas`, `salt`).

`Control`:

- `If { cond }`: evaluate condition and fork path states with `cond` / `!cond`.
- `Loop { cond }`: same branch logic plus loop bounding/merging policy.
- `Break` / `Continue`: follow CFG edges accordingly.
- `Revert`: terminate path (optionally record failing model).
- `Try` / `Catch` / `EndTry`: use CFG edges; optionally fork call-success/call-failure.

`Return`:

- Evaluate return values and terminate current function path.

`Eval`:

- Evaluate for side effects/constraint collection; result may be ignored.

`Emit`:

- Usually ignored for safety properties, but useful for trace/event assertions.

`InlineAsm` and `Unknown`:

- Treat as conservative havoc unless you have a dedicated model.

### Minimal Symbolic Interpreter Pseudocode

```text
for block in cfg_path:
  for instr in block.instrs:
    match instr:
      Assign  => env[dest] = eval(src)
      Binary  => env[dest] = bin(op, eval(lhs), eval(rhs))
      Unary   => env[dest] = unary(op, eval(expr), prefix)
      Select  => env[dest] = ite(eval(cond), eval(then), eval(else))
      Load    => env[dest] = heap_read(key(src_place))
      Store   => heap_write(key(dest_place), eval(src))
      Call    => model_call(...)
      Control => branch/terminate by kind
      Return  => finish_path
      _       => conservative handling
```

## How Fuzzing Engine Should Use IR

`src/fuzzing` is currently a skeleton; this is the intended model.

Target selection inputs:

- AST visibility/public entrypoints
- CFG complexity (branches, loops, depth)
- IR signals (`Store`, external-like `Call`, revert paths)
- Static summaries (`storage_writes`, `low_level_calls`, `unresolved_calls`)

Harness generation inputs:

- Function signatures from normalized AST
- Call behavior hints from IR (`Call`, `CallOption::Value/Gas/Salt`)
- State-mutating behavior via `Store` and storage-class places

Feedback guidance:

- CFG edge coverage
- New path conditions (from branch-driving operands)
- New storage-write patterns (new `IrPlace` roots/fields/indexes)

Practical loop:

1. Seed with callable public/external functions.
2. Prioritize functions with high-risk IR patterns.
3. Mutate toward uncovered CFG edges.
4. Use IR + spans to minimize and report crashes/findings precisely.

## IR Dumps for Debugging

```bash
# text dump
cargo run -- --static <path-to-solidity> --dump-ir text

# json dump
cargo run -- --static <path-to-solidity> --dump-ir json
```

Use dumps to validate:

- Lowering output for tricky syntax
- Storage/memory place classification
- Control markers around nested branches/loops/try-catch

## Invariants and Gotchas

- `IrFunction.source` links IR function back to AST function id.
- IR currently starts as one logical block per function; CFG re-splits by control instructions.
- `Call.dest` may be empty (ignored return), single, or tuple-like multi return.
- Tuple declarations/assignments are lowered into multiple writes.
- On parser fallback (`FrontendMode::Partial`), keep analyses conservative and confidence-aware.

## Suggested Next Steps for Contributors

For symbolic:

- Implement `SymExpr`, symbolic state, and an instruction interpreter over `IrInstr`.
- Add branch forking over CFG with solver-backed feasibility checks.

For fuzzing:

- Build a function-priority scorer using CFG + IR + summaries.
- Generate ABI-aware seeds and coverage-guided mutators tied to IR branch operands.

For static:

- Keep detectors span-based and conservative when IR/AST values are `Unknown`.
