//! ChainVet core: the shared types every engine and frontend agrees on.
//!
//! Normalized AST (`norm`), the SlithIR-style instruction set (`ir`), control-flow
//! graphs (`cfg`), SSA form (`ssa`), the finding/report model (`artifacts`), and
//! error types (`util`). Pure data and lowering — no engine logic, no I/O.

pub mod artifacts;
pub mod cfg;
pub mod ir;
pub mod norm;
pub mod ssa;
pub mod util;
