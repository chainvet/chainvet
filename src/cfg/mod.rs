use std::collections::HashMap;

use crate::ir::{ControlKind, IrInstr, IrModule};

pub type BlockId = u32;

#[derive(Debug, Clone)]
pub struct CfgFunction {
    pub id: u32,
    pub blocks: Vec<Block>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone)]
pub struct Cfg {
    pub blocks: Vec<Block>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    pub instrs: Vec<IrInstr>,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub from: BlockId,
    pub to: BlockId,
}

pub fn build_from_ir(module: &IrModule) -> Vec<CfgFunction> {
    let mut cfgs = Vec::new();
    for func in &module.functions {
        let blocks = split_blocks(&func.blocks);
        let edges = build_edges(&blocks);
        cfgs.push(CfgFunction {
            id: func.id,
            blocks,
            edges,
        });
    }
    cfgs
}

#[derive(Clone)]
enum Terminator {
    Control(ControlKind),
    Return,
    None,
}

struct IfInfo {
    else_block: Option<usize>,
    end_block: usize,
}

struct TryInfo {
    catch_blocks: Vec<usize>,
    end_block: usize,
}

fn split_blocks(ir_blocks: &[crate::ir::IrBlock]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut current = Vec::new();
    let mut next_id: u32 = 0;

    let flush = |blocks: &mut Vec<Block>, current: &mut Vec<IrInstr>, next_id: &mut u32| {
        if current.is_empty() {
            return;
        }
        blocks.push(Block {
            id: *next_id,
            instrs: std::mem::take(current),
        });
        *next_id += 1;
    };

    for block in ir_blocks {
        for instr in &block.instrs {
            if should_split_before(instr) {
                flush(&mut blocks, &mut current, &mut next_id);
            }
            current.push(instr.clone());
            if is_split_point(instr) {
                flush(&mut blocks, &mut current, &mut next_id);
            }
        }
        flush(&mut blocks, &mut current, &mut next_id);
    }

    blocks
}

fn is_split_point(instr: &IrInstr) -> bool {
    matches!(instr, IrInstr::Control { .. } | IrInstr::Return { .. })
}

fn should_split_before(instr: &IrInstr) -> bool {
    match instr {
        IrInstr::Control { kind, .. } => matches!(
            kind,
            ControlKind::Else
                | ControlKind::EndIf
                | ControlKind::EndLoop
                | ControlKind::Catch
                | ControlKind::EndTry
        ),
        _ => false,
    }
}

fn build_edges(blocks: &[Block]) -> Vec<Edge> {
    let mut edges = Vec::new();
    let n = blocks.len();
    if n == 0 {
        return edges;
    }

    let terminators: Vec<Terminator> = blocks
        .iter()
        .map(block_terminator)
        .collect();

    let (if_map, loop_end_by_header, loop_header_by_end, try_map) = match_control(&terminators);
    let loop_context = build_loop_context(&terminators);
    let else_to_end = build_else_to_end(&if_map);
    let catch_to_end = build_catch_to_end(&try_map);

    let mut push_edge = |from_idx: usize, to_idx: usize| {
        let mut target = to_idx;
        if let Some(end) = else_to_end.get(&target) {
            target = *end;
        }
        if let Some(end) = catch_to_end.get(&target) {
            target = *end;
        }
        if target < n {
            edges.push(Edge {
                from: blocks[from_idx].id,
                to: blocks[target].id,
            });
        }
    };

    for i in 0..n {
        match &terminators[i] {
            Terminator::Return => continue,
            Terminator::Control(kind) => match kind {
                ControlKind::If { .. } => {
                    if let Some(info) = if_map.get(&i) {
                        if let Some(then_block) = next_index(i, n) {
                            push_edge(i, then_block);
                        }
                        if let Some(else_block) = info.else_block {
                            let else_body = else_block + 1;
                            if else_body < n {
                                push_edge(i, else_body);
                            } else if info.end_block < n {
                                push_edge(i, info.end_block);
                            }
                        } else if info.end_block < n {
                            push_edge(i, info.end_block);
                        }
                    } else if let Some(next) = next_index(i, n) {
                        push_edge(i, next);
                    }
                }
                ControlKind::Try => {
                    if let Some(info) = try_map.get(&i) {
                        let mut success = i + 1;
                        if let Some(first_catch) = info.catch_blocks.first() {
                            if *first_catch == success {
                                success = info.end_block;
                            }
                        }
                        if success < n {
                            push_edge(i, success);
                        }
                        for catch_block in &info.catch_blocks {
                            let body = catch_block + 1;
                            if body < n {
                                push_edge(i, body);
                            } else if info.end_block < n {
                                push_edge(i, info.end_block);
                            }
                        }
                    } else if let Some(next) = next_index(i, n) {
                        push_edge(i, next);
                    }
                }
                ControlKind::Else
                | ControlKind::EndIf
                | ControlKind::Catch
                | ControlKind::EndTry => {
                    if let Some(next) = next_index(i, n) {
                        push_edge(i, next);
                    }
                }
                ControlKind::Loop { cond } => {
                    if let Some(body) = next_index(i, n) {
                        push_edge(i, body);
                    }
                    if cond.is_some() {
                        if let Some(end_block) = loop_end_by_header.get(&i) {
                            let exit = end_block + 1;
                            if exit < n {
                                push_edge(i, exit);
                            }
                        }
                    }
                }
                ControlKind::EndLoop => {
                    if let Some(header) = loop_header_by_end.get(&i) {
                        push_edge(i, *header);
                    }
                }
                ControlKind::Break => {
                    if let Some(header) = loop_context[i] {
                        if let Some(end_block) = loop_end_by_header.get(&header) {
                            let exit = end_block + 1;
                            if exit < n {
                                push_edge(i, exit);
                            }
                        }
                    }
                }
                ControlKind::Continue => {
                    if let Some(header) = loop_context[i] {
                        push_edge(i, header);
                    }
                }
                ControlKind::Revert { .. } => {}
            },
            Terminator::None => {
                if let Some(next) = next_index(i, n) {
                    push_edge(i, next);
                }
            }
        }
    }

    edges
}

fn block_terminator(block: &Block) -> Terminator {
    match block.instrs.last() {
        Some(IrInstr::Return { .. }) => Terminator::Return,
        Some(IrInstr::Control { kind, .. }) => Terminator::Control(kind.clone()),
        _ => Terminator::None,
    }
}

fn match_control(
    terms: &[Terminator],
) -> (
    HashMap<usize, IfInfo>,
    HashMap<usize, usize>,
    HashMap<usize, usize>,
    HashMap<usize, TryInfo>,
) {
    let mut if_stack: Vec<(usize, Option<usize>)> = Vec::new();
    let mut if_map = HashMap::new();
    let mut loop_stack: Vec<usize> = Vec::new();
    let mut loop_end_by_header = HashMap::new();
    let mut loop_header_by_end = HashMap::new();
    let mut try_stack: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut try_map = HashMap::new();

    for (idx, term) in terms.iter().enumerate() {
        if let Terminator::Control(kind) = term {
            match kind {
                ControlKind::If { .. } => if_stack.push((idx, None)),
                ControlKind::Else => {
                    if let Some(frame) = if_stack.last_mut() {
                        frame.1 = Some(idx);
                    }
                }
                ControlKind::EndIf => {
                    if let Some((if_block, else_block)) = if_stack.pop() {
                        if_map.insert(
                            if_block,
                            IfInfo {
                                else_block,
                                end_block: idx,
                            },
                        );
                    }
                }
                ControlKind::Loop { .. } => loop_stack.push(idx),
                ControlKind::EndLoop => {
                    if let Some(header) = loop_stack.pop() {
                        loop_end_by_header.insert(header, idx);
                        loop_header_by_end.insert(idx, header);
                    }
                }
                ControlKind::Try => {
                    try_stack.push((idx, Vec::new()));
                }
                ControlKind::Catch => {
                    if let Some(frame) = try_stack.last_mut() {
                        frame.1.push(idx);
                    }
                }
                ControlKind::EndTry => {
                    if let Some((try_block, catch_blocks)) = try_stack.pop() {
                        try_map.insert(
                            try_block,
                            TryInfo {
                                catch_blocks,
                                end_block: idx,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    (if_map, loop_end_by_header, loop_header_by_end, try_map)
}

fn build_loop_context(terms: &[Terminator]) -> Vec<Option<usize>> {
    let mut context = Vec::with_capacity(terms.len());
    let mut stack: Vec<usize> = Vec::new();

    for (idx, term) in terms.iter().enumerate() {
        context.push(stack.last().copied());
        if let Terminator::Control(kind) = term {
            match kind {
                ControlKind::Loop { .. } => stack.push(idx),
                ControlKind::EndLoop => {
                    stack.pop();
                }
                _ => {}
            }
        }
    }

    context
}

fn build_else_to_end(if_map: &HashMap<usize, IfInfo>) -> HashMap<usize, usize> {
    let mut redirect = HashMap::new();
    for info in if_map.values() {
        if let Some(else_block) = info.else_block {
            redirect.insert(else_block, info.end_block);
        }
    }
    redirect
}

fn build_catch_to_end(try_map: &HashMap<usize, TryInfo>) -> HashMap<usize, usize> {
    let mut redirect = HashMap::new();
    for info in try_map.values() {
        for catch_block in &info.catch_blocks {
            redirect.insert(*catch_block, info.end_block);
        }
    }
    redirect
}

fn next_index(idx: usize, len: usize) -> Option<usize> {
    let next = idx + 1;
    if next < len {
        Some(next)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ControlKind, IrBlock, IrFunction, IrInstr, IrModule, IrValue, IrVar};
    use crate::norm::Span;
    use std::collections::HashSet;

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }

    fn cfg_from_instrs(instrs: Vec<IrInstr>) -> CfgFunction {
        let module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: None,
                source: None,
                span: span(),
                blocks: vec![IrBlock { id: 0, instrs }],
            }],
        };
        let mut cfgs = build_from_ir(&module);
        cfgs.remove(0)
    }

    fn edges_set(cfg: &CfgFunction) -> HashSet<(u32, u32)> {
        cfg.edges.iter().map(|edge| (edge.from, edge.to)).collect()
    }

    #[test]
    fn cfg_if_loop_else_edges() {
        let s = span();
        let instrs = vec![
            IrInstr::Control {
                kind: ControlKind::If {
                    cond: IrValue::Var(IrVar::Named("cond".to_string())),
                },
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::Loop {
                    cond: Some(IrValue::Var(IrVar::Named("loop".to_string()))),
                },
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::Break,
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::EndLoop,
                span: s,
            },
            IrInstr::Eval {
                expr: IrValue::Var(IrVar::Named("then".to_string())),
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::Else,
                span: s,
            },
            IrInstr::Eval {
                expr: IrValue::Var(IrVar::Named("else".to_string())),
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::EndIf,
                span: s,
            },
        ];

        let cfg = cfg_from_instrs(instrs);
        let expected: HashSet<(u32, u32)> = vec![
            (0, 1),
            (0, 6),
            (1, 2),
            (1, 4),
            (2, 4),
            (3, 1),
            (4, 7),
            (5, 6),
            (6, 7),
        ]
        .into_iter()
        .collect();

        assert_eq!(edges_set(&cfg), expected);
    }

    #[test]
    fn cfg_try_catch_edges() {
        let s = span();
        let instrs = vec![
            IrInstr::Eval {
                expr: IrValue::Var(IrVar::Named("pre".to_string())),
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::Try,
                span: s,
            },
            IrInstr::Eval {
                expr: IrValue::Var(IrVar::Named("try_body".to_string())),
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::Catch,
                span: s,
            },
            IrInstr::Eval {
                expr: IrValue::Var(IrVar::Named("catch_body".to_string())),
                span: s,
            },
            IrInstr::Control {
                kind: ControlKind::EndTry,
                span: s,
            },
        ];

        let cfg = cfg_from_instrs(instrs);
        let expected: HashSet<(u32, u32)> = vec![(0, 1), (0, 3), (1, 4), (2, 3), (3, 4)]
            .into_iter()
            .collect();

        assert_eq!(edges_set(&cfg), expected);
    }
}
