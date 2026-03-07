# ── Intermediate Representation (IR) ──────────────────────────
# Each instruction is a tuple whose first element is the opcode.
#
# Supported opcodes:
#   ("assign", var, expr)              – env[var] = eval(expr)
#   ("sload", var, slot_expr)          – env[var] = storage[slot]  (symbolic)
#   ("sstore", slot_expr, val_expr)    – storage[slot] = eval(val_expr)
#   ("branch", cond_expr, true_pc, false_pc)
#   ("halt",)                          – terminate current path
#
# Expressions are nested tuples:
#   ("const", n)                       – literal integer
#   ("var", name)                      – lookup in env
#   ("add", e1, e2)                    – e1 + e2
#   ("sub", e1, e2)                    – e1 - e2
#   ("mul", e1, e2)                    – e1 * e2
#   ("gt", e1, e2)                     – e1 > e2
#   ("lt", e1, e2)                     – e1 < e2
#   ("eq", e1, e2)                     – e1 == e2
#   ("not", e)                         – logical not
# ──────────────────────────────────────────────────────────────

# Example program – models a simplified smart-contract function:
#
#   function withdraw(amount):
#       if amount > balance:    # overflow / insufficient-balance check
#           halt                # revert
#       balance = balance - amount
#       halt                    # success
#
# IR encoding (index = pc):


# fn withdraw (id 1, source 1) {
#   block 0:
#     ("load", ("temp", 0), ("place_var", ("named", "balance"), "storage"))
#     ("binary", ("temp", 1), ">", ("var", ("named", "amount")), ("var", ("temp", 0)))
#     ("control", ("if", ("var", ("temp", 1))))
#     ("control", ("revert"))
#     ("control", ("endif"))
#     ("load", ("temp", 2), ("place_var", ("named", "balance"), "storage"))
#     ("binary", ("temp", 3), "-", ("var", ("temp", 2)), ("var", ("named", "amount")))
#     ("store", ("place_var", ("named", "balance"), "storage"), ("var", ("temp", 3)))
# }

PROGRAM_SAFE = [
    # 0: load balance from storage slot 0
    ("sload", "balance", ("const", 0)),
    # 1: branch – amount > balance ? → pc 2 (revert) : pc 3 (continue)
    ("branch", ("gt", ("var", "amount"), ("var", "balance")), 2, 3),
    # 2: revert path
    ("halt",),
    # 3: new_balance = balance - amount
    ("assign", "new_balance", ("sub", ("var", "balance"), ("var", "amount"))),
    # 4: store new_balance back to slot 0
    ("sstore", ("const", 0), ("var", "new_balance")),
    # 5: success path
    ("halt",),
]

# Vulnerable version – no balance check before subtraction!
#
#   function withdraw(amount):
#       balance = balance - amount    # underflow possible!
#       halt
#
PROGRAM_VULN = [
    # 0: load balance from storage slot 0
    ("sload", "balance", ("const", 0)),
    # 1: new_balance = balance - amount  (NO guard — can underflow)
    ("assign", "new_balance", ("sub", ("var", "balance"), ("var", "amount"))),
    # 2: store new_balance back to slot 0
    ("sstore", ("const", 0), ("var", "new_balance")),
    # 3: success path (always reached)
    ("halt",),
]

PROGRAM = PROGRAM_VULN  # ← switch to PROGRAM_VULN to test the vulnerable version

vulns = 0

##### Symbolic Execution Engine #####
import copy
from z3 import Solver, Int, And, Not, sat, unsat

# Symbolic execution state
class State:
    def __init__(self):
        self.pc = 0
        self.env = {}
        self.storage = {}
        self.path_constraints = []

def underflow_check(state, a, b):
    global vulns
    """Check if b > a (meaning a - b would underflow)."""
    solver = Solver()
    solver.add(*state.path_constraints)
    solver.add(b > a)
    if solver.check() == sat:
        print(f"⚠ UNDERFLOW DETECTED at pc={state.pc}")
        print(f"  Trigger: {solver.model()}")
        vulns += 1

def eval_expr(state, expr):
    match expr[0]:
        case "const":
            return expr[1]
        case "var":
            if expr[1] not in state.env:
                state.env[expr[1]] = Int(expr[1]) # Create symbolic variable if not concrete
            return state.env[expr[1]]
        case "add":
            return eval_expr(state, expr[1]) + eval_expr(state, expr[2])
        case "sub":
            a = eval_expr(state, expr[1])
            b = eval_expr(state, expr[2])
            underflow_check(state, a, b)  # Check for potential underflow before subtraction
            return a - b
        case "mul":
            return eval_expr(state, expr[1]) * eval_expr(state, expr[2])
        case "gt":
            return eval_expr(state, expr[1]) > eval_expr(state, expr[2])
        case "lt":
            return eval_expr(state, expr[1]) < eval_expr(state, expr[2])
        case "eq":
            return eval_expr(state, expr[1]) == eval_expr(state, expr[2])
        case "not":
            return Not(eval_expr(state, expr[1]))

def assign(state, var, expr):
    value = eval_expr(state, expr)
    state.env[var] = value
    state.pc += 1
    return state  # Return updated state for worklist

def sload(state, var, slot_expr):
    slot = eval_expr(state, slot_expr)
    if slot not in state.storage:
        state.storage[slot] = Int(f"storage_{slot}_{var}")  # fresh symbolic value
    state.env[var] = state.storage[slot]
    state.pc += 1
    return state  # Return updated state for worklist

def sstore(state, slot_expr, val_expr):
    slot = eval_expr(state, slot_expr)
    value = eval_expr(state, val_expr)
    state.storage[slot] = value
    state.pc += 1
    return state  # Return updated state for worklist

def branch(state, cond_expr, true_pc, false_pc, worklist):
    z3_cond = eval_expr(state, cond_expr)

    # Create two new states for true and false branches
    true_state = copy.deepcopy(state)
    true_state.path_constraints.append(z3_cond)
    true_state.pc = true_pc

    solver = Solver()
    solver.add(*true_state.path_constraints)
    if solver.check() == sat:
        worklist.append(true_state)

    false_state = copy.deepcopy(state)
    false_state.path_constraints.append(Not(z3_cond))
    false_state.pc = false_pc

    solver = Solver()
    solver.add(*false_state.path_constraints)
    if solver.check() == sat:
        worklist.append(false_state)

def halt(state):
    solver = Solver()
    solver.add(*state.path_constraints)
    if solver.check() == sat:
        print(f"Reachable path: {state.pc}")
        print("  Constraints:", state.path_constraints)
        print("  Model:", solver.model())
    else:
        print("Unreachable path")

def execution_loop(initial_state):
    # Initial state: pc=0, empty env, empty storage, no constraints
    worklist = [initial_state]

    while worklist:
        state = worklist.pop()

        instr = PROGRAM[state.pc]
        opcode = instr[0]

        match opcode:
            case "assign":
                var = instr[1]
                expr = instr[2]
                worklist.append(assign(state, var, expr))
            case "sload":
                var = instr[1]
                slot_expr = instr[2]
                worklist.append(sload(state, var, slot_expr))
            case "sstore":
                slot_expr = instr[1]
                val_expr = instr[2]
                worklist.append(sstore(state, slot_expr, val_expr))
            case "branch":
                cond_expr = instr[1]
                true_pc = instr[2]
                false_pc = instr[3]
                branch(state, cond_expr, true_pc, false_pc, worklist)  # Implement branching logic
            case "halt":
                halt(state)  # Implement halting logic
            case _:
                raise Exception(f"Unknown opcode: {opcode}")

if __name__ == "__main__":
    print("Starting symbolic execution...")
    initial_state = State()
    execution_loop(initial_state)
    if vulns > 0:
        print(f"Total vulnerabilities found: {vulns}")
    else:
        print("No vulnerabilities detected.")