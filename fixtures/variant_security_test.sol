pragma solidity ^0.8.0;

contract VariantSecurityTest {
    uint256 public lockedUntil;
    mapping(address => uint256) public balances;
    address public admin;

    function ModifierTimestamp() public {
        // Variant 1: Check block.timestamp in require
        require(block.timestamp > lockedUntil, "Locked");
        
        // Variant 2: Check now in require
        require(now > lockedUntil, "Also locked");
    }

    function LoopReentrancy(address _target) public {
        // Variant 3: Reentrancy inside a loop
        for (uint i = 0; i < 5; i++) {
            // External call
            (bool success, ) = _target.call("");
            require(success);
            // State update after call in loop
            balances[msg.sender] += 1;
        }
    }

    function ConditionalReentrancy(address _target) public {
        // Variant 4: Call in condition
        // note: our detector might miss this if it doesn't scan conditions for calls, 
        // OR it might catch it if `call` is considered an external call statement.
        // Actually, if `call` is in condition, it is an Expr.
        // My detector checks StmtKind::Expr(expr_id).
        // If it sends `call` as part of `If` condition, it is NOT StmtKind::Expr(expr_id).
        // It is `If { cond: expr_id, ... }`.
        // My detector `check_reentrancy_in_stmt` handles `If`, recurse to `then/else`.
        // It does NOT check `cond` for external call to set the "seen" flag.
        // So this is a known limitation I might discover.
        
        if (_target.call(abi.encodeWithSignature("ping()"))) { // This is bool result
           balances[msg.sender] = 0; // State update
        }
    }

    function ShadowingVariants() public {
        // Variant 5: Shadowing in for-loop init
        for (uint256 admin = 0; admin < 10; admin++) { // Shadows 'admin' state var
            // do something
        }

        // Variant 6: Shadowing in nested block
        {
            uint256 balances = 100; // Shadows 'balances' state var
        }
    }

    function TxOriginInIf() public {
        // Variant 7: tx.origin in if
        if (tx.origin != msg.sender) {
            // slightly legitimate use check, but still flags as potential phising risk
        }
    }
}
