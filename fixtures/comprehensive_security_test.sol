pragma solidity ^0.8.0;

contract ComprehensiveSecurityTest {
    address public owner;
    uint256 public balance;
    uint256 public timestamp;

    constructor() {
        owner = msg.sender;
    }

    // 1. tx.origin Misuse
    function withdrawAll(address payable _recipient) public {
        // DETECTOR: tx.origin used for authorization
        require(tx.origin == owner, "Not owner");
        _recipient.transfer(address(this).balance);
    }

    // 2. Delegatecall to untrusted address
    function forward(address _target, bytes memory _data) public {
        // DETECTOR: low-level call via delegatecall
        (bool success, ) = _target.delegatecall(_data);
        require(success, "Delegatecall failed");
    }

    // 3. Unchecked Low-Level Calls
    function sendMoney(address payable _to, uint256 _amount) public {
        // DETECTOR: unchecked low-level call via call
        _to.call{value: _amount}(""); 
        
        // DETECTOR: unchecked low-level call via send
        _to.send(_amount);
    }

    // 4. Selfdestruct
    function kill() public {
        require(msg.sender == owner, "Not owner");
        // DETECTOR: use of selfdestruct
        selfdestruct(payable(owner));
    }

    // 5. Timestamp Dependency
    function luckyDraw() public {
        // DETECTOR: block.timestamp used in conditional
        if (block.timestamp % 2 == 0) {
            balance += 1;
        }

        // DETECTOR: now used in conditional (older solidity alias)
        if (now % 2 == 0) {
            balance += 1;
        }
        
        // This should NOT trigger (assignment, not conditional)
        timestamp = block.timestamp;
    }

    // 6. Shadowing
    function shadowingTest(uint256 balance) public {
        // DETECTOR: variable 'balance' shadows state variable (param shadows state var - handled by logic?) 
        // Logic checks: for param in func.params { check if name shadows... wait.
        // detect_shadowing logic:
        // 1. Adds params to `local_vars` set.
        // 2. Recurses into body.
        // 3. If `Box<VarDecl>` encountered:
        //    - Check if name in `local_vars` (shadows local/param) -> FINDING
        //    - Check if name in `state_vars` -> FINDING
        //    - Add to `local_vars`

        // So params themselves are not checked against state vars in the current logic loops.
        // A variable declared IN the body that shadows a param will catch "shadows local variable".
        // A variable declared IN the body that shadows state var will catch "shadows state variable".

        uint256 owner = 123; // DETECTOR: variable 'owner' shadows state variable
        
        uint256 temp = 1;
        if (true) {
            uint256 temp = 2; // DETECTOR: variable 'temp' shadows existing local variable
        }
    }

    // 7. Reentrancy
    function withdraw(uint256 _amount) public {
        require(balance >= _amount, "Insufficient balance");

        // DETECTOR: potential reentrancy: state update after external call
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        balance -= _amount; // State update after external call
    }
}
