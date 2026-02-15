// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    /* =========================
       TX.ORIGIN VULNERABILITY
       ========================= */
    function txOriginAuth() public {
        // ❌ BAD: tx.origin used for authorization
        require(tx.origin == owner, "not owner");
    }

    /* =========================
       DELEGATECALL VULNERABILITY
       ========================= */
    function unsafeDelegate(address target, bytes memory data) public {
        // ❌ BAD: delegatecall
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    /* =========================
       UNCHECKED LOW-LEVEL CALL
       ========================= */
    function uncheckedCall(address target) public {
        // ❌ BAD: return value ignored
        target.call("hello");
    }

    /* =========================
       SELFDESTRUCT VULNERABILITY
       ========================= */
    function kill() public {
        // ❌ BAD: selfdestruct
        selfdestruct(payable(msg.sender));
    }

    /* =========================
       TIMESTAMP DEPENDENCY
       ========================= */
    function timeBasedLogic() public {
        // ❌ BAD: block.timestamp in condition
        if (block.timestamp % 2 == 0) {
            balances[msg.sender] += 1;
        }
    }

    /* =========================
       SHADOWING VULNERABILITY
       ========================= */
    function shadowingExample(uint256 owner) public {
        // ❌ BAD: parameter shadows state variable "owner"
        balances[msg.sender] = owner;
    }

    /* =========================
       REENTRANCY VULNERABILITY
       ========================= */
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "not enough");

        // ❌ BAD: external call before state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");

        // ❌ BAD: state update after external call
        balances[msg.sender] -= amount;
    }

    /* =========================
       SUPPORT FUNCTIONS
       ========================= */
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
