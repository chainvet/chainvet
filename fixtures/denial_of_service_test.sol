// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Denial of Service Test Cases
/// @notice Exercises all six Denial of Service detectors (DS-01..DS-06).

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-01  `transfer()` and `send()` with Hardcoded Gas Amount
// ═══════════════════════════════════════════════════════════════════════════════

contract DS01_HardcodedGas {

    /// Should trigger DS-01: uses `.transfer()` which forwards only 2300 gas.
    function unsafeTransfer(address payable recipient) public {
        recipient.transfer(1 ether);
    }

    /// Should trigger DS-01: uses `.send()` which forwards only 2300 gas.
    function unsafeSend(address payable recipient) public {
        bool ok = recipient.send(1 ether);
        require(ok, "send failed");
    }

    /// Should NOT trigger DS-01: uses `.call{value: ...}` which forwards
    /// all remaining gas (safe against future gas-cost changes).
    function safeCall(address payable recipient) public {
        (bool ok, ) = recipient.call{value: 1 ether}("");
        require(ok, "call failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-02  Contract Could Lock Ether
// ═══════════════════════════════════════════════════════════════════════════════

/// Should trigger DS-02: has a `receive()` but no withdrawal mechanism.
contract DS02_LockedEther {
    uint256 public total;

    receive() external payable {
        total += msg.value;
    }

    /// No withdraw function — ether is locked forever!
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/// Should NOT trigger DS-02: has payable + withdrawal.
contract DS02_Safe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-03  DoS with Block Gas Limit
// ═══════════════════════════════════════════════════════════════════════════════

contract DS03_BlockGasLimit {
    address[] public users;

    function addUser(address user) public {
        users.push(user);
    }

    /// Should trigger DS-03: for-loop iterates over dynamically-sized array.
    function distributeRewards() public {
        for (uint i = 0; i < users.length; i++) {
            // expensive operation for each user
            payable(users[i]).transfer(1 ether);
        }
    }

    uint256[] public data;

    /// Should trigger DS-03: while-loop uses `.length` in condition.
    function processAll() public {
        uint256 idx = 0;
        while (idx < data.length) {
            data[idx] = data[idx] * 2;
            idx++;
        }
    }

    /// Should trigger DS-03: loop body pushes to array (unbounded growth).
    function growInLoop() public {
        for (uint i = 0; i < 10; i++) {
            users.push(msg.sender);
        }
    }

    /// Should NOT trigger DS-03: fixed-size iteration (constant bound).
    function fixedLoop() public pure returns (uint256 sum) {
        for (uint i = 0; i < 10; i++) {
            sum += i;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-04  DoS with Failed Call
// ═══════════════════════════════════════════════════════════════════════════════

contract DS04_FailedCall {
    address payable[] public recipients;

    /// Should trigger DS-04: external call (.transfer) inside a for-loop.
    function pushPayments() public {
        for (uint i = 0; i < recipients.length; i++) {
            recipients[i].transfer(1 ether);
        }
    }

    mapping(address => uint256) public balances;

    /// Should NOT trigger DS-04: pull-payment pattern (recipient calls withdraw).
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-05  Force Sending Ether with `this.balance` Check
// ═══════════════════════════════════════════════════════════════════════════════

contract DS05_ForceEther {
    uint256 public expectedBalance;

    constructor() payable {
        expectedBalance = msg.value;
    }

    /// Should trigger DS-05: require() checks address(this).balance.
    /// Attacker can selfdestruct another contract to force-send Ether and
    /// break this invariant.
    function deposit() public payable {
        expectedBalance += msg.value;
        require(address(this).balance == expectedBalance, "balance mismatch");
    }

    /// Should trigger DS-05: assert() checks this.balance.
    function checkBalance() public view {
        assert(address(this).balance >= 1 ether);
    }

    /// Should NOT trigger DS-05: does not use this.balance in require/assert.
    function safeDeposit() public payable {
        expectedBalance += msg.value;
    }
}

/// Helper contract demonstrating selfdestruct-based force-send.
contract DS05_Attacker {
    /// Force-sends all Ether to `target` via selfdestruct.
    function attack(address payable target) public payable {
        selfdestruct(target);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DS-06  Unsafe `send()` in `require()` Condition
// ═══════════════════════════════════════════════════════════════════════════════

contract DS06_UnsafeSendRequire {

    /// Should trigger DS-06: `.send()` inside `require()` — a malicious
    /// recipient can always return false, causing permanent revert.
    function unsafePayment(address payable recipient) public {
        require(recipient.send(1 ether), "payment failed");
    }

    /// Should NOT trigger DS-06: `.send()` outside require, checked separately.
    function safePayment(address payable recipient) public {
        bool ok = recipient.send(1 ether);
        if (!ok) {
            // handle failure gracefully
            revert("payment failed");
        }
    }
}
