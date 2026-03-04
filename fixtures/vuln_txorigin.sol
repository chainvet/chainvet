// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Multi-Hop Relay Wallet with tx.origin Auth
/// @notice tx.origin usage hidden behind a relay/forwarder pattern:
///         the wallet dispatches calls through a relay, and the relay
///         uses tx.origin for critical auth decisions.
contract RelayWallet {
    struct Permit {
        address beneficiary;
        uint256 amount;
        uint256 deadline;
        bool executed;
    }

    mapping(address => uint256) public balances;
    mapping(uint256 => Permit) public permits;
    uint256 public permitCount;
    address public owner;
    address public relayer;
    uint256 public dailyLimit;
    uint256 public spentToday;
    uint256 public lastDay;

    event PermitCreated(uint256 id, address beneficiary, uint256 amount);
    event PermitExecuted(uint256 id);
    event Transferred(address from, address to, uint256 amount);

    constructor(address _relayer) {
        owner = msg.sender;
        relayer = _relayer;
        dailyLimit = 10 ether;
        lastDay = block.timestamp / 1 days;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: uses tx.origin for authentication — if owner interacts with
    // a malicious contract, that contract can call this through the relay
    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "tx.origin not owner");
        require(balances[owner] >= amount, "Insufficient");

        // Daily limit check
        uint256 today = block.timestamp / 1 days;
        if (today > lastDay) {
            spentToday = 0;
            lastDay = today;
        }
        spentToday += amount;

        balances[owner] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Transferred(owner, to, amount);
    }

    // Step 1: Create a permit (looks safe — uses msg.sender)
    function createPermit(address beneficiary, uint256 amount, uint256 deadlineOffset) external {
        require(msg.sender == owner, "Not owner");
        uint256 id = permitCount++;
        permits[id] = Permit({
            beneficiary: beneficiary,
            amount: amount,
            deadline: block.timestamp + deadlineOffset,
            executed: false
        });
        emit PermitCreated(id, beneficiary, amount);
    }

    // Step 2: Execute permit — BUG: uses tx.origin instead of msg.sender
    // This means a phishing contract can trick the owner into executing
    // an attacker's permit
    function executePermit(uint256 permitId) external {
        Permit storage p = permits[permitId];
        require(!p.executed, "Already executed");
        require(block.timestamp <= p.deadline, "Expired");
        // BUG: tx.origin auth — should be msg.sender == owner
        require(tx.origin == owner, "Not authorized");

        p.executed = true;
        require(balances[owner] >= p.amount, "Insufficient");
        balances[owner] -= p.amount;

        (bool ok, ) = p.beneficiary.call{value: p.amount}("");
        require(ok, "Execution failed");
        emit PermitExecuted(permitId);
    }

    // BUG: relay function uses tx.origin to determine sender role
    function relayCall(address payable destination, uint256 amount) external {
        require(msg.sender == relayer, "Not relayer");
        // BUG: tx.origin determines who pays — attacker can route through relay
        address payer = tx.origin;
        require(balances[payer] >= amount, "Insufficient");
        balances[payer] -= amount;
        (bool ok, ) = destination.call{value: amount}("");
        require(ok, "Relay failed");
    }

    function setDailyLimit(uint256 limit) external {
        // BUG: tx.origin auth on admin function
        require(tx.origin == owner, "Not owner");
        dailyLimit = limit;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
