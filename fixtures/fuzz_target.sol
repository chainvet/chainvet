// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FuzzTarget {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    bool public locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Reentrancy vulnerability: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Timestamp dependency: using block.timestamp in a conditional
    function timeLock() external view returns (bool) {
        if (block.timestamp > 1000) {
            return true;
        }
        return false;
    }

    // Unchecked low-level call
    function unsafeSend(address payable target, uint256 amount) external {
        target.call{value: amount}("");
    }

    // Integer overflow potential (pre-0.8 pattern, still detectable)
    function addReward(uint256 bonus) external {
        uint256 reward = totalDeposits + bonus;
        balances[msg.sender] += reward;
    }

    // State update function for dependency chaining
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    // Function that reads state set by setOwner
    function ownerWithdraw() external {
        require(msg.sender == owner, "Not owner");
        uint256 bal = address(this).balance;
        (bool ok, ) = owner.call{value: bal}("");
        require(ok, "Transfer failed");
    }
}
