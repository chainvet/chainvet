// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Multi-Sig with Proxy Pattern — Unchecked Low-Level Calls
/// @notice Unchecked-call vulnerabilities hidden within a multi-sig wallet
///         that uses proxy calls and batch execution. The calls appear to
///         be guarded but return values are silently dropped.
contract MultiSigProxy {
    struct Transaction {
        address payable destination;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    mapping(address => bool) public isOwner;
    mapping(uint256 => mapping(address => bool)) public confirmed;
    address[] public owners;
    Transaction[] public transactions;
    uint256 public required;
    address public fallbackHandler;

    event Submitted(uint256 txId);
    event Confirmed(uint256 txId, address owner);
    event Executed(uint256 txId);

    constructor(address[] memory _owners, uint256 _required) {
        require(_owners.length >= _required, "Invalid config");
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
        }
        required = _required;
    }

    // Step 1: Submit transaction
    function submitTransaction(address payable dest, uint256 value, bytes calldata data) external returns (uint256) {
        require(isOwner[msg.sender], "Not owner");
        uint256 txId = transactions.length;
        transactions.push(Transaction({
            destination: dest,
            value: value,
            data: data,
            executed: false,
            confirmations: 0
        }));
        emit Submitted(txId);
        return txId;
    }

    // Step 2: Confirm transaction
    function confirmTransaction(uint256 txId) external {
        require(isOwner[msg.sender], "Not owner");
        require(txId < transactions.length, "Invalid tx");
        require(!confirmed[txId][msg.sender], "Already confirmed");

        confirmed[txId][msg.sender] = true;
        transactions[txId].confirmations += 1;
        emit Confirmed(txId, msg.sender);
    }

    // Step 3: Execute — BUG: return value of call is not checked
    function executeTransaction(uint256 txId) external {
        require(isOwner[msg.sender], "Not owner");
        Transaction storage txn = transactions[txId];
        require(!txn.executed, "Already executed");
        require(txn.confirmations >= required, "Not enough confirmations");

        txn.executed = true;

        // BUG: return value of call completely ignored
        // Transaction appears to succeed even if the call fails
        txn.destination.call{value: txn.value}(txn.data);
        emit Executed(txId);
    }

    // BUG: Batch execution — partial failures are silently ignored
    function executeBatch(uint256[] calldata txIds) external {
        require(isOwner[msg.sender], "Not owner");
        for (uint256 i = 0; i < txIds.length; i++) {
            Transaction storage txn = transactions[txIds[i]];
            if (!txn.executed && txn.confirmations >= required) {
                txn.executed = true;
                // BUG: call result ignored — some transfers may fail silently
                txn.destination.call{value: txn.value}(txn.data);
            }
        }
    }

    // BUG: proxy forwarding — delegatecall result not verified
    function setFallbackHandler(address handler) external {
        require(isOwner[msg.sender], "Not owner");
        fallbackHandler = handler;
    }

    // BUG: delegatecall without checking return
    function proxyForward(bytes calldata data) external {
        require(fallbackHandler != address(0), "No handler");
        // BUG: delegatecall return not checked — execution continues on failure
        (bool success, ) = fallbackHandler.delegatecall(data);
        // 'success' captured but never used — state may be corrupted
    }

    // BUG: send() return value dropped
    function refundOwner(address payable recipient, uint256 amount) external {
        require(isOwner[msg.sender], "Not owner");
        // BUG: send returns false on failure but result is ignored
        recipient.send(amount);
    }

    function transactionCount() external view returns (uint256) {
        return transactions.length;
    }

    receive() external payable {}
}
