// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Payment Splitter with DoS via Unbounded Loops
/// @notice DoS vulnerabilities hidden in a multi-party payment splitter:
///         payees register, income accumulates, then batch distribution
///         iterates all payees. Also includes a pull-payment pattern that
///         has a failed-call DoS and gas limit issues.
contract PaymentSplitter {
    struct Payee {
        address payable account;
        uint256 shares;
        uint256 released;
        bool active;
    }

    Payee[] public payees;
    mapping(address => uint256) public payeeIndex;
    mapping(address => uint256) public pendingPayments;
    mapping(address => bool) public isPayee;
    uint256 public totalShares;
    uint256 public totalReleased;
    uint256 public totalReceived;
    address public manager;
    bool public distributionLocked;

    event PayeeAdded(address account, uint256 shares);
    event PaymentReleased(address to, uint256 amount);

    constructor() {
        manager = msg.sender;
    }

    // Step 1: Add payees (builds up array)
    function addPayee(address payable account, uint256 shares) external {
        require(msg.sender == manager, "Not manager");
        require(!isPayee[account], "Already payee");
        require(shares > 0, "Zero shares");

        payeeIndex[account] = payees.length;
        payees.push(Payee({
            account: account,
            shares: shares,
            released: 0,
            active: true
        }));
        isPayee[account] = true;
        totalShares += shares;
        emit PayeeAdded(account, shares);
    }

    // Step 2: Receive payments
    receive() external payable {
        totalReceived += msg.value;
    }

    function receivePayment() external payable {
        require(msg.value > 0, "Zero payment");
        totalReceived += msg.value;
    }

    // BUG: DoS with block gas limit — iterates ALL payees
    // An attacker can add many payees to make this function run out of gas
    function distributeAll() external {
        require(msg.sender == manager, "Not manager");
        require(!distributionLocked, "Locked");
        distributionLocked = true;

        // BUG: unbounded loop over storage array
        for (uint256 i = 0; i < payees.length; i++) {
            if (!payees[i].active) continue;

            uint256 payment = _pendingPayment(i);
            if (payment > 0) {
                payees[i].released += payment;
                totalReleased += payment;
                // BUG: DoS with failed call — one revert blocks everyone
                payees[i].account.transfer(payment);
                emit PaymentReleased(payees[i].account, payment);
            }
        }
        distributionLocked = false;
    }

    // BUG: another unbounded loop — calculates total pending for all payees
    function totalPending() external view returns (uint256) {
        uint256 total = 0;
        // BUG: iterates entire array — DoS with gas limit
        for (uint256 i = 0; i < payees.length; i++) {
            if (payees[i].active) {
                total += _pendingPayment(i);
            }
        }
        return total;
    }

    // BUG: linear search for payee — O(n) lookup
    function findPayee(address account) external view returns (uint256) {
        for (uint256 i = 0; i < payees.length; i++) {
            if (payees[i].account == account) {
                return i;
            }
        }
        return type(uint256).max;
    }

    // Pull payment pattern — but still has issues
    function claimPayment() external {
        require(isPayee[msg.sender], "Not payee");
        uint256 idx = payeeIndex[msg.sender];
        uint256 payment = _pendingPayment(idx);
        require(payment > 0, "Nothing to claim");

        payees[idx].released += payment;
        totalReleased += payment;

        // BUG: unchecked call — return value not verified
        msg.sender.call{value: payment}("");
        emit PaymentReleased(msg.sender, payment);
    }

    function deactivatePayee(address account) external {
        require(msg.sender == manager, "Not manager");
        require(isPayee[account], "Not payee");
        uint256 idx = payeeIndex[account];
        payees[idx].active = false;
        totalShares -= payees[idx].shares;
    }

    function _pendingPayment(uint256 index) internal view returns (uint256) {
        if (totalShares == 0) return 0;
        uint256 totalDue = totalReceived * payees[index].shares / totalShares;
        if (totalDue <= payees[index].released) return 0;
        return totalDue - payees[index].released;
    }

    function payeeCount() external view returns (uint256) {
        return payees.length;
    }
}
