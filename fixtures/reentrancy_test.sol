// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Reentrancy Test Cases
/// @notice Exercises all five Reentrancy detectors (RE-01..RE-05).

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyTests {

    mapping(address => uint256) public userBalance;
    mapping(address => uint256) public deposits;
    mapping(address => bool) public withdrawn;
    uint256 public totalDeposits;
    IERC20 public token;

    event Withdrawal(address indexed user, uint256 amount);
    event DepositEvent(address indexed user, uint256 amount);

    // ═══════════════════════════════════════════════════════════════════════
    //  RE-01  Reentrancy Vulnerability with Negative Events
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger RE-01: external call followed by state update AND emit.
    /// The event logs stale data because the attacker re-enters before
    /// the state is updated and the event is emitted.
    function withdrawWithEvent() public {
        uint256 bal = userBalance[msg.sender];
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        userBalance[msg.sender] = 0;
        emit Withdrawal(msg.sender, bal);
    }

    /// Should trigger RE-01: transfer + state update + emit.
    function withdrawTransferWithEvent() public {
        uint256 bal = userBalance[msg.sender];
        payable(msg.sender).transfer(bal);
        userBalance[msg.sender] = 0;
        emit Withdrawal(msg.sender, bal);
    }

    /// Should NOT trigger RE-01: state updated BEFORE the call (safe pattern).
    function safeWithdrawWithEvent() public {
        uint256 bal = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        emit Withdrawal(msg.sender, bal);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  RE-02  Reentrancy Vulnerability with Transfer
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger RE-02: .transfer() followed by state update.
    function withdrawViaTransfer() public {
        uint256 amount = userBalance[msg.sender];
        payable(msg.sender).transfer(amount);
        userBalance[msg.sender] = 0;
    }

    /// Should trigger RE-02: .send() followed by state update.
    function withdrawViaSend() public {
        uint256 amount = userBalance[msg.sender];
        bool sent = payable(msg.sender).send(amount);
        require(sent);
        userBalance[msg.sender] = 0;
    }

    /// Should NOT trigger RE-02: state updated before transfer (safe pattern).
    function safeWithdrawTransfer() public {
        uint256 amount = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  RE-03  Reentrancy Vulnerability with Same Effect
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger RE-03: `userBalance` is read before the call and
    /// written after — the classic DAO drain pattern.
    function withdrawBalance() public {
        uint256 bal = userBalance[msg.sender];
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        userBalance[msg.sender] = 0;
    }

    /// Should trigger RE-03: deposits read before, written after.
    function claimDeposit() public {
        uint256 dep = deposits[msg.sender];
        require(dep > 0);
        (bool ok, ) = msg.sender.call{value: dep}("");
        require(ok);
        deposits[msg.sender] = 0;
    }

    /// Should NOT trigger RE-03: different variable read vs written.
    function withdrawDifferentVar() public {
        uint256 amt = totalDeposits;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        userBalance[msg.sender] = 0;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  RE-04  Reentrancy Vulnerability with ETH Transfer
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger RE-04: .call{value: ...} followed by state update.
    function withdrawEth() public {
        uint256 bal = userBalance[msg.sender];
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        userBalance[msg.sender] = 0;
    }

    /// Should trigger RE-04: .transfer() (sends ETH) followed by state update.
    function withdrawEthTransfer() public {
        uint256 bal = userBalance[msg.sender];
        payable(msg.sender).transfer(bal);
        userBalance[msg.sender] = 0;
    }

    /// Should NOT trigger RE-04: state updated before ETH transfer (safe).
    function safeWithdrawEth() public {
        uint256 bal = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  RE-05  Reentrancy Vulnerability without ETH Transfer
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger RE-05: cross-contract call (no ETH) followed by
    /// state update.
    function withdrawTokens(address from, uint256 amount) public {
        token.transferFrom(from, address(this), amount);
        deposits[from] = deposits[from] - amount;
    }

    /// Should trigger RE-05: external call on interface followed by state update.
    function syncBalance(address user) public {
        uint256 bal = token.balanceOf(user);
        userBalance[user] = bal;
    }

    /// Should NOT trigger RE-05: no state update after the call.
    function checkBalance(address user) public view returns (uint256) {
        return token.balanceOf(user);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Safe patterns (should NOT trigger any RE-xx)
    // ═══════════════════════════════════════════════════════════════════════

    /// Checks-effects-interactions: update state first, then call.
    function safeWithdraw() public {
        uint256 bal = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }

    /// Internal function — should not trigger (private visibility).
    function _internalWithdraw(address to) internal {
        uint256 bal = userBalance[to];
        (bool success, ) = to.call{value: bal}("");
        require(success);
        userBalance[to] = 0;
    }

    /// Pure computation — no external calls at all.
    function computeReward(uint256 amount) public pure returns (uint256) {
        return amount * 2;
    }

    /// Receive function for accepting ETH.
    receive() external payable {}
}
