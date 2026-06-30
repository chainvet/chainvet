// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Multi-Phase Lending Pool with Cross-Function Reentrancy
/// @notice Reentrancy is hidden behind a state machine: you must register,
///         deposit, wait for cooldown, then withdraw — only the final step
///         has the bug, and only when multiple state variables align.
contract LendingPool {
    enum UserStatus { None, Registered, Active, Frozen }

    struct Account {
        UserStatus status;
        uint256 balance;
        uint256 collateral;
        uint256 lastAction;
        uint256 nonce;
    }

    mapping(address => Account) public accounts;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalDeposited;
    uint256 public totalBorrowed;
    uint256 public protocolFee;
    address public admin;
    bool public emergencyMode;

    event Registered(address indexed user);
    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);
    event Repaid(address indexed user, uint256 amount);

    constructor() {
        admin = msg.sender;
        protocolFee = 50; // 0.5%
    }

    // Step 1: Must register first
    function register() external {
        require(accounts[msg.sender].status == UserStatus.None, "Already registered");
        accounts[msg.sender].status = UserStatus.Registered;
        accounts[msg.sender].lastAction = block.timestamp;
        emit Registered(msg.sender);
    }

    // Step 2: Activate account by depositing collateral
    function depositCollateral() external payable {
        Account storage acc = accounts[msg.sender];
        require(acc.status == UserStatus.Registered || acc.status == UserStatus.Active, "Not registered");
        require(msg.value > 0, "Zero collateral");
        acc.collateral += msg.value;
        acc.status = UserStatus.Active;
        acc.lastAction = block.timestamp;
    }

    // Step 3: Deposit funds (only active users)
    function deposit() external payable {
        Account storage acc = accounts[msg.sender];
        require(acc.status == UserStatus.Active, "Not active");
        require(!emergencyMode, "Emergency mode");
        acc.balance += msg.value;
        totalDeposited += msg.value;
        acc.nonce += 1;
        acc.lastAction = block.timestamp;
        emit Deposited(msg.sender, msg.value);
    }

    // Step 4: Borrow against collateral — increases exposure
    function borrow(uint256 amount) external {
        Account storage acc = accounts[msg.sender];
        require(acc.status == UserStatus.Active, "Not active");
        require(acc.collateral >= amount * 2, "Insufficient collateral");
        uint256 fee = amount * protocolFee / 10000;
        acc.balance += amount;
        totalBorrowed += amount + fee;
        acc.lastAction = block.timestamp;
        emit Borrowed(msg.sender, amount);
    }

    // BUG: Cross-function reentrancy — withdraw sends ETH before updating
    // balance, and the accounting interacts with borrow() state.
    // Only reachable after register → depositCollateral → deposit → time passes.
    function withdraw(uint256 amount) external {
        Account storage acc = accounts[msg.sender];
        require(acc.status == UserStatus.Active, "Not active");
        require(acc.balance >= amount, "Insufficient balance");
        require(block.timestamp >= acc.lastAction + 10, "Cooldown active");
        require(!emergencyMode, "Emergency");

        // VULNERABLE: external call before state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        // State update after call — an attacker can re-enter via borrow()
        // to inflate their balance before this line executes
        acc.balance -= amount;
        totalDeposited -= amount;
        acc.nonce += 1;
    }

    // BUG: Delegated withdrawal — reentrancy through allowance mechanism
    function withdrawFor(address user, uint256 amount) external {
        require(allowances[user][msg.sender] >= amount, "No allowance");
        Account storage acc = accounts[user];
        require(acc.status == UserStatus.Active, "Not active");
        require(acc.balance >= amount, "Insufficient");

        allowances[user][msg.sender] -= amount;

        // VULNERABLE: sends to msg.sender (the delegate), not the account owner
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");

        acc.balance -= amount;
        totalDeposited -= amount;
    }

    function approve(address spender, uint256 amount) external {
        require(accounts[msg.sender].status == UserStatus.Active, "Not active");
        allowances[msg.sender][spender] = amount;
    }

    function setEmergency(bool flag) external {
        require(msg.sender == admin, "Not admin");
        emergencyMode = flag;
    }

    function repay(uint256 amount) external {
        Account storage acc = accounts[msg.sender];
        require(acc.status == UserStatus.Active, "Not active");
        require(acc.balance >= amount, "Nothing to repay");
        acc.balance -= amount;
        totalBorrowed -= amount;
        emit Repaid(msg.sender, amount);
    }
}
