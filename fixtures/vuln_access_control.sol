// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Role-Based Access with Privilege Escalation Path
/// @notice Subtle access control bugs: role system looks safe but has a
///         privilege escalation path through the nominateAdmin flow and
///         an unprotected initializer that can be called after deployment.
contract RoleVault {
    enum Role { None, Member, Manager, Admin }

    struct UserInfo {
        Role role;
        uint256 balance;
        uint256 joinedAt;
        address nominatedBy;
    }

    mapping(address => UserInfo) public users;
    mapping(address => mapping(address => bool)) public approvals;
    address public pendingAdmin;
    address public owner;
    uint256 public totalFunds;
    bool private initialized;

    event RoleChanged(address indexed user, Role newRole);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
        users[msg.sender] = UserInfo(Role.Admin, 0, block.timestamp, address(0));
    }

    // BUG: initializer can be called again — "initialized" check is missing
    // a proper guard, allowing re-initialization to hijack the contract
    function initialize(address newOwner) external {
        require(!initialized, "Already initialized");
        // BUG: initialized is never set to true — can be called repeatedly
        owner = newOwner;
        users[newOwner].role = Role.Admin;
    }

    function deposit() external payable {
        require(users[msg.sender].role != Role.None, "Not a member");
        users[msg.sender].balance += msg.value;
        totalFunds += msg.value;
    }

    // Safe: manager-only function
    function addMember(address user) external {
        require(users[msg.sender].role >= Role.Manager, "Not manager");
        require(users[user].role == Role.None, "Already member");
        users[user] = UserInfo(Role.Member, 0, block.timestamp, msg.sender);
        emit RoleChanged(user, Role.Member);
    }

    // BUG: missing access control — anyone can nominate a new admin
    function nominateAdmin(address candidate) external {
        // Should check that msg.sender is Admin, but doesn't!
        pendingAdmin = candidate;
    }

    // BUG: accepts nomination without verifying nominator's role
    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Not nominated");
        users[msg.sender].role = Role.Admin;
        pendingAdmin = address(0);
        emit RoleChanged(msg.sender, Role.Admin);
    }

    // Protected withdrawal — but admin role can be stolen via nominateAdmin
    function adminWithdraw(uint256 amount) external {
        require(users[msg.sender].role == Role.Admin, "Not admin");
        require(amount <= totalFunds, "Insufficient");
        totalFunds -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
        emit Withdrawal(msg.sender, amount);
    }

    // BUG: upgradeable owner — anyone with Manager role can promote to Admin
    function promoteManager(address user) external {
        require(users[msg.sender].role == Role.Admin, "Not admin");
        require(users[user].role == Role.Member, "Not member");
        users[user].role = Role.Manager;
        emit RoleChanged(user, Role.Manager);
    }

    // BUG: no sender check — writes to storage with arbitrary user
    function setBalance(address user, uint256 amount) external {
        // Should have access control but doesn't
        users[user].balance = amount;
    }

    function getRole(address user) external view returns (Role) {
        return users[user].role;
    }
}
