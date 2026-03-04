// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Upgradeable Contract with Hidden Selfdestruct
/// @notice selfdestruct is hidden behind a two-phase upgrade pattern
///         and a sunset mechanism. The proxy setup makes it look safe
///         but the implementation can be swapped and then destroyed.
contract UpgradeableVault {
    address public implementation;
    address public owner;
    address public pendingOwner;
    mapping(address => uint256) public balances;
    uint256 public totalLocked;
    uint256 public deployTime;
    uint256 public sunsetDate;
    bool public sunsetMode;

    event Upgraded(address newImpl);
    event SunsetActivated(uint256 sunsetDate);
    event Destroyed(address recipient);

    constructor() {
        owner = msg.sender;
        deployTime = block.timestamp;
        sunsetDate = block.timestamp + 365 days;
    }

    function deposit() external payable {
        require(!sunsetMode, "Contract sunsetting");
        balances[msg.sender] += msg.value;
        totalLocked += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        totalLocked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }

    // Step 1: Upgrade implementation (owner-only, looks safe)
    function upgrade(address newImpl) external {
        require(msg.sender == owner, "Not owner");
        require(newImpl != address(0), "Zero address");
        implementation = newImpl;
        emit Upgraded(newImpl);
    }

    // Step 2: Activate sunset mode
    function activateSunset() external {
        require(msg.sender == owner, "Not owner");
        sunsetMode = true;
        sunsetDate = block.timestamp + 30 days;
        emit SunsetActivated(sunsetDate);
    }

    // Step 3: BUG: selfdestruct behind sunset check — but the sunset
    // can be activated by anyone who becomes owner
    function destroyContract(address payable recipient) external {
        require(msg.sender == owner, "Not owner");
        require(sunsetMode, "Not in sunset");
        require(block.timestamp > sunsetDate, "Too early");
        emit Destroyed(recipient);
        selfdestruct(recipient);
    }

    // BUG: Unprotected ownership claim — the two-phase transfer has
    // a race condition: anyone can front-run the pending owner
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        pendingOwner = newOwner;
    }

    // BUG: No check that msg.sender == pendingOwner in some paths
    function claimOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // BUG: Emergency destroy — has owner check but no sunset check
    // This is a shortcut that bypasses the sunset mechanism entirely
    function emergencyDestroy(address payable recipient) external {
        require(msg.sender == owner, "Not owner");
        // Missing sunsetMode check — can destroy immediately
        selfdestruct(recipient);
    }

    // BUG: delegatecall to implementation — implementation can selfdestruct
    function delegateToImpl(bytes calldata data) external {
        require(implementation != address(0), "No impl");
        (bool ok, ) = implementation.delegatecall(data);
        require(ok, "Delegate failed");
    }
}
