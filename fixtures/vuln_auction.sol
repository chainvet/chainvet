// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title DeFi Staking Vault — Multiple Vulnerability Classes Combined
/// @notice A realistic DeFi vault with: reentrancy in compound(), overflow
///         in reward math, timestamp-dependent epoch transitions, unchecked
///         calls in emergency withdrawal, missing access control on epoch
///         advance, and exception disorder in batch harvest.
contract StakingVault {
    struct Position {
        uint256 staked;
        uint256 rewardDebt;
        uint256 entryEpoch;
        uint256 lastClaimTime;
        bool active;
    }

    struct Epoch {
        uint256 startTime;
        uint256 endTime;
        uint256 rewardPool;
        uint256 totalStaked;
        bool finalized;
    }

    mapping(address => Position) public positions;
    mapping(uint256 => Epoch) public epochs;
    mapping(address => uint256) public pendingRewards;
    uint256 public currentEpoch;
    uint256 public totalStaked;
    uint256 public totalRewardsDistributed;
    address public governance;
    uint256 public epochDuration;
    uint256 public rewardMultiplier;
    bool public paused;

    event Staked(address indexed user, uint256 amount, uint256 epoch);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event EpochAdvanced(uint256 newEpoch);

    constructor(uint256 _epochDuration) {
        governance = msg.sender;
        epochDuration = _epochDuration;
        rewardMultiplier = 250;
        currentEpoch = 0;
        epochs[0] = Epoch({
            startTime: block.timestamp,
            endTime: block.timestamp + _epochDuration,
            rewardPool: 0,
            totalStaked: 0,
            finalized: false
        });
    }

    // Step 1: Stake into current epoch
    function stake() external payable {
        require(!paused, "Paused");
        require(msg.value > 0, "Zero stake");
        // BUG: timestamp dependency — epoch check based on block.timestamp
        require(block.timestamp < epochs[currentEpoch].endTime, "Epoch ended");

        Position storage pos = positions[msg.sender];
        if (pos.active) {
            // Accumulate pending rewards before modifying position
            pendingRewards[msg.sender] += _calculateReward(msg.sender);
        }

        pos.staked += msg.value;
        pos.entryEpoch = currentEpoch;
        pos.lastClaimTime = block.timestamp;
        pos.active = true;

        totalStaked += msg.value;
        epochs[currentEpoch].totalStaked += msg.value;
        emit Staked(msg.sender, msg.value, currentEpoch);
    }

    // BUG: Missing access control — anyone can advance the epoch
    // Should be governance-only but check is missing
    function advanceEpoch() external {
        // BUG: timestamp dependency
        require(block.timestamp >= epochs[currentEpoch].endTime, "Epoch not ended");
        epochs[currentEpoch].finalized = true;

        currentEpoch += 1;
        epochs[currentEpoch] = Epoch({
            startTime: block.timestamp,
            endTime: block.timestamp + epochDuration,
            rewardPool: 0,
            totalStaked: totalStaked,
            finalized: false
        });
        emit EpochAdvanced(currentEpoch);
    }

    // Fund the reward pool for current epoch
    function fundRewardPool() external payable {
        require(msg.sender == governance, "Not governance");
        epochs[currentEpoch].rewardPool += msg.value;
    }

    // BUG: Reentrancy — compound sends ETH then updates state
    function compoundRewards() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No position");

        uint256 reward = _calculateReward(msg.sender) + pendingRewards[msg.sender];
        require(reward > 0, "No rewards");

        pendingRewards[msg.sender] = 0;
        totalRewardsDistributed += reward;

        // BUG: external call before state update — reentrancy vector
        // Sends reward to user, who can re-enter compoundRewards
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "Reward send failed");

        // State update after call
        pos.rewardDebt += reward;
        pos.lastClaimTime = block.timestamp;
    }

    // BUG: Exception disorder in batch harvest — failures silently ignored
    function batchHarvest(address[] calldata users) external {
        require(msg.sender == governance, "Not governance");
        for (uint256 i = 0; i < users.length; i++) {
            Position storage pos = positions[users[i]];
            if (!pos.active) continue;

            uint256 reward = _calculateReward(users[i]);
            if (reward > 0) {
                pos.rewardDebt += reward;
                // BUG: call return value not checked — some users may not receive
                users[i].call{value: reward}("");
                totalRewardsDistributed += reward;
            }
        }
    }

    // BUG: Unchecked call in emergency withdrawal
    function emergencyWithdraw() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No position");

        uint256 amount = pos.staked;
        pos.staked = 0;
        pos.active = false;
        totalStaked -= amount;

        // BUG: unchecked call — user may not receive their funds
        msg.sender.call{value: amount}("");
    }

    function unstake() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No position");
        // BUG: timestamp dependency
        require(block.timestamp >= pos.lastClaimTime + 100, "Cooldown");

        uint256 reward = _calculateReward(msg.sender) + pendingRewards[msg.sender];
        uint256 total = pos.staked + reward;

        pos.staked = 0;
        pos.active = false;
        pendingRewards[msg.sender] = 0;
        totalStaked -= pos.staked;

        (bool ok, ) = msg.sender.call{value: total}("");
        require(ok, "Unstake failed");
        emit Unstaked(msg.sender, total);
    }

    // BUG: overflow in reward calculation with large stakes and multipliers
    function _calculateReward(address user) internal view returns (uint256) {
        Position storage pos = positions[user];
        if (!pos.active || pos.staked == 0) return 0;

        uint256 elapsed = block.timestamp - pos.lastClaimTime;
        // BUG: multiplication can overflow with large staked amounts
        uint256 reward = pos.staked * rewardMultiplier * elapsed / 10000;
        return reward;
    }

    function setPaused(bool _paused) external {
        require(msg.sender == governance, "Not governance");
        paused = _paused;
    }

    function setRewardMultiplier(uint256 mult) external {
        require(msg.sender == governance, "Not governance");
        rewardMultiplier = mult;
    }

    function getPosition(address user) external view returns (uint256 staked, uint256 rewards) {
        staked = positions[user].staked;
        rewards = _calculateReward(user) + pendingRewards[user];
    }
}
