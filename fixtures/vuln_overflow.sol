// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Yield Farming Vault with Subtle Arithmetic Bugs
/// @notice Overflow/underflow hidden behind multi-step staking lifecycle:
///         approve → stake → accrue → claim. Includes division-before-multiplication
///         and unsafe array length patterns.
contract YieldVault {
    struct StakeInfo {
        uint256 principal;
        uint256 rewardDebt;
        uint256 lastStakeTime;
        uint256 lockDuration;
        bool active;
    }

    mapping(address => StakeInfo) public stakes;
    mapping(address => uint256) public rewardBalances;
    uint256 public totalStaked;
    uint256 public rewardRate;     // rewards per second per token
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public multiplierBasis;
    address public owner;
    uint256[] public rewardHistory;

    event Staked(address indexed user, uint256 amount, uint256 lockDuration);
    event Claimed(address indexed user, uint256 reward);

    constructor() {
        owner = msg.sender;
        rewardRate = 150;        // seems safe, but used in dangerous math
        multiplierBasis = 10000;
        lastUpdateTime = block.timestamp;
    }

    function setRewardRate(uint256 rate) external {
        require(msg.sender == owner, "Not owner");
        rewardRate = rate;
    }

    // Step 1: Stake tokens with a lock period
    function stake(uint256 lockWeeks) external payable {
        require(msg.value > 0, "Zero stake");
        require(lockWeeks >= 1 && lockWeeks <= 52, "Invalid lock");
        require(!stakes[msg.sender].active, "Already staked");

        stakes[msg.sender] = StakeInfo({
            principal: msg.value,
            rewardDebt: 0,
            lastStakeTime: block.timestamp,
            lockDuration: lockWeeks * 7 * 24 * 3600,
            active: true
        });
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value, lockWeeks);
    }

    // Step 2: Calculate accrued rewards
    // BUG: Division before multiplication causes precision loss, and with
    // extreme values the multiplication can overflow
    function calculateReward(address user) public view returns (uint256) {
        StakeInfo storage s = stakes[user];
        if (!s.active) return 0;

        uint256 elapsed = block.timestamp - s.lastStakeTime;
        // BUG: integer division before multiplication — loses precision
        uint256 baseReward = s.principal / multiplierBasis * rewardRate * elapsed;
        // BUG: bonus calculation can overflow with large principal
        uint256 lockBonus = s.principal * s.lockDuration / 365 days;
        // BUG: combining both can overflow
        uint256 totalReward = baseReward + lockBonus;
        return totalReward;
    }

    // Step 3: Claim rewards (only after lock period)
    function claimReward() external {
        StakeInfo storage s = stakes[msg.sender];
        require(s.active, "No active stake");
        require(block.timestamp >= s.lastStakeTime + s.lockDuration, "Lock not expired");

        uint256 reward = calculateReward(msg.sender);
        require(reward > 0, "No reward");

        // BUG: potential underflow if rewardDebt > reward somehow
        uint256 netReward = reward - s.rewardDebt;
        s.rewardDebt = reward;
        rewardBalances[msg.sender] += netReward;

        // Track history — BUG: unbounded array growth
        rewardHistory.push(netReward);
    }

    // Step 4: Unstake principal + accumulated rewards
    function unstake() external {
        StakeInfo storage s = stakes[msg.sender];
        require(s.active, "Not staked");
        require(block.timestamp >= s.lastStakeTime + s.lockDuration, "Still locked");

        uint256 principal = s.principal;
        uint256 rewards = rewardBalances[msg.sender];

        // BUG: potential overflow combining principal + rewards
        uint256 payout = principal + rewards;

        s.active = false;
        s.principal = 0;
        totalStaked -= principal;
        rewardBalances[msg.sender] = 0;

        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "Payout failed");
    }

    // BUG: Batch reward calculation — multiplication chain overflow
    function batchCalculate(address[] calldata users) external view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < users.length; i++) {
            // BUG: compound multiplication with user count
            total += calculateReward(users[i]) * (i + 1);
        }
        return total;
    }

    // BUG: unsafe fee math — division truncates, then multiplied back
    function calculateWithdrawalFee(uint256 amount, uint256 feeBps) external pure returns (uint256) {
        // Division before multiplication pattern
        uint256 feeRate = feeBps / 100;
        uint256 fee = amount * feeRate * 365;  // can overflow with large amounts
        return fee;
    }
}
