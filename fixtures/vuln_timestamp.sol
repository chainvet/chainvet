// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Multi-Phase Governance with Timestamp-Dependent Voting
/// @notice Timestamp vulnerabilities hidden within a proposal lifecycle:
///         create → vote → finalize. The voting window and execution
///         timing are all block.timestamp-dependent. Also includes weak
///         PRNG seeded from block.timestamp.
contract GovernanceDAO {
    enum ProposalState { None, Pending, Active, Passed, Executed, Rejected }

    struct Proposal {
        address proposer;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 startTime;
        uint256 endTime;
        ProposalState state;
        uint256 amount;
        address payable target;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256) public votingPower;
    uint256 public proposalCount;
    address public guardian;
    uint256 public treasuryBalance;
    uint256 public lastRandomSeed;

    event ProposalCreated(uint256 id, address proposer);
    event Voted(uint256 id, address voter, bool support);
    event Executed(uint256 id);

    constructor() {
        guardian = msg.sender;
    }

    function buyVotingPower() external payable {
        require(msg.value > 0, "Zero value");
        votingPower[msg.sender] += msg.value;
        treasuryBalance += msg.value;
    }

    // Step 1: Create proposal (requires voting power)
    function createProposal(address payable target, uint256 amount) external returns (uint256) {
        require(votingPower[msg.sender] >= 100, "Need 100+ voting power");

        uint256 id = proposalCount++;
        proposals[id] = Proposal({
            proposer: msg.sender,
            votesFor: 0,
            votesAgainst: 0,
            startTime: block.timestamp + 10,     // BUG: miner can manipulate start
            endTime: block.timestamp + 10 + 3600, // BUG: voting window manipulable
            state: ProposalState.Pending,
            amount: amount,
            target: target
        });
        emit ProposalCreated(id, msg.sender);
        return id;
    }

    // Step 2: Vote on proposal (must be within voting window)
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(p.state == ProposalState.Pending || p.state == ProposalState.Active, "Bad state");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(votingPower[msg.sender] > 0, "No voting power");

        // BUG: timestamp-dependent activation
        if (block.timestamp >= p.startTime && p.state == ProposalState.Pending) {
            p.state = ProposalState.Active;
        }
        require(p.state == ProposalState.Active, "Not active");
        // BUG: timestamp-dependent deadline check
        require(block.timestamp <= p.endTime, "Voting ended");

        hasVoted[proposalId][msg.sender] = true;
        if (support) {
            p.votesFor += votingPower[msg.sender];
        } else {
            p.votesAgainst += votingPower[msg.sender];
        }
        emit Voted(proposalId, msg.sender, support);
    }

    // Step 3: Finalize — BUG: execution timing is timestamp-dependent
    function finalizeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.state == ProposalState.Active, "Not active");
        // BUG: timestamp-dependent check
        require(block.timestamp > p.endTime, "Voting not ended");

        if (p.votesFor > p.votesAgainst) {
            p.state = ProposalState.Passed;
        } else {
            p.state = ProposalState.Rejected;
        }
    }

    // Step 4: Execute passed proposal
    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.state == ProposalState.Passed, "Not passed");
        require(p.amount <= treasuryBalance, "Insufficient treasury");

        p.state = ProposalState.Executed;
        treasuryBalance -= p.amount;

        (bool ok, ) = p.target.call{value: p.amount}("");
        require(ok, "Execution failed");
        emit Executed(proposalId);
    }

    // BUG: Weak PRNG using block.timestamp as seed
    function randomReward(address payable recipient) external {
        require(msg.sender == guardian, "Not guardian");
        // BUG: predictable "random" using block.timestamp
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, lastRandomSeed)));
        lastRandomSeed = seed;
        uint256 reward = seed % 1000;
        if (reward > 500) {
            (bool ok, ) = recipient.call{value: reward}("");
            require(ok, "Reward failed");
        }
    }

    function emergencyPause() external {
        // BUG: timestamp-gated emergency — attacker can wait for right timestamp
        require(msg.sender == guardian, "Not guardian");
        require(block.timestamp % 100 < 10, "Not in emergency window");
        // Freeze all proposals
        for (uint256 i = 0; i < proposalCount; i++) {
            if (proposals[i].state == ProposalState.Active) {
                proposals[i].state = ProposalState.Rejected;
            }
        }
    }
}
