// SPDX-License-Identifier: MIT
// A compact Governor-class governance contract: stateful proposal lifecycle
// (propose -> vote -> queue -> execute) guarded by access-control and state
// require()s. Exercises the fuzzer's ability to reach deep, guarded state.
pragma solidity ^0.8.0;

contract Governor {
    enum State {
        Pending,
        Active,
        Defeated,
        Succeeded,
        Queued,
        Executed
    }

    struct Proposal {
        address proposer;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 eta;
        State state;
    }

    address public admin;
    uint256 public proposalCount;
    uint256 public quorum;
    uint256 public votingPeriod;

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256) public votingPower;

    constructor() {
        admin = msg.sender;
        quorum = 100;
        votingPeriod = 10;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function grantPower(address voter, uint256 power) external onlyAdmin {
        votingPower[voter] = power;
    }

    function propose() external returns (uint256) {
        require(votingPower[msg.sender] > 0, "no power");
        proposalCount += 1;
        uint256 id = proposalCount;
        Proposal storage p = proposals[id];
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.state = State.Active;
        return id;
    }

    function castVote(uint256 id, bool support) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Active, "not active");
        require(!hasVoted[id][msg.sender], "already voted");
        uint256 power = votingPower[msg.sender];
        require(power > 0, "no power");
        hasVoted[id][msg.sender] = true;
        if (support) {
            p.forVotes += power;
        } else {
            p.againstVotes += power;
        }
    }

    function tally(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Active, "not active");
        if (p.forVotes >= quorum && p.forVotes > p.againstVotes) {
            p.state = State.Succeeded;
        } else {
            p.state = State.Defeated;
        }
    }

    function queue(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Succeeded, "not succeeded");
        p.eta = block.timestamp + 1 days;
        p.state = State.Queued;
    }

    function execute(uint256 id) external onlyAdmin {
        Proposal storage p = proposals[id];
        require(p.state == State.Queued, "not queued");
        require(block.timestamp >= p.eta, "timelock");
        p.state = State.Executed;
    }
}
