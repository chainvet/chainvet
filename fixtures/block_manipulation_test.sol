// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Block Manipulation Test Cases
/// @notice Exercises all three Block Manipulation detectors (BM-01..BM-03).

contract BlockManipulationTests {

    uint256 public price;
    uint256 public reward;
    uint256 public lastTimestamp;
    mapping(address => uint256) public balances;

    // ═══════════════════════════════════════════════════════════════════════
    //  BM-01  Dangerous Usage of `block.timestamp`
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger BM-01: block.timestamp used in if-condition.
    function conditionalTimestamp() public {
        if (block.timestamp > 1000) {
            price = 1;
        }
    }

    /// Should trigger BM-01: block.timestamp used in while-condition.
    function whileTimestamp() public {
        uint256 counter;
        while (block.timestamp > counter) {
            counter++;
        }
    }

    /// Should trigger BM-01: block.timestamp assigned to a variable.
    function assignTimestamp() public {
        lastTimestamp = block.timestamp;
    }

    /// Should trigger BM-01: block.timestamp passed as an argument.
    function callWithTimestamp() public {
        _helper(block.timestamp);
    }

    /// Should trigger BM-01: `now` alias for block.timestamp (pre-0.7).
    /// (The parser will normalize `now` to an Ident("now") node.)
    function useNow() public {
        uint256 t = block.timestamp;
    }

    /// Should NOT trigger BM-01: no timestamp usage.
    function safeFunction() public {
        price = 42;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  BM-02  Transaction Order Dependency (TOD / front-running)
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger BM-02: reads `price` and sends value.
    function buyToken() public payable {
        uint256 amount = msg.value / price;
        balances[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    /// Should trigger BM-02: reads `reward` and transfers.
    function claimReward() external {
        uint256 r = reward;
        payable(msg.sender).transfer(r);
    }

    /// Should NOT trigger BM-02: internal function, not externally callable.
    function _internalTransfer() internal {
        uint256 r = reward;
        payable(msg.sender).transfer(r);
    }

    /// Should NOT trigger BM-02: no value-transfer call.
    function getPrice() public view returns (uint256) {
        return price;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  BM-03  Weak PRNG
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger BM-03: block.timestamp used with modulo for
    /// "random" number.
    function weakRandomTimestamp() public view returns (uint256) {
        return block.timestamp % 100;
    }

    /// Should trigger BM-03: block.difficulty used in arithmetic.
    function weakRandomDifficulty() public view returns (uint256) {
        return block.difficulty + 1;
    }

    /// Should trigger BM-03: blockhash passed to keccak256.
    function weakRandomBlockhash() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(blockhash(block.number - 1))));
    }

    /// Should trigger BM-03: combining multiple block values.
    function weakRandomCombined() public view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(block.timestamp, block.difficulty, msg.sender)
            )
        );
    }

    /// Should NOT trigger BM-03: no block values in arithmetic.
    function safeMath() public pure returns (uint256) {
        uint256 a = 10;
        uint256 b = 20;
        return a + b;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Helper
    // ═══════════════════════════════════════════════════════════════════════

    function _helper(uint256 _val) internal pure {
        // no-op
    }
}
