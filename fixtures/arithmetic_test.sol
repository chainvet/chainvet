// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// Test contract for Arithmetic detectors (AR-01 to AR-04)
contract ArithmeticTest {

    uint256 public total;
    uint256[] public data;

    // AR-01: Division before multiplication
    // Dividing first truncates the intermediate result
    function computeShare(uint256 amount, uint256 parts, uint256 factor) public pure returns (uint256) {
        uint256 intermediate = amount / parts;
        uint256 result = intermediate * factor;
        return result;
    }

    // AR-01: another variant — direct expression
    function losesPrecision(uint256 a, uint256 b, uint256 c) public {
        total = a / b * c;
    }

    // AR-02: Integer overflow (pre-0.8, no SafeMath)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    function unsafeMul(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b;
    }

    // AR-03: Integer underflow (pre-0.8, no SafeMath)
    function unsafeSub(uint256 a, uint256 b) public pure returns (uint256) {
        return a - b;
    }

    // AR-04: Unsafe array length assignment from user parameter
    function resizeArray(uint256 newLen) public {
        data.length = newLen;
    }

    // Safe: division after multiplication — should NOT be flagged
    function safeCompute(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a * b) / c;
    }
}
