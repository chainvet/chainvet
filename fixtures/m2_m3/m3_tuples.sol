// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TupleTest {
    function pair(uint256 x) internal pure returns (uint256, uint256) {
        return (x, x + 1);
    }

    function triple(uint256 x) internal pure returns (uint256, uint256, uint256) {
        return (x, x + 1, x + 2);
    }

    function tupleDecl(uint256 x) external pure returns (uint256) {
        (uint256 a, uint256 b) = pair(x);
        (uint256 c, uint256 d, uint256 e) = triple(x);
        (a, b) = (b, a);
        (, d, e) = triple(a);
        (a, b, c) = (a + 1, b + 1, c + 1);
        return a + b + c + d + e;
    }

    function tupleAssign(uint256 x) external pure returns (uint256) {
        uint256 a = 1;
        uint256 b = 2;
        (a, b) = pair(x);
        return a + b;
    }

    function returnPair(uint256 x) external pure returns (uint256, uint256) {
        return pair(x);
    }
}
