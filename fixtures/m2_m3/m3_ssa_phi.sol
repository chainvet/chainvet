// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SsaPhiTest {
    function ifPhi(uint256 x) external pure returns (uint256) {
        uint256 y;
        if (x > 0) {
            y = x + 1;
        } else {
            y = x - 1;
        }
        return y + 1;
    }

    function ifElseChain(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 r = a;
        if (a > b) {
            r = a - b;
        } else if (b > a) {
            r = b - a;
        } else {
            r = 0;
        }
        return r;
    }

    function loopPhi(uint256 n) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            sum = sum + i;
        }
        return sum;
    }

    function nestedPhi(uint256 x) external pure returns (uint256) {
        uint256 y = 1;
        while (x > 0) {
            if (x % 2 == 0) {
                y = y * 2;
            } else {
                y = y + 3;
            }
            x--;
        }
        return y;
    }
}
