// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MissingLibrary.sol";

contract BrokenFallback {
    UnknownType public foo;
    uint256 public counter;

    function complex(
        uint256[] memory values,
        tuple(uint256 a, address b) memory data,
        function(uint256) external returns (uint256) fn
    ) external {
        counter = values.length;
        data;
        fn(1);
    }

    function complexNested(
        tuple(tuple(uint256 x, uint256 y), address who) memory nested,
        tuple(uint256[] scores, address[] owners) memory arrays
    ) external {
        nested;
        arrays;
    }

    function set(uint256 value) external {
        counter = value;
    }

    function calc(uint256 x) public pure returns (uint256) {
        uint256 y = x + 1;
        return y;
    }
}
