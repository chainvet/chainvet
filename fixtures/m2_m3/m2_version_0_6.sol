// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Legacy06 {
    uint256 public counter;

    constructor() public {
        counter = 1;
    }

    receive() external payable {
        counter += msg.value;
    }

    fallback() external payable {
        counter += 1;
    }

    function set(uint256 x) external {
        counter = x;
    }
}
