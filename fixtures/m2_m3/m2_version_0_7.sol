// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Legacy07 {
    uint256 public counter;

    constructor() {
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
