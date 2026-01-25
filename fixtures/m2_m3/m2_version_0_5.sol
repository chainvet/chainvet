// SPDX-License-Identifier: MIT
pragma solidity ^0.5.17;

contract Legacy05 {
    uint256 public counter;

    constructor() public {
        counter = 1;
    }

    function() external payable {
        counter += msg.value;
    }

    function set(uint256 x) external {
        counter = x;
    }

    function get() external view returns (uint256) {
        return counter;
    }
}
