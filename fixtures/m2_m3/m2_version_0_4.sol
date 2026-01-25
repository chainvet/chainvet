// SPDX-License-Identifier: MIT
pragma solidity ^0.4.26;

contract Legacy04 {
    uint256 public counter;

    event Hit(address who, uint256 value);

    function Legacy04() public {
        counter = 1;
    }

    function() public payable {
        counter += msg.value;
        emit Hit(msg.sender, msg.value);
    }

    function set(uint256 x) public {
        counter = x;
    }

    function get() public view returns (uint256) {
        return counter;
    }
}
