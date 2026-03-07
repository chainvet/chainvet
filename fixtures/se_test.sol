// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SETest {
    uint256 public balance;
    address public owner;
    bool public cond;
    bytes1 public data;

    function deposit() external payable {
        balance += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        if (data == "t") {    // overflow / insufficient-balance check
            balance = balance - amount;
        }
        revert();                // revert
    }
}