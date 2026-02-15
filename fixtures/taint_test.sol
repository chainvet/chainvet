// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TaintTest {
    function testDirectTaint(address target) public {
        // msg.sender is a source
        // This call has tainted arguments
        target.call(abi.encodePacked(msg.sender));
    }

    function testPropagatedTaint(address target) public {
        address source = msg.sender;
        // propagate taint to local var
        // call with local var
        target.call(abi.encodePacked(source));
    }
    
    function testTxOriginTaint(address target) public {
        // tx.origin is a source
        require(tx.origin == target); // Call to require with tainted arg (binary expr)
    }
}
