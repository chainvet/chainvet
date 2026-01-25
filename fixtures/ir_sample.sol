// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract IRTest {
    uint256 public counter;
    mapping(address => uint256) public balances;
    address public owner;
    uint256[] public data;

    struct User {
        uint256 score;
        address referrer;
    }

    mapping(address => User) public users;

    event Log(address who, uint256 value);

    constructor() {
        owner = msg.sender;
        counter = 1;
        data.push(42);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        counter++;
        data.push(msg.value);
        emit Log(msg.sender, msg.value);
    }

    function updateUser(address user, uint256 score) external {
        users[user].score = score;
        users[user].referrer = msg.sender;
    }

    function calc(uint256 x) public view returns (uint256) {
        uint256 local = x + counter;
        if (local > 10) {
            local = local * 2;
        } else {
            local = local + 1;
        }
        return local;
    }

    function loop(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            counter = counter + i;
            data[i] = counter;
        }
    }

    function callExternal(address payable target) external {
        (bool ok, ) = target.call{value: 1 wei}("");
        require(ok, "call failed");
    }

    function useOrigin() external view returns (address) {
        if (tx.origin == owner) {
            return tx.origin;
        }
        return msg.sender;
    }

    function tryCatch(address target) external returns (uint256) {
        try IRTest(target).calc(3) returns (uint256 value) {
            return value;
        } catch {
            return 0;
        }
    }
}
