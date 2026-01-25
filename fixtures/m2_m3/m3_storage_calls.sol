// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract BaseStorage {
    uint256 public baseCount;

    function bump() internal {
        baseCount += 1;
    }
}

contract StorageCalls is BaseStorage {
    struct Item {
        uint256 val;
    }

    mapping(address => Item) public items;
    uint256 public counter;
    uint256[] public list;

    constructor() {
        counter = 1;
        list.push(1);
    }

    function store(address user) external {
        Item storage it = items[user];
        it.val = counter;
        items[user].val += 1;
        list.push(counter);
        counter = counter + 1;
        super.bump();
    }

    function memoryCopy(address user) external view returns (uint256) {
        Item memory tmp = items[user];
        return tmp.val;
    }

    function assignIndex(uint256 idx, uint256 value) external {
        list[idx] = value;
        delete list[idx];
    }

    function useThis(address user) external returns (uint256) {
        this.store(user);
        return this.counter();
    }

    function extCalls(address target, bytes calldata data)
        external
        payable
        returns (bool, bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: msg.value, gas: 50000}(data);
        return (ok, ret);
    }

    function delegate(address target, bytes calldata data)
        external
        returns (bool, bytes memory)
    {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        return (ok, ret);
    }

    function staticCall(address target, bytes calldata data)
        external
        view
        returns (bool, bytes memory)
    {
        (bool ok, bytes memory ret) = target.staticcall(data);
        return (ok, ret);
    }
}

contract StorageFactory {
    function create() external returns (address) {
        StorageCalls sc = new StorageCalls{salt: bytes32(uint256(2))}();
        return address(sc);
    }
}
