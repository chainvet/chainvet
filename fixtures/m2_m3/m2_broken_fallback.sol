// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MissingDependency.sol";

interface IUnknown {
    function ping(uint256 x) external returns (uint256);
}

contract BrokenFallbackCase {
    UnknownType public foo;
    uint256 public counter;
    uint256[] public data;

    event Hit(address who, uint256 value);

    function mixed(
        address target,
        uint256[] memory values,
        bytes memory payload,
        function(uint256) external returns (uint256) fn
    ) external payable returns (uint256) {
        uint256 a = values.length;
        uint256 b = data.length;
        counter = a + b;
        counter += 1;
        counter = counter > 10 ? counter : 10;
        counter++;
        --counter;
        (counter, a) = (a, counter);
        data.push(counter);
        data[0] = counter;
        emit Hit(target, counter);
        fn(counter);
        (bool ok, ) = target.call{value: msg.value, gas: 5000}(payload);
        if (!ok) {
            revert("fail");
        }
        return counter;
    }

    function chain(address target) external {
        IUnknown(target).ping{gas: 12345}(1);
    }

    function asm() external {
        assembly {
            let x := 1
            pop(x)
        }
    }

    function tryCall(address target) external returns (uint256) {
        try IUnknown(target).ping(7) returns (uint256 value) {
            return value;
        } catch {
            return 0;
        }
    }
}
