// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IExternal {
    function ping(uint256 x) external returns (uint256);
}

contract ControlFlowTest {
    uint256 public counter;
    uint256[] public data;

    event Log(uint256 value);

    constructor() {
        counter = 1;
        data.push(1);
    }

    function branches(uint256 x) public returns (uint256) {
        uint256 local = x;
        if (x > 10) {
            local = x * 2;
        } else if (x == 10) {
            local = x + 1;
        } else {
            local = x - 1;
        }
        local = x > 100 ? x : local;
        emit Log(local);
        return local;
    }

    function loops(uint256 n) public {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            if (i == 3) {
                continue;
            }
            sum += i;
            if (sum > 10) {
                break;
            }
        }

        uint256 j = 0;
        while (j < n) {
            sum += j;
            j++;
        }

        uint256 k = 0;
        do {
            k++;
        } while (k < n);

        counter = sum + k;
    }

    function tryCatch(address target) external returns (uint256) {
        try IExternal(target).ping(7) returns (uint256 value) {
            return value;
        } catch {
            return 0;
        }
    }

    function revertExample(bool ok) external pure returns (uint256) {
        if (!ok) {
            revert("bad");
        }
        return 1;
    }

    function inlineAsm() external {
        assembly {
            let x := 1
            pop(x)
        }
    }
}
