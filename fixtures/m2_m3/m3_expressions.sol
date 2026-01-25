// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

interface IHelper {
    function ping(uint256 x) external returns (uint256);
}

contract Helper is IHelper {
    function ping(uint256 x) external pure override returns (uint256) {
        return x + 1;
    }
}

function topLevel(uint256 x) pure returns (uint256) {
    return x + 1;
}

contract ExprTest {
    uint256 public counter;
    uint256[] public arr;
    mapping(address => uint256) public balances;
    IHelper public helper;

    event Logged(bytes data, uint256 value);

    constructor() {
        counter = 1;
        arr.push(10);
        helper = new Helper();
    }

    function exprs(address target, uint256 x) external payable returns (uint256) {
        uint256 a = 1;
        uint256 b = 2;
        uint256 c = 3;

        a = a + b;
        a += b;
        a -= 1;
        a *= 2;
        a /= 2;
        a %= 3;
        a |= b;
        a &= b;
        a ^= b;
        a <<= 1;
        a >>= 1;

        b = a ** 2;

        bool ok = (a > b) && (b != c) || (a == c);
        ok = !ok;

        c = (a + b) * 2;
        c = ok ? a : b;

        a++;
        ++a;
        b--;
        --b;

        arr.push(a);
        arr[0] = b;
        balances[target] = a + b;
        balances[target] += 1;

        bytes memory data = abi.encodePacked(a, b, c);
        emit Logged(data, c);

        uint256 d = helper.ping{gas: 50000}(a);
        (a, b) = (b, a);
        (a, b, c) = (a + 1, b + 1, c + 1);

        (bool success, bytes memory ret) = target.call{value: msg.value, gas: 70000}(data);
        ret;
        if (!success) {
            revert("call failed");
        }

        Helper created = new Helper{salt: bytes32(uint256(1))}();
        d += created.ping(a);

        address addr = address(0x1234567890123456789012345678901234567890);
        balances[addr] = MathLib.add(balances[addr], x);

        return d + topLevel(c);
    }

    function memberIndexChain(address user, uint256 idx) external returns (uint256) {
        balances[user] = balances[user] + 1;
        uint256 v = arr[idx];
        uint256 r = IHelper(address(helper)).ping(v);
        return r + balances[user];
    }
}
