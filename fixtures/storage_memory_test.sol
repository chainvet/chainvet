// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Storage & Memory Test Cases
/// @notice Exercises all seven Storage & Memory detectors (SM-01..SM-07).

contract StorageMemoryTests {

    uint256 public value;
    uint256[] public data;
    mapping(address => uint256) public balances;

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-01  Arbitrary Function Jump via Inline Assembly
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-01: inline assembly can modify memory-based
    /// function pointers, causing arbitrary jumps.
    function arbitraryJump(bytes memory input) public {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(add(input, 0x20)))
        }
    }

    /// Should trigger SM-01: assembly modifying memory directly.
    function asmMemoryOverwrite() public {
        assembly {
            mstore(0x00, 0x1234)
        }
    }

    /// Should NOT trigger SM-01: no inline assembly.
    function noAssembly() public {
        value = 42;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-02  Bytes Variables Risk
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-02: msg.data used directly.
    function rawCalldata() public {
        bytes memory d = msg.data;
        // Different msg.data payloads may produce the same decoded value
    }

    /// Should trigger SM-02: msg.data passed as argument.
    function forwardCalldata() public {
        _processData(msg.data);
    }

    /// Should NOT trigger SM-02: no msg.data usage.
    function noMsgData() public pure returns (uint256) {
        return 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-03  Dangerous Usage of `msg.value` inside a Loop
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-03: msg.value used in for-loop.
    function badMsgValueFor(address[] memory receivers) public payable {
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += msg.value;
        }
    }

    /// Should trigger SM-03: msg.value used in while-loop.
    function badMsgValueWhile(address[] memory receivers) public payable {
        uint256 i = 0;
        while (i < receivers.length) {
            balances[receivers[i]] += msg.value;
            i++;
        }
    }

    /// Should NOT trigger SM-03: msg.value outside loop.
    function safeMsgValue() public payable {
        balances[msg.sender] += msg.value;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-04  Error-prone Assembly Usage
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-04: any inline assembly is flagged.
    function usesAssembly() public view returns (uint256 size) {
        address addr = msg.sender;
        assembly {
            size := extcodesize(addr)
        }
    }

    /// Should NOT trigger SM-04: no assembly.
    function pureComputation() public pure returns (uint256) {
        return 2 + 2;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-05  Memory Manipulation
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-05: inline assembly + references state variable.
    function manipulateMemory(uint256 _value) public {
        uint256[] memory array = new uint256[](1);
        array[0] = _value;
        assembly {
            mstore(add(sload(0), 0x20), mload(add(array, 0x20)))
        }
    }

    /// Should trigger SM-05: assembly with memory array creation.
    function unsafeMemoryWrite() public {
        uint256[] memory buf = new uint256[](2);
        assembly {
            mstore(add(buf, 0x20), 0xFF)
            mstore(add(buf, 0x40), 0xAA)
        }
    }

    /// Should NOT trigger SM-05: assembly without state/memory array.
    function safeAssembly() public pure returns (uint256 result) {
        assembly {
            result := add(1, 2)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-06  Modifying Storage Array by Value
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-06: memory parameter assigned to storage variable.
    function setData(uint256[] memory newData) public {
        data = newData;
    }

    /// Should trigger SM-06: storage variable read into parameter.
    function getData(uint256[] memory output) public {
        output = data;
    }

    /// Should NOT trigger SM-06: no cross storage/memory assignment.
    function getLength() public view returns (uint256) {
        return data.length;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SM-07  Payable Functions using `delegatecall` inside a Loop
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger SM-07: delegatecall in loop of payable function.
    function badDelegatecallLoop(address[] memory receivers) public payable {
        for (uint256 i = 0; i < receivers.length; i++) {
            address(this).delegatecall(
                abi.encodeWithSignature("addBalance(address)", receivers[i])
            );
        }
    }

    /// Should NOT trigger SM-07: delegatecall outside a loop.
    function singleDelegatecall() public payable {
        address(this).delegatecall(
            abi.encodeWithSignature("addBalance(address)", msg.sender)
        );
    }

    /// Should NOT trigger SM-07: delegatecall in loop but NOT payable.
    function nonPayableDelegatecallLoop(address[] memory receivers) public {
        for (uint256 i = 0; i < receivers.length; i++) {
            address(this).delegatecall(
                abi.encodeWithSignature("addBalance(address)", receivers[i])
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════════

    function _processData(bytes memory) internal pure {
        // no-op
    }

    function addBalance(address a) public payable {
        balances[a] += msg.value;
    }
}
