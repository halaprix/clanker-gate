// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ClankerGateCore} from "../src/ClankerGateCore.sol";

/// @dev Thin harness that exposes the internal library function via an external call.
contract DecodeHarness {
    function decodeAny(bytes memory callData)
        external
        pure
        returns (
            ClankerGateCore.ExecKind kind,
            address target,
            uint256 innerOffset,
            uint256 innerLength,
            uint256 value
        )
    {
        return ClankerGateCore.decodeAnyExecuteMemory(callData);
    }
}

contract CoreExecuteDecodeTest is Test {
    DecodeHarness harness;

    function setUp() public {
        harness = new DecodeHarness();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Build a standard execute(address,uint256,bytes) calldata blob (4337 style).
    function _build4337(address target, uint256 value, bytes memory inner)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", target, value, inner);
    }

    /// @dev Build an ERC-7579 execute(bytes32,bytes) calldata blob for single+default mode.
    function _build7579Single(address target, uint256 value, bytes memory inner)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 mode = bytes32(0); // callType=0x00 (single), execType=0x00 (default)
        bytes memory executionCalldata = abi.encodePacked(target, value, inner);
        return abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);
    }

    // -------------------------------------------------------------------------
    // test_decode4337Wrapper
    // -------------------------------------------------------------------------

    function test_decode4337Wrapper() public view {
        address target = address(0xBEEF);
        uint256 value  = 1 ether;
        bytes memory inner = hex"aabbccdd";

        bytes memory cd = _build4337(target, value, inner);
        (
            ClankerGateCore.ExecKind kind,
            address gotTarget,
            uint256 innerOffset,
            uint256 innerLength,
            uint256 gotValue
        ) = harness.decodeAny(cd);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute4337), "kind should be Execute4337");
        assertEq(gotTarget,  target,       "target mismatch");
        assertEq(gotValue,   value,        "value mismatch");
        assertEq(innerLength, inner.length, "innerLength mismatch");

        // Verify inner bytes at innerOffset
        bytes memory extracted = new bytes(innerLength);
        for (uint256 i; i < innerLength; i++) {
            extracted[i] = cd[innerOffset + i];
        }
        assertEq(extracted, inner, "inner calldata mismatch");
    }

    function test_decode4337Wrapper_zeroTargetStillWrapped() public view {
        bytes memory inner = hex"aabbccdd";
        bytes memory cd = _build4337(address(0), 2 ether, inner);

        (
            ClankerGateCore.ExecKind kind,
            address gotTarget,
            ,
            uint256 innerLength,
            uint256 gotValue
        ) = harness.decodeAny(cd);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute4337));
        assertEq(gotTarget, address(0));
        assertEq(gotValue, 2 ether);
        assertEq(innerLength, inner.length);
    }

    function test_rejectShort4337Wrapper() public {
        bytes memory cd = abi.encodePacked(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            bytes32(uint256(uint160(address(0xBEEF))))
        );

        vm.expectRevert(ClankerGateCore.InvalidExecuteEncoding.selector);
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_decode7579Single
    // -------------------------------------------------------------------------

    function test_decode7579Single() public view {
        address target = address(0xCAFE);
        uint256 value  = 0.5 ether;
        bytes memory inner = hex"deadbeef1234";

        bytes memory cd = _build7579Single(target, value, inner);
        (
            ClankerGateCore.ExecKind kind,
            address gotTarget,
            uint256 innerOffset,
            uint256 innerLength,
            uint256 gotValue
        ) = harness.decodeAny(cd);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute7579Single), "kind should be Execute7579Single");
        assertEq(gotTarget,  target,       "target mismatch");
        assertEq(gotValue,   value,        "value mismatch");
        assertEq(innerLength, inner.length, "innerLength mismatch");

        // Verify inner bytes at innerOffset
        bytes memory extracted = new bytes(innerLength);
        for (uint256 i; i < innerLength; i++) {
            extracted[i] = cd[innerOffset + i];
        }
        assertEq(extracted, inner, "inner calldata mismatch");
    }

    // -------------------------------------------------------------------------
    // testFuzz_decode7579Single — KEY CORRECTNESS GATE
    // -------------------------------------------------------------------------

    function testFuzz_decode7579Single(
        address target,
        uint256 value,
        bytes memory inner
    ) public view {
        vm.assume(inner.length <= 1024);

        bytes memory cd = _build7579Single(target, value, inner);
        (
            ClankerGateCore.ExecKind kind,
            address gotTarget,
            uint256 innerOffset,
            uint256 innerLength,
            uint256 gotValue
        ) = harness.decodeAny(cd);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute7579Single), "kind should be Execute7579Single");
        assertEq(gotTarget,  target,       "target mismatch");
        assertEq(gotValue,   value,        "value mismatch");
        assertEq(innerLength, inner.length, "innerLength mismatch");

        // Verify inner bytes at innerOffset
        bytes memory extracted = new bytes(innerLength);
        for (uint256 i; i < innerLength; i++) {
            extracted[i] = cd[innerOffset + i];
        }
        assertEq(extracted, inner, "inner calldata mismatch");
    }

    // -------------------------------------------------------------------------
    // test_reject7579Batch  (callType 0x01)
    // -------------------------------------------------------------------------

    function test_reject7579Batch() public {
        // mode byte[0] = 0x01 (batch)
        bytes32 mode = bytes32(bytes1(0x01)); // 0x0100...00
        bytes memory executionCalldata = new bytes(52); // minimal length (won't get that far)
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedCallType.selector, bytes1(0x01))
        );
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_reject7579Delegatecall  (callType 0xff)
    // -------------------------------------------------------------------------

    function test_reject7579Delegatecall() public {
        bytes32 mode = bytes32(bytes1(0xff));
        bytes memory executionCalldata = new bytes(52);
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedCallType.selector, bytes1(0xff))
        );
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_reject7579Static  (callType 0xfe)
    // -------------------------------------------------------------------------

    function test_reject7579Static() public {
        bytes32 mode = bytes32(bytes1(0xfe));
        bytes memory executionCalldata = new bytes(52);
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedCallType.selector, bytes1(0xfe))
        );
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_reject7579TryExec  (execType 0x01)
    // -------------------------------------------------------------------------

    function test_reject7579TryExec() public {
        // mode: byte[0]=0x00 (single), byte[1]=0x01 (try)
        // bytes32: leftmost = byte[0], second-from-left = byte[1]
        bytes32 mode = bytes32(uint256(0x0001) << 240); // puts 0x00 at byte0, 0x01 at byte1
        bytes memory executionCalldata = new bytes(52);
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedExecType.selector, bytes1(0x01))
        );
        harness.decodeAny(cd);
    }

    function test_reject7579CustomMode() public {
        // single + default, but a non-zero account-specific mode selector.
        bytes32 mode = bytes32(uint256(0x11223344) << 176);
        bytes memory executionCalldata = abi.encodePacked(
            address(0xBEEF),
            uint256(0),
            hex"aabbccdd"
        );
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedExecutionMode.selector, mode)
        );
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_reject7579ShortExecData  (executionCalldata length < 52)
    // -------------------------------------------------------------------------

    function test_reject7579ShortExecData() public {
        bytes32 mode = bytes32(0); // single + default
        // Only 20 bytes — missing value and inner calldata
        bytes memory executionCalldata = new bytes(20);
        bytes memory cd = abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionCalldata);

        vm.expectRevert(ClankerGateCore.InvalidExecutionCalldata.selector);
        harness.decodeAny(cd);
    }

    // -------------------------------------------------------------------------
    // test_directCallForUnknownSelector
    // -------------------------------------------------------------------------

    function test_directCallForUnknownSelector() public view {
        // Build arbitrary calldata with an unknown selector
        bytes memory cd = abi.encodeWithSignature("transfer(address,uint256)", address(0x1234), uint256(999));

        (
            ClankerGateCore.ExecKind kind,
            address gotTarget,
            ,
            uint256 innerLength,
            uint256 gotValue
        ) = harness.decodeAny(cd);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Direct), "kind should be Direct");
        assertEq(gotTarget, address(0),   "target should be address(0) for Direct");
        assertEq(gotValue,  0,             "value should be 0 for Direct");
        assertEq(innerLength, cd.length,   "innerLength should equal callData.length for Direct");
    }
}
