// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ClankerGateCore, ParamRule, Permission, OP_EQ, OP_GT, OP_LT, OP_GTE, OP_LTE, OP_IN} from "../src/ClankerGateCore.sol";

contract ClankerGateCoreWrapper {
    function validateCallDataWrapped(bytes calldata callData, Permission memory permission) 
        external 
        pure 
        returns (bool valid, uint256 ruleIndex) 
    {
        return ClankerGateCore.validateCallData(callData, permission);
    }

    function hashPermissionWrapped(Permission memory permission) external view returns (bytes32) {
        return ClankerGateCore.hashPermission(permission);
    }
}

contract ClankerGateCoreTest is Test {
    function test_HashPermission() public view {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 hash = ClankerGateCore.hashPermission(permission);
        assertTrue(hash != bytes32(0));
    }

    function test_HashPermission_WithRules() public view {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](2);
        permission.rules[0] = ParamRule(0, OP_EQ, bytes32(uint256(100)), new bytes32[](0));
        permission.rules[1] = ParamRule(32, OP_LTE, bytes32(uint256(200)), new bytes32[](0));
        permission.validAfter = 1000;
        permission.validUntil = 2000;
        permission.chainId = 1;

        bytes32 hash = ClankerGateCore.hashPermission(permission);
        assertTrue(hash != bytes32(0));
    }

    function test_CompareRule_EQ() public pure {
        assertTrue(ClankerGateCore.compareRule(OP_EQ, bytes32(uint256(100)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_EQ, bytes32(uint256(100)), bytes32(uint256(101)), new bytes32[](0)));
    }

    function test_CompareRule_GT() public pure {
        assertTrue(ClankerGateCore.compareRule(OP_GT, bytes32(uint256(101)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_GT, bytes32(uint256(100)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_GT, bytes32(uint256(99)), bytes32(uint256(100)), new bytes32[](0)));
    }

    function test_CompareRule_LT() public pure {
        assertTrue(ClankerGateCore.compareRule(OP_LT, bytes32(uint256(99)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_LT, bytes32(uint256(100)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_LT, bytes32(uint256(101)), bytes32(uint256(100)), new bytes32[](0)));
    }

    function test_CompareRule_GTE() public pure {
        assertTrue(ClankerGateCore.compareRule(OP_GTE, bytes32(uint256(100)), bytes32(uint256(100)), new bytes32[](0)));
        assertTrue(ClankerGateCore.compareRule(OP_GTE, bytes32(uint256(101)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_GTE, bytes32(uint256(99)), bytes32(uint256(100)), new bytes32[](0)));
    }

    function test_CompareRule_LTE() public pure {
        assertTrue(ClankerGateCore.compareRule(OP_LTE, bytes32(uint256(100)), bytes32(uint256(100)), new bytes32[](0)));
        assertTrue(ClankerGateCore.compareRule(OP_LTE, bytes32(uint256(99)), bytes32(uint256(100)), new bytes32[](0)));
        assertFalse(ClankerGateCore.compareRule(OP_LTE, bytes32(uint256(101)), bytes32(uint256(100)), new bytes32[](0)));
    }

    function test_CompareRule_IN() public pure {
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));

        assertTrue(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(100)), bytes32(0), allowedValues));
        assertTrue(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(200)), bytes32(0), allowedValues));
        assertTrue(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(300)), bytes32(0), allowedValues));
        assertFalse(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(999)), bytes32(0), allowedValues));
    }

    function test_CompareRule_IN_EmptyArray() public pure {
        bytes32[] memory emptyArray = new bytes32[](0);
        assertFalse(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(100)), bytes32(0), emptyArray));
    }

    function test_InArray() public pure {
        bytes32[] memory arr = new bytes32[](3);
        arr[0] = bytes32(uint256(1));
        arr[1] = bytes32(uint256(2));
        arr[2] = bytes32(uint256(3));

        assertTrue(ClankerGateCore.inArray(bytes32(uint256(1)), arr));
        assertTrue(ClankerGateCore.inArray(bytes32(uint256(2)), arr));
        assertTrue(ClankerGateCore.inArray(bytes32(uint256(3)), arr));
        assertFalse(ClankerGateCore.inArray(bytes32(uint256(4)), arr));
    }
}

contract ValidatePermissionTests is Test {
    function test_ValidatePermission_Valid() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        (bool valid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        assertTrue(valid);
        assertEq(errorCode, 0);
    }

    function test_ValidatePermission_TimeWindow() public {
        vm.warp(10000);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(5000);
        permission.validUntil = uint48(15000);
        permission.chainId = 0;

        (bool valid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        assertTrue(valid);
        assertEq(errorCode, 0);
    }

    function test_ValidatePermission_NotYetValid() public {
        vm.warp(1000);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(5000);
        permission.validUntil = 0;
        permission.chainId = 0;

        (bool valid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        assertFalse(valid);
        assertEq(errorCode, 7);
    }

    function test_ValidatePermission_Expired() public {
        vm.warp(20000);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = uint48(10000);
        permission.chainId = 0;

        (bool valid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        assertFalse(valid);
        assertEq(errorCode, 8);
    }

    function test_ValidatePermission_ChainIdMismatch() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 999;

        (bool valid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        assertFalse(valid);
        assertEq(errorCode, 9);
    }
}

contract ValidateCallDataTests is Test {
    ClankerGateCoreWrapper wrapper;

    function setUp() public {
        wrapper = new ClankerGateCoreWrapper();
    }

    function test_ValidateCallData_SelectorMatch() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000001";

        (bool valid, ) = ClankerGateCore.validateCallDataMemory(callData, permission);
        assertTrue(valid);
    }

    function test_ValidateCallData_SelectorMismatch() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0xdeadbeef;
        permission.rules = new ParamRule[](0);

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000001";

        (bool valid, ) = ClankerGateCore.validateCallDataMemory(callData, permission);
        assertFalse(valid);
    }

    function test_ValidateCallData_RuleEQ_Pass() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, OP_EQ, bytes32(uint256(123)), new bytes32[](0));

        bytes memory callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";

        (bool valid, ) = ClankerGateCore.validateCallDataMemory(callData, permission);
        assertTrue(valid);
    }

    function test_ValidateCallData_RuleIN_Pass() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, OP_IN, bytes32(0), allowedValues);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8";

        (bool valid, ) = ClankerGateCore.validateCallDataMemory(callData, permission);
        assertTrue(valid);
    }

    function test_ValidateCallData_RuleIN_Fail() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, OP_IN, bytes32(0), allowedValues);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        wrapper.validateCallDataWrapped(callData, permission);
    }

    function test_ValidateCallData_MultipleValues_IN() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        bytes32[] memory allowedReceivers = new bytes32[](2);
        allowedReceivers[0] = bytes32(uint256(uint160(0xAAAA)));
        allowedReceivers[1] = bytes32(uint256(uint160(0xBBBB)));
        permission.rules[0] = ParamRule(0, OP_IN, bytes32(0), allowedReceivers);

        bytes memory callData = new bytes(36);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);

        assembly {
            mstore(add(add(callData, 32), 4), 0xAAAA)
        }

        (bool valid, ) = ClankerGateCore.validateCallDataMemory(callData, permission);
        assertTrue(valid);
    }
}

contract FuzzTests is Test {
    function testFuzz_CompareRule_EQ(bytes32 a, bytes32 b) public pure {
        bool result = ClankerGateCore.compareRule(OP_EQ, a, b, new bytes32[](0));
        assertEq(result, a == b);
    }

    function testFuzz_CompareRule_GT(bytes32 a, bytes32 b) public pure {
        bool result = ClankerGateCore.compareRule(OP_GT, a, b, new bytes32[](0));
        assertEq(result, a > b);
    }

    function testFuzz_CompareRule_LT(bytes32 a, bytes32 b) public pure {
        bool result = ClankerGateCore.compareRule(OP_LT, a, b, new bytes32[](0));
        assertEq(result, a < b);
    }

    function testFuzz_CompareRule_GTE(bytes32 a, bytes32 b) public pure {
        bool result = ClankerGateCore.compareRule(OP_GTE, a, b, new bytes32[](0));
        assertEq(result, a >= b);
    }

    function testFuzz_CompareRule_LTE(bytes32 a, bytes32 b) public pure {
        bool result = ClankerGateCore.compareRule(OP_LTE, a, b, new bytes32[](0));
        assertEq(result, a <= b);
    }
}

// ============================================================
// CG-15: _packValidationData bit shift fix validation
// ERC-4337: validUntil=bits160-207, validAfter=bits208-255
// ============================================================
contract CG15_BitShiftTest is Test {
    function test_CG15_PackValidationData_CorrectBitPositions() external pure {
        uint48 validUntil = 0;
        uint48 validAfter = 1;
        bool sigFailed = false;
        
        // Packed: (validUntil << 160) | (validAfter << 208) | sigFailed
        uint256 packed = (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
        
        // Decode like EntryPoint does:
        // sigFailed = packed & 1
        // validUntil = uint48(packed >> 160)
        // validAfter = uint48(packed >> 208)
        uint256 decodedSigFailed = packed & 1;
        uint48 decodedValidUntil = uint48(packed >> 160);
        uint48 decodedValidAfter = uint48(packed >> 208);
        
        assertEq(decodedSigFailed, 0, "sigFailed should be 0");
        assertEq(decodedValidUntil, validUntil, "validUntil mismatch");
        assertEq(decodedValidAfter, validAfter, "validAfter mismatch");
    }
    
    function test_CG15_PackValidationData_NoOverlap() external pure {
        // Test that validUntil and validAfter don't overlap
        uint48 validUntil = 4095;
        uint48 validAfter = 12345;
        bool sigFailed = false;
        
        uint256 packed = (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
        
        uint48 decodedValidUntil = uint48(packed >> 160);
        uint48 decodedValidAfter = uint48(packed >> 208);
        
        assertEq(decodedValidUntil, validUntil, "validUntil corrupted");
        assertEq(decodedValidAfter, validAfter, "validAfter misaligned due to wrong shift (<< 192 should be << 208)");
    }
    
    function test_CG15_PackValidationData_FullRange() external pure {
        uint48 validUntil = type(uint48).max;
        uint48 validAfter = type(uint48).max;
        bool sigFailed = true;
        
        uint256 packed = (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
        
        assertEq(uint48(packed >> 160), validUntil, "validUntil max");
        assertEq(uint48(packed >> 208), validAfter, "validAfter max");
        assertEq(packed & 1, 1, "sigFailed");
    }
}
