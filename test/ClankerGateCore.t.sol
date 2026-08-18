// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ClankerGateCore, ParamRule, Permission, OP_EQ, OP_GT, OP_LT, OP_GTE, OP_LTE, OP_IN, DOMAIN_SEPARATOR_TYPEHASH} from "../src/ClankerGateCore.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";

contract ClankerGateCoreWrapper {
    function validateCallDataWrapped(bytes calldata callData, Permission memory permission)
        external
        pure
        returns (bool valid, uint8 errorCode, uint256 ruleIndex)
    {
        return ClankerGateCore.validateCallDataExtended(callData, permission);
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

    function test_HashPermission_RejectsTooManyRulesBeforeMerkleVerification() public {
        ClankerGateCoreWrapper wrapper = new ClankerGateCoreWrapper();
        Permission memory permission;
        permission.rules = new ParamRule[](11);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.TooManyRules.selector,
                uint256(11),
                uint8(10)
            )
        );
        wrapper.hashPermissionWrapped(permission);
    }

    function test_HashPermission_RejectsOversizedNestedValues() public {
        ClankerGateCoreWrapper wrapper = new ClankerGateCoreWrapper();
        Permission memory permission;
        permission.rules = new ParamRule[](1);
        permission.rules[0].values = new bytes32[](21);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.TooManyValues.selector,
                uint256(21),
                uint256(20)
            )
        );
        wrapper.hashPermissionWrapped(permission);
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

        (bool valid, , ) = ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
        assertTrue(valid);
    }

    function test_ValidateCallData_SelectorMismatch() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0xdeadbeef;
        permission.rules = new ParamRule[](0);

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000001";

        (bool valid, , ) = ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
        assertFalse(valid);
    }

    function test_ValidateCallData_RuleEQ_Pass() public pure {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, OP_EQ, bytes32(uint256(123)), new bytes32[](0));

        bytes memory callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";

        (bool valid, , ) = ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
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

        (bool valid, , ) = ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
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

        (bool valid, , ) = ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
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
// CG-15: _packValidationData bit positions — real coverage lives in
// test/invariant/ClankerGateInvariant.t.sol (test_ExpiredPermissionsRejected /
// test_FuturePermissionsRejected assert the packed validUntil/validAfter bits
// returned by the deployed gate). The former CG15_BitShiftTest computed and
// decoded the packing entirely inside the test without calling any source
// code, so it could never fail — removed.
// ============================================================

// ============================================================
// CANONICAL LEAF FORMULA INVARIANT GUARD
// Independently re-derives the Merkle leaf and asserts equality
// with the contract's computation. Any future change to field
// order, double-hashing, or per-rule hashing fails loudly.
// ============================================================
contract LeafInvariantTest is Test {
    ClankerGate4337 g;

    function setUp() public {
        g = new ClankerGate4337();
    }

    function test_canonicalLeaf_formulaLocked() public {
        // Fixed non-trivial permission: OP_IN rule with non-empty values,
        // nonzero maxValue, authorizedCaller, validAfter, validUntil, chainId, singleUse=true.
        bytes32[] memory inValues = new bytes32[](3);
        inValues[0] = bytes32(uint256(0xAA));
        inValues[1] = bytes32(uint256(0xBB));
        inValues[2] = bytes32(uint256(0xCC));

        Permission memory p;
        p.target   = address(0x1234567890123456789012345678901234567890);
        p.selector = 0xabcdef01;
        p.rules    = new ParamRule[](1);
        p.rules[0] = ParamRule(32, OP_IN, bytes32(0), inValues);
        p.validAfter  = uint48(1_000_000);
        p.validUntil  = uint48(9_999_999);
        p.chainId     = 31337; // default Foundry chainId
        p.singleUse   = true;
        p.maxValue    = 1 ether;
        p.authorizedCaller = address(0xDEAD);

        address account = address(0xBEEF);
        uint256 nonce   = 7;

        // ---- Independently re-derive the leaf ----

        // 1. Domain separator (same formula as all three gate contracts)
        bytes32 domainSep = keccak256(abi.encode(
            DOMAIN_SEPARATOR_TYPEHASH,
            keccak256("ClankerGate"),
            keccak256("1"),
            block.chainid,
            address(g)
        ));

        // 2. Per-rule hashes
        bytes32[] memory ruleHashes = new bytes32[](p.rules.length);
        for (uint256 i; i < p.rules.length; ++i) {
            ParamRule memory r = p.rules[i];
            ruleHashes[i] = keccak256(abi.encode(r.offset, r.op, r.value, r.values));
        }

        // 3. Encoded permission (field order must match hashPermission in ClankerGateCore)
        bytes32 enc = keccak256(abi.encode(
            p.target,
            p.selector,
            ruleHashes,
            p.validAfter,
            p.validUntil,
            p.chainId,
            p.singleUse,
            p.maxValue,
            p.authorizedCaller
        ));

        // 4. Permission hash = double-keccak with domain separator
        bytes32 permHash = keccak256(abi.encode(domainSep, enc));

        // 5. Leaf = account-scoped binding
        bytes32 expectedLeaf = keccak256(abi.encode(account, permHash, nonce));

        // ---- Assert the contract computes the same leaf ----
        assertEq(g.computePermissionHash(account, p, nonce), expectedLeaf, "leaf mismatch");

        // Emit values for SDK cross-check vectors
        emit log_named_bytes32("leaf",            expectedLeaf);
        emit log_named_bytes32("domainSeparator", domainSep);
        emit log_named_bytes32("permHash",        permHash);
    }
}
