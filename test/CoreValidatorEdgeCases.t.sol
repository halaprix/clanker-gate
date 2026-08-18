// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test, stdError} from "forge-std/Test.sol";
import {
    ClankerGateCore,
    ParamRule,
    Permission,
    OP_EQ,
    OP_GT,
    OP_LT,
    OP_GTE,
    OP_LTE,
    OP_IN,
    OP_SGT,
    OP_SLT,
    MAX_RULES,
    MAX_IN_VALUES,
    ERR_INVALID_LENGTH,
    ERR_SELECTOR_MISMATCH
} from "../src/ClankerGateCore.sol";

/// @notice External wrapper so library reverts can be asserted with vm.expectRevert
///         and the `bytes calldata` path is exercised through real calldata.
contract EdgeCaseWrapper {
    function validateCalldata(bytes calldata callData, Permission memory permission)
        external
        pure
        returns (bool, uint8, uint256)
    {
        return ClankerGateCore.validateCallDataExtended(callData, permission);
    }

    function validateMemory(bytes memory callData, Permission memory permission)
        external
        pure
        returns (bool, uint8, uint256)
    {
        return ClankerGateCore.validateCallDataMemoryExtended(callData, permission);
    }

    function compareRuleWrapped(uint8 op, bytes32 actual, bytes32 expected, bytes32[] memory values)
        external
        pure
        returns (bool)
    {
        return ClankerGateCore.compareRule(op, actual, expected, values);
    }

    function decodeExecute(bytes memory callData)
        external
        pure
        returns (address target, uint256 innerDataOffset, uint256 innerDataLength, uint256 value)
    {
        return ClankerGateCore.decodeExecuteCallMemory(callData);
    }

    function decodeAny(bytes memory callData)
        external
        pure
        returns (ClankerGateCore.ExecKind, address, uint256, uint256, uint256)
    {
        return ClankerGateCore.decodeAnyExecuteMemory(callData);
    }
}

abstract contract EdgeCaseBase is Test {
    EdgeCaseWrapper internal wrapper;
    bytes4 internal constant SEL = 0x12345678;

    function setUp() public virtual {
        wrapper = new EdgeCaseWrapper();
    }

    function _permWithRule(uint256 offset, uint8 op, bytes32 value) internal pure returns (Permission memory p) {
        p.selector = SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule(offset, op, value, new bytes32[](0));
    }

    function _cd(bytes32 word0) internal pure returns (bytes memory) {
        return abi.encodePacked(SEL, word0);
    }
}

// ============================================================
//  Signed comparison operators (OP_SGT / OP_SLT) — previously untested
// ============================================================
contract SignedOpsTest is EdgeCaseBase {
    function test_SGT_NegativeExpected_PositiveActual_Passes() public view {
        // 5 > -3 signed. Unsigned, -3 is a huge uint and 5 > it would be FALSE —
        // this is the case that discriminates OP_SGT from OP_GT.
        Permission memory p = _permWithRule(0, OP_SGT, bytes32(uint256(int256(-3))));
        (bool valid,,) = wrapper.validateCalldata(_cd(bytes32(uint256(5))), p);
        assertTrue(valid, "5 > -3 must hold under signed comparison");
    }

    function test_GT_DisagreesWithSGT_OnNegativeValues() public view {
        // Same operands, unsigned operator: 5 > uint(-3) is false.
        assertFalse(
            ClankerGateCore.compareRule(
                OP_GT, bytes32(uint256(5)), bytes32(uint256(int256(-3))), new bytes32[](0)
            ),
            "unsigned GT must disagree with signed SGT here"
        );
    }

    function test_SLT_MinusOneLessThanZero_Passes() public view {
        Permission memory p = _permWithRule(0, OP_SLT, bytes32(0));
        (bool valid,,) = wrapper.validateCalldata(_cd(bytes32(uint256(int256(-1)))), p);
        assertTrue(valid, "-1 < 0 must hold under signed comparison");
    }

    function test_SLT_IntMinIsSmallestValue() public view {
        bytes32 intMin = bytes32(uint256(type(int256).min));
        assertTrue(
            ClankerGateCore.compareRule(OP_SLT, intMin, bytes32(uint256(type(int256).max)), new bytes32[](0)),
            "int256.min < int256.max"
        );
        assertFalse(
            ClankerGateCore.compareRule(OP_SGT, intMin, bytes32(uint256(int256(-1))), new bytes32[](0)),
            "int256.min is not greater than anything"
        );
    }

    function test_SGT_MaxSentinelIsMinusOne_Reverts() public {
        // uint256.max reinterprets as -1; the OP_SGT(-1) guard must reject it
        Permission memory p = _permWithRule(0, OP_SGT, bytes32(uint256(int256(-1))));
        bytes memory cd = _cd(bytes32(type(uint256).max));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector, 0, OP_SGT, p.rules[0].value, bytes32(type(uint256).max)
            )
        );
        wrapper.validateCalldata(cd, p);
    }

    function testFuzz_SGT_MatchesNativeSignedComparison(int256 actual, int256 expected) public view {
        bool result = ClankerGateCore.compareRule(
            OP_SGT, bytes32(uint256(actual)), bytes32(uint256(expected)), new bytes32[](0)
        );
        assertEq(result, actual > expected, "OP_SGT must match int256 >");
    }

    function testFuzz_SLT_MatchesNativeSignedComparison(int256 actual, int256 expected) public view {
        bool result = ClankerGateCore.compareRule(
            OP_SLT, bytes32(uint256(actual)), bytes32(uint256(expected)), new bytes32[](0)
        );
        assertEq(result, actual < expected, "OP_SLT must match int256 <");
    }

    function test_InvalidOperator_EightReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.InvalidOperator.selector, uint8(8)));
        wrapper.compareRuleWrapped(8, bytes32(0), bytes32(0), new bytes32[](0));
    }

    function test_InvalidOperator_MaxUint8Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.InvalidOperator.selector, uint8(255)));
        wrapper.compareRuleWrapped(255, bytes32(0), bytes32(0), new bytes32[](0));
    }
}

// ============================================================
//  OP_IN boundary and semantic edge cases
// ============================================================
contract OpInEdgeCasesTest is EdgeCaseBase {
    function _values(uint256 n) internal pure returns (bytes32[] memory v) {
        v = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            v[i] = bytes32(i + 1);
        }
    }

    function test_ExactlyMaxInValues_LastElementMatches() public view {
        // 20 values (MAX_IN_VALUES boundary), match on the final element
        bytes32[] memory v = _values(MAX_IN_VALUES);
        Permission memory p;
        p.selector = SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule(0, OP_IN, bytes32(0), v);

        (bool valid,,) = wrapper.validateCalldata(_cd(bytes32(uint256(MAX_IN_VALUES))), p);
        assertTrue(valid, "20-value set must be accepted and match its last element");
    }

    function test_TwentyOneValues_RevertsAtCompareTime() public {
        // hashPermission blocks >20 values before any leaf exists, but the
        // compare-time require is a second line of defense — lock it too.
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.TooManyValues.selector, uint256(MAX_IN_VALUES + 1), MAX_IN_VALUES)
        );
        wrapper.compareRuleWrapped(OP_IN, bytes32(uint256(1)), bytes32(0), _values(MAX_IN_VALUES + 1));
    }

    function test_DuplicateValuesInSet_StillMatch() public view {
        bytes32[] memory v = new bytes32[](3);
        v[0] = bytes32(uint256(7));
        v[1] = bytes32(uint256(7));
        v[2] = bytes32(uint256(7));
        assertTrue(ClankerGateCore.compareRule(OP_IN, bytes32(uint256(7)), bytes32(0), v));
    }

    function test_ZeroIsALegitimateSetMember() public view {
        // bytes32(0) in the allowed set must match a zero calldata word —
        // membership is not confused with "empty"/"unset".
        bytes32[] memory v = new bytes32[](2);
        v[0] = bytes32(uint256(1));
        v[1] = bytes32(0);
        Permission memory p;
        p.selector = SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule(0, OP_IN, bytes32(0), v);

        (bool valid,,) = wrapper.validateCalldata(_cd(bytes32(0)), p);
        assertTrue(valid, "zero word must match a zero set member");
    }

    function test_RuleValueFieldIgnoredForOpIn() public view {
        // For OP_IN only `values` matters; a non-zero `value` must not create a
        // hidden extra constraint (it DOES affect the permission hash, though).
        bytes32[] memory v = new bytes32[](1);
        v[0] = bytes32(uint256(42));
        Permission memory p;
        p.selector = SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule(0, OP_IN, bytes32(uint256(0xDEAD)), v);

        (bool valid,,) = wrapper.validateCalldata(_cd(bytes32(uint256(42))), p);
        assertTrue(valid, "rule.value must be ignored for OP_IN matching");
    }
}

// ============================================================
//  MAX_RULES in the validate path, length boundaries, offset arithmetic,
//  and memory/calldata variant parity
// ============================================================
contract RuleLimitsAndBoundsTest is EdgeCaseBase {
    function _nRules(uint256 n) internal pure returns (Permission memory p) {
        p.selector = SEL;
        p.rules = new ParamRule[](n);
        for (uint256 i; i < n; ++i) {
            p.rules[i] = ParamRule(i * 32, OP_LTE, bytes32(type(uint256).max), new bytes32[](0));
        }
    }

    function test_ExactlyMaxRules_Pass() public view {
        Permission memory p = _nRules(MAX_RULES);
        bytes memory cd = abi.encodePacked(SEL, new bytes(uint256(MAX_RULES) * 32));
        (bool valid,,) = wrapper.validateCalldata(cd, p);
        assertTrue(valid, "exactly MAX_RULES rules must be allowed");
    }

    function test_ElevenRules_RevertInCalldataPath() public {
        Permission memory p = _nRules(uint256(MAX_RULES) + 1);
        bytes memory cd = abi.encodePacked(SEL, new bytes((uint256(MAX_RULES) + 1) * 32));
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.TooManyRules.selector, uint256(MAX_RULES) + 1, MAX_RULES)
        );
        wrapper.validateCalldata(cd, p);
    }

    function test_ElevenRules_RevertInMemoryPath() public {
        Permission memory p = _nRules(uint256(MAX_RULES) + 1);
        bytes memory cd = abi.encodePacked(SEL, new bytes((uint256(MAX_RULES) + 1) * 32));
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.TooManyRules.selector, uint256(MAX_RULES) + 1, MAX_RULES)
        );
        wrapper.validateMemory(cd, p);
    }

    function test_EmptyCalldata_InvalidLength_BothPaths() public view {
        Permission memory p;
        p.selector = SEL;
        p.rules = new ParamRule[](0);
        (bool v1, uint8 e1,) = wrapper.validateCalldata(hex"", p);
        (bool v2, uint8 e2,) = wrapper.validateMemory(hex"", p);
        assertFalse(v1);
        assertFalse(v2);
        assertEq(e1, ERR_INVALID_LENGTH);
        assertEq(e2, ERR_INVALID_LENGTH);
    }

    function test_ThreeByteCalldata_InvalidLength_BothPaths() public view {
        Permission memory p;
        p.selector = SEL;
        p.rules = new ParamRule[](0);
        (bool v1, uint8 e1,) = wrapper.validateCalldata(hex"123456", p);
        (bool v2, uint8 e2,) = wrapper.validateMemory(hex"123456", p);
        assertFalse(v1);
        assertFalse(v2);
        assertEq(e1, ERR_INVALID_LENGTH);
        assertEq(e2, ERR_INVALID_LENGTH);
    }

    function test_UnalignedOffset_StraddlingWordRead_BothPaths() public view {
        // Rule at offset 1 reads bytes [5, 37): one byte of padding shifts the
        // word — a rule offset need not be 32-aligned and both variants must
        // read the identical straddling word. 37-byte calldata = exact fit.
        bytes32 value = bytes32(uint256(0xCAFEBABE));
        bytes memory cd = abi.encodePacked(SEL, bytes1(0xAA), value);
        assertEq(cd.length, 37);

        Permission memory p = _permWithRule(1, OP_EQ, value);
        (bool v1,,) = wrapper.validateCalldata(cd, p);
        (bool v2,,) = wrapper.validateMemory(cd, p);
        assertTrue(v1, "calldata path must read the unaligned word");
        assertTrue(v2, "memory path must read the unaligned word");
    }

    function test_OneByteShortOfUnalignedWord_OutOfRange() public {
        bytes memory cd = abi.encodePacked(SEL, bytes1(0xAA), bytes31(0));
        assertEq(cd.length, 36);
        Permission memory p = _permWithRule(1, OP_EQ, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.CalldataOutOfRange.selector, uint256(5)));
        wrapper.validateCalldata(cd, p);
    }

    function test_RuleOffsetNearMaxUint_ArithmeticPanic() public {
        // 4 + rule.offset is checked arithmetic: an absurd offset panics (0x11)
        // instead of silently wrapping into a low offset.
        Permission memory p = _permWithRule(type(uint256).max, OP_EQ, bytes32(0));
        bytes memory cd = _cd(bytes32(0));
        vm.expectRevert(stdError.arithmeticError);
        wrapper.validateCalldata(cd, p);
    }

    function testFuzz_MemoryAndCalldataPathsAgree(bytes memory tail, bytes4 otherSelector, bool useMatchingSelector)
        public
        view
    {
        vm.assume(otherSelector != SEL);
        vm.assume(tail.length <= 96);

        bytes memory cd = abi.encodePacked(useMatchingSelector ? SEL : otherSelector, tail);

        Permission memory p;
        p.selector = SEL;
        if (tail.length >= 32) {
            bytes32 word0;
            assembly {
                word0 := mload(add(tail, 32))
            }
            p.rules = new ParamRule[](1);
            p.rules[0] = ParamRule(0, OP_EQ, word0, new bytes32[](0));
        } else {
            p.rules = new ParamRule[](0);
        }

        (bool v1, uint8 e1, uint256 i1) = wrapper.validateCalldata(cd, p);
        (bool v2, uint8 e2, uint256 i2) = wrapper.validateMemory(cd, p);
        assertEq(v1, v2, "valid flag must agree across variants");
        assertEq(e1, e2, "error code must agree across variants");
        assertEq(i1, i2, "rule index must agree across variants");
    }
}

// ============================================================
//  validatePermission exact time/chain boundaries
// ============================================================
contract ValidatePermissionBoundaryTest is Test {
    function test_ValidUntilEqualToNow_StillValid() public {
        vm.warp(1000);
        Permission memory p;
        p.validUntil = 1000;
        (bool valid, uint8 code) = ClankerGateCore.validatePermission(p);
        assertTrue(valid, "validUntil == block.timestamp must still be valid");
        assertEq(code, 0);
    }

    function test_ValidAfterEqualToNow_AlreadyValid() public {
        vm.warp(1000);
        Permission memory p;
        p.validAfter = 1000;
        (bool valid, uint8 code) = ClankerGateCore.validatePermission(p);
        assertTrue(valid, "validAfter == block.timestamp must already be valid");
        assertEq(code, 0);
    }

    function test_OneSecondPastValidUntil_Invalid() public {
        vm.warp(1001);
        Permission memory p;
        p.validUntil = 1000;
        (bool valid, uint8 code) = ClankerGateCore.validatePermission(p);
        assertFalse(valid);
        assertEq(code, 8);
    }

    function test_MatchingChainId_Valid() public view {
        Permission memory p;
        p.chainId = block.chainid;
        (bool valid, uint8 code) = ClankerGateCore.validatePermission(p);
        assertTrue(valid, "explicit matching chainId must be valid");
        assertEq(code, 0);
    }
}

// ============================================================
//  decodeExecuteCallMemory / decodeAnyExecuteMemory malformed-ABI cases
// ============================================================
contract DecodeEdgeCasesTest is EdgeCaseBase {
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 internal constant EXEC7579_SELECTOR = 0xe9ae5c53;

    function test_DirtyTargetPadding_Reverts() public {
        // Upper 12 bytes of the target word must be zero
        bytes32 dirtyTarget = bytes32(uint256(uint160(address(0xCAFE))) | (uint256(1) << 200));
        bytes memory cd = abi.encodePacked(
            EXECUTE_SELECTOR,
            dirtyTarget,
            uint256(0), // value
            uint256(0x60), // dataOffset
            uint256(4), // dataLength
            bytes4(0xdeadbeef),
            bytes28(0)
        );
        vm.expectRevert(ClankerGateCore.InvalidAddressPadding.selector);
        wrapper.decodeExecute(cd);
    }

    function test_OverstatedDataLength_Reverts() public {
        bytes memory cd = abi.encodePacked(
            EXECUTE_SELECTOR,
            bytes32(uint256(uint160(address(0xCAFE)))),
            uint256(0),
            uint256(0x60),
            uint256(1000), // claims 1000 bytes of inner data that don't exist
            bytes4(0xdeadbeef),
            bytes28(0)
        );
        vm.expectRevert(ClankerGateCore.InvalidExecuteEncoding.selector);
        wrapper.decodeExecute(cd);
    }

    function test_MaxUintDataOffset_ArithmeticPanic() public {
        // dataLengthPos wraps inside its unchecked block, but the final
        // innerDataOffset computation is checked and must panic rather than
        // decode from a wrapped position.
        bytes memory cd = abi.encodePacked(
            EXECUTE_SELECTOR,
            bytes32(uint256(uint160(address(0xCAFE)))),
            uint256(0),
            type(uint256).max, // dataOffset
            uint256(4),
            bytes4(0xdeadbeef),
            bytes28(0)
        );
        vm.expectRevert(stdError.arithmeticError);
        wrapper.decodeExecute(cd);
    }

    function test_TrailingBytesAfterTail_StillDecodes() public view {
        // Solidity accepts trailing calldata beyond the encoded tail; the
        // decoder must keep working and the inner slice must be unaffected.
        bytes memory inner = hex"deadbeef";
        bytes memory canonical =
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xCAFE), uint256(7), inner);
        bytes memory cd = abi.encodePacked(canonical, bytes32(uint256(0xBAD)));

        (address target, uint256 innerOffset, uint256 innerLength, uint256 value) = wrapper.decodeExecute(cd);
        assertEq(target, address(0xCAFE));
        assertEq(value, 7);
        assertEq(innerLength, inner.length);
        bytes4 innerSel;
        uint256 pos = innerOffset;
        assembly {
            innerSel := mload(add(add(cd, 32), pos))
        }
        assertEq(innerSel, bytes4(0xdeadbeef), "inner bytes must be unaffected by trailing garbage");
    }

    function test_7579_NonCanonicalExecOffset_DecodesConsistently() public view {
        // executionCalldata pointer 0x60 instead of 0x40 (one junk word); the
        // decoder follows the pointer, so a consistent non-canonical layout
        // must still decode to the same target/value/inner.
        address target = address(0xCAFE);
        bytes memory execData = abi.encodePacked(target, uint256(9), bytes4(0xdeadbeef));
        bytes memory cd = abi.encodePacked(
            EXEC7579_SELECTOR,
            bytes32(0), // mode: single, default
            uint256(0x60), // non-canonical pointer
            uint256(0xdead), // junk word
            uint256(execData.length),
            execData
        );

        (ClankerGateCore.ExecKind kind, address t,, uint256 innerLength, uint256 v) = wrapper.decodeAny(cd);
        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute7579Single));
        assertEq(t, target);
        assertEq(v, 9);
        assertEq(innerLength, 4);
    }

    function test_7579_ExecLenExactly52_EmptyInner() public view {
        // 20-byte target + 32-byte value and nothing else: inner length 0
        address target = address(0xCAFE);
        bytes memory execData = abi.encodePacked(target, uint256(3));
        assertEq(execData.length, 52);
        bytes memory cd = abi.encodeWithSelector(EXEC7579_SELECTOR, bytes32(0), execData);

        (ClankerGateCore.ExecKind kind, address t,, uint256 innerLength, uint256 v) = wrapper.decodeAny(cd);
        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute7579Single));
        assertEq(t, target);
        assertEq(v, 3);
        assertEq(innerLength, 0, "52-byte executionCalldata means empty inner call");
    }
}
