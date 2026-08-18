// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
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
    ERR_INVALID_LENGTH,
    ERR_SELECTOR_MISMATCH
} from "../../src/ClankerGateCore.sol";

/// @notice External wrapper so tests exercise the `bytes calldata` validation path
///         (assembly `calldataload`) and can use vm.expectRevert on library reverts.
contract ProtocolValidatorHarness {
    function validate(bytes calldata callData, Permission memory permission)
        external
        pure
        returns (bool valid, uint8 errorCode, uint256 ruleIndex)
    {
        return ClankerGateCore.validateCallDataExtended(callData, permission);
    }

    function decodeAny(bytes memory callData)
        external
        pure
        returns (ClankerGateCore.ExecKind kind, address target, uint256 innerOffset, uint256 innerLength, uint256 value)
    {
        return ClankerGateCore.decodeAnyExecuteMemory(callData);
    }
}

/// @notice Shared fixtures and builders for real-protocol calldata validation tests.
///         Rule offsets are relative to the end of the 4-byte selector: static
///         parameter i lives at offset 32*i.
abstract contract ProtocolCalldataTestBase is Test {
    ProtocolValidatorHarness internal harness;

    // Session-key policy actors
    address internal constant ACCOUNT = 0xAcc0000000000000000000000000000000000001;
    address internal constant ATTACKER = 0xBAd0000000000000000000000000000000000Bad;

    // Common mainnet-style token addresses (values are arbitrary but distinct)
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address internal constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    function setUp() public virtual {
        harness = new ProtocolValidatorHarness();
    }

    // ---------------------------------------------------------------- builders

    function _perm(address target, bytes4 selector, ParamRule[] memory rules)
        internal
        pure
        returns (Permission memory p)
    {
        p.target = target;
        p.selector = selector;
        p.rules = rules;
    }

    function _noRules() internal pure returns (ParamRule[] memory r) {
        r = new ParamRule[](0);
    }

    function _rules1(ParamRule memory a) internal pure returns (ParamRule[] memory r) {
        r = new ParamRule[](1);
        r[0] = a;
    }

    function _rules2(ParamRule memory a, ParamRule memory b) internal pure returns (ParamRule[] memory r) {
        r = new ParamRule[](2);
        r[0] = a;
        r[1] = b;
    }

    function _rules3(ParamRule memory a, ParamRule memory b, ParamRule memory c)
        internal
        pure
        returns (ParamRule[] memory r)
    {
        r = new ParamRule[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    function _rules4(ParamRule memory a, ParamRule memory b, ParamRule memory c, ParamRule memory d)
        internal
        pure
        returns (ParamRule[] memory r)
    {
        r = new ParamRule[](4);
        r[0] = a;
        r[1] = b;
        r[2] = c;
        r[3] = d;
    }

    function _rule(uint256 offset, uint8 op, bytes32 value) internal pure returns (ParamRule memory) {
        return ParamRule(offset, op, value, new bytes32[](0));
    }

    function _ruleAddr(uint256 offset, uint8 op, address value) internal pure returns (ParamRule memory) {
        return ParamRule(offset, op, bytes32(uint256(uint160(value))), new bytes32[](0));
    }

    function _ruleUint(uint256 offset, uint8 op, uint256 value) internal pure returns (ParamRule memory) {
        return ParamRule(offset, op, bytes32(value), new bytes32[](0));
    }

    function _ruleIn(uint256 offset, bytes32[] memory values) internal pure returns (ParamRule memory) {
        return ParamRule(offset, OP_IN, bytes32(0), values);
    }

    function _addrSet2(address a, address b) internal pure returns (bytes32[] memory s) {
        s = new bytes32[](2);
        s[0] = bytes32(uint256(uint160(a)));
        s[1] = bytes32(uint256(uint160(b)));
    }

    function _addrSet3(address a, address b, address c) internal pure returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = bytes32(uint256(uint160(a)));
        s[1] = bytes32(uint256(uint160(b)));
        s[2] = bytes32(uint256(uint160(c)));
    }

    // ---------------------------------------------------------------- wrappers

    /// @dev ERC-4337 execute(address,uint256,bytes) wrapper
    function _wrap4337(address target, uint256 value, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", target, value, inner);
    }

    /// @dev ERC-7579 execute(bytes32,bytes) single-call, zero mode
    function _wrap7579Single(address target, uint256 value, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(0xe9ae5c53, bytes32(0), abi.encodePacked(target, value, inner));
    }

    // ---------------------------------------------------------------- asserts

    function _assertValid(bytes memory callData, Permission memory p) internal view {
        (bool valid, uint8 errorCode,) = harness.validate(callData, p);
        assertTrue(valid, "expected calldata to pass policy");
        assertEq(errorCode, 0, "unexpected error code");
    }

    function _assertSelectorMismatch(bytes memory callData, Permission memory p) internal view {
        (bool valid, uint8 errorCode,) = harness.validate(callData, p);
        assertFalse(valid, "expected selector mismatch");
        assertEq(errorCode, ERR_SELECTOR_MISMATCH, "expected ERR_SELECTOR_MISMATCH");
    }

    function _assertInvalidLength(bytes memory callData, Permission memory p) internal view {
        (bool valid, uint8 errorCode,) = harness.validate(callData, p);
        assertFalse(valid, "expected invalid length");
        assertEq(errorCode, ERR_INVALID_LENGTH, "expected ERR_INVALID_LENGTH");
    }

    function _expectRuleViolation(bytes memory callData, Permission memory p, uint256 ruleIndex) internal {
        ParamRule memory r = p.rules[ruleIndex];
        bytes32 actual = _wordAt(callData, 4 + r.offset);
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.RuleViolation.selector, ruleIndex, r.op, r.value, actual)
        );
        harness.validate(callData, p);
    }

    function _expectNotInSet(bytes memory callData, Permission memory p, uint256 ruleIndex) internal {
        ParamRule memory r = p.rules[ruleIndex];
        bytes32 actual = _wordAt(callData, 4 + r.offset);
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, ruleIndex, actual, r.values)
        );
        harness.validate(callData, p);
    }

    function _expectOutOfRange(bytes memory callData, Permission memory p, uint256 absoluteOffset) internal {
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.CalldataOutOfRange.selector, absoluteOffset));
        harness.validate(callData, p);
    }

    /// @dev Reads the 32-byte word at `pos` bytes into `data` (mirrors the validator's read).
    function _wordAt(bytes memory data, uint256 pos) internal pure returns (bytes32 word) {
        require(pos + 32 <= data.length, "wordAt OOB");
        assembly {
            word := mload(add(add(data, 32), pos))
        }
    }

    /// @dev Copies `len` bytes of `data` starting at `start` — used to extract the
    ///      inner call from a decoded execute() wrapper.
    function _slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        require(start + len <= data.length, "slice OOB");
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = data[start + i];
        }
    }

    /// @dev Truncates `data` to `newLen` bytes (in-memory), for short-calldata cases.
    function _truncate(bytes memory data, uint256 newLen) internal pure returns (bytes memory out) {
        require(newLen <= data.length, "truncate grows");
        out = new bytes(newLen);
        for (uint256 i; i < newLen; ++i) {
            out[i] = data[i];
        }
    }
}
