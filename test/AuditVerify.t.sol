// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateCore, Permission, ParamRule} from "../src/ClankerGateCore.sol";
import {IEntryPoint, IAccount} from "../src/interfaces/IERC4337.sol";

/// Harness to expose the internal library decode for direct testing.
contract CoreHarness {
    function decodeMem(bytes memory cd)
        external
        pure
        returns (address target, uint256 innerOffset, uint256 innerLength, uint256 value)
    {
        return ClankerGateCore.decodeExecuteCallMemory(cd);
    }
}

contract AccountMock is IAccount {
    address private _owner;
    constructor(address o) { _owner = o; }
    function owner() external view override returns (address) { return _owner; }
    function validateUserOp(bytes calldata, bytes32, uint256) external pure override returns (uint256) { return 0; }
}

/// A proxy-style account that ALSO exposes implementation() (common in proxy accounts).
contract ProxyAccountMock is IAccount {
    address private _owner;
    address public immutable IMPL = address(0x000000000000000000000000000000000000bEEF);
    constructor(address o) { _owner = o; }
    function owner() external view override returns (address) { return _owner; }
    function implementation() external view returns (address) { return IMPL; }
    function validateUserOp(bytes calldata, bytes32, uint256) external pure override returns (uint256) { return 0; }
}

contract AuditVerify is Test {
    CoreHarness harness;
    ClankerGate4337 gate;
    AccountMock account;
    uint256 ownerKey = 0xA11CE;
    address owner;

    // a fake "router" target and an inner function selector (e.g. a swap)
    address constant ROUTER = 0x00000000000000000000000000000000DeaDBeef;
    bytes4 constant INNER_SEL = bytes4(keccak256("swap(uint256)"));

    function setUp() public {
        harness = new CoreHarness();
        gate = new ClankerGate4337();
        owner = vm.addr(ownerKey);
        account = new AccountMock(owner);
    }

    /// FIX (C-1 + C-2): EXECUTE_SELECTOR is now 0xb61d27f6 and offset math is corrected.
    /// A real execute(address,uint256,bytes) wrapper is now correctly decoded.
    function test_realExecuteWrapper_isDecoded() public view {
        bytes memory inner = abi.encodeWithSelector(INNER_SEL, uint256(100 ether));
        bytes memory wrapped = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", ROUTER, uint256(5 ether), inner
        );
        // sanity: this is the standard selector real accounts use
        assertEq(bytes4(wrapped), bytes4(0xb61d27f6), "real execute selector");

        (address target, , uint256 innerLength, uint256 value) = harness.decodeMem(wrapped);

        // After the fix: the wrapper is correctly decoded.
        assertEq(target, ROUTER, "target extracted correctly");
        assertEq(value, 5 ether, "value extracted correctly");
        assertEq(innerLength, inner.length, "inner length == inner call length (not whole calldata)");
    }

    /// Round-trip test: build execute(addr, value, inner) and assert decode is exact.
    function test_executeWrapper_roundTrip() public view {
        // Case 1: non-empty inner
        bytes memory inner = abi.encodeWithSelector(INNER_SEL, uint256(42 ether));
        bytes memory wrapped = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", ROUTER, uint256(1 ether), inner
        );
        (address t1, uint256 off1, uint256 len1, uint256 v1) = harness.decodeMem(wrapped);
        assertEq(t1, ROUTER, "round-trip target");
        assertEq(v1, 1 ether, "round-trip value");
        assertEq(len1, inner.length, "round-trip inner length");

        // Verify the inner bytes are correct at the reported offset
        bytes memory extracted1 = new bytes(len1);
        for (uint256 i = 0; i < len1; i++) {
            extracted1[i] = wrapped[off1 + i];
        }
        assertEq(extracted1, inner, "round-trip inner bytes match");

        // Case 2: empty inner
        bytes memory emptyInner = new bytes(0);
        bytes memory wrappedEmpty = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", ROUTER, uint256(0), emptyInner
        );
        (address t2, , uint256 len2, uint256 v2) = harness.decodeMem(wrappedEmpty);
        assertEq(t2, ROUTER, "empty inner: target");
        assertEq(v2, 0, "empty inner: value");
        assertEq(len2, 0, "empty inner: length is zero");
    }

    /// Fuzz: for any (addr, value, inner), decode returns the exact inputs back.
    function testFuzz_executeWrapper_roundTrip(address addr, uint256 val, bytes calldata innerData) public view {
        // Skip the zero address (maps to the "direct" branch, not a useful fuzz target here)
        vm.assume(addr != address(0));
        // Skip excessively large inner to keep gas bounded
        vm.assume(innerData.length <= 1024);

        bytes memory wrapped = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", addr, val, innerData
        );
        (address target, uint256 innerOffset, uint256 innerLength, uint256 value) = harness.decodeMem(wrapped);

        assertEq(target, addr, "fuzz: target");
        assertEq(value, val, "fuzz: value");
        assertEq(innerLength, innerData.length, "fuzz: inner length");

        // Verify bytes content
        bytes memory extracted = new bytes(innerLength);
        for (uint256 i = 0; i < innerLength; i++) {
            extracted[i] = wrapped[innerOffset + i];
        }
        assertEq(extracted, innerData, "fuzz: inner bytes match");
    }

    /// FIX (C-1 + C-2, end-to-end): a policy-compliant call wrapped in execute() the way
    /// every real ERC-4337 account submits it now PASSES validation correctly.
    function test_4337_wrappedCompliantCall_passes() public {
        // Policy: allow INNER_SEL on ROUTER, arg <= 1 ether, no ETH.
        Permission memory p;
        p.target = ROUTER;
        p.selector = INNER_SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule({offset: 0, op: 4 /*LTE*/, value: bytes32(uint256(1 ether)), values: new bytes32[](0)});
        // single-leaf tree: root == leaf computed at nonce that validation will use (post-increment = 1)
        bytes32 leaf = gate.computePermissionHash(address(account), p, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, p, sig);

        bytes memory innerCompliant = abi.encodeWithSelector(INNER_SEL, uint256(0.5 ether)); // within limit

        // (1) Real account flow: callData = execute(ROUTER, 0, innerCompliant) — now passes.
        bytes memory wrapped = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", ROUTER, uint256(0), innerCompliant
        );
        uint256 vd1 = gate.validateUserOp(_userOp(address(account), wrapped), userOpHash, guardData);
        assertEq(vd1, 0, "WRAPPED compliant call passes (returns 0 = valid)");

        // (2) Direct (unwrapped) inner call also passes — unchanged behaviour.
        // Need a fresh nonce: use nonce=2 for the second call.
        bytes32 leaf2 = gate.computePermissionHash(address(account), p, 2);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerKey, userOpHash);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        bytes memory guardData2 = abi.encode(proof, p, sig2);
        uint256 vd2 = gate.validateUserOp(_userOp(address(account), innerCompliant), userOpHash, guardData2);
        assertEq(vd2, 0, "direct (unwrapped) inner call passes");
    }

    /// FINDING: _getOwner() calls implementation() (0x5c60da1b) FIRST and only falls back to
    /// owner() (0x8da5cb5b). An account that exposes implementation() has its *implementation
    /// contract address* treated as the owner, so every owner-signed op is rejected (DoS).
    function test_getOwner_usesImplementationAsOwner() public {
        ProxyAccountMock proxyAcct = new ProxyAccountMock(owner);

        Permission memory p;
        p.target = ROUTER;
        p.selector = INNER_SEL;
        p.rules = new ParamRule[](1);
        p.rules[0] = ParamRule({offset: 0, op: 4, value: bytes32(uint256(1 ether)), values: new bytes32[](0)});
        bytes32 leaf = gate.computePermissionHash(address(proxyAcct), p, 1);
        vm.prank(address(proxyAcct));
        gate.setPolicyRoot(address(proxyAcct), leaf);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, p, sig);
        bytes memory inner = abi.encodeWithSelector(INNER_SEL, uint256(0.5 ether));

        // Real owner signed correctly, yet validation reverts because _getOwner returned IMPL (0xBEEF).
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGate4337.UnauthorizedSigner.selector, address(0xBEEF), owner)
        );
        gate.validateUserOp(_userOp(address(proxyAcct), inner), userOpHash, guardData);
    }

    function _userOp(address sender, bytes memory callData) internal pure returns (bytes memory) {
        return abi.encode(
            sender, uint256(0), bytes(""), callData,
            uint256(0), uint256(0), uint256(0), uint256(0), uint256(0),
            bytes(""), bytes("")
        );
    }
}
