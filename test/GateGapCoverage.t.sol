// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ClankerGateValidatorBase} from "../src/ClankerGateValidatorBase.sol";
import {Test} from "forge-std/Test.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateSafe} from "../src/ClankerGateSafe.sol";
import {ClankerGateCore, ParamRule, Permission, ERR_INVALID_LENGTH} from "../src/ClankerGateCore.sol";
import {PackedUserOperation, IAccount} from "../src/interfaces/IERC4337.sol";

contract OwnerAccountMock is IAccount {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view returns (address) {
        return _owner;
    }

    function validateUserOp(bytes calldata, bytes32, uint256) external pure returns (uint256) {
        return 0;
    }

    function callValidate(address gate, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256)
    {
        return ClankerGate4337(gate).validateUserOp(userOp, userOpHash);
    }
}

contract MockSafeForGaps {
    address[] public owners;

    constructor(address owner_) {
        owners.push(owner_);
    }

    function execTransactionFromModule(address, uint256, bytes calldata, uint8) external pure returns (bool) {
        return true;
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }
}

/// @title Gate-level coverage gaps: short calldata, cross-account singleUse
///        isolation, the empty-inner-calldata fallback, and Safe's
///        permission.authorizedCaller enforcement.
contract Gate4337GapsTest is Test {
    ClankerGate4337 gate;
    OwnerAccountMock account;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        gate = new ClankerGate4337();
        account = new OwnerAccountMock(owner);
    }

    function _packUserOp(address sender, bytes memory callData, bytes memory sigField)
        internal
        pure
        returns (PackedUserOperation memory u)
    {
        u.sender = sender;
        u.callData = callData;
        u.signature = sigField;
    }

    function _guardData(Permission memory permission, bytes32 userOpHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        return abi.encode(new bytes32[](0), permission, abi.encodePacked(r, s, v));
    }

    function _installSingleLeaf(address acct, Permission memory permission) internal returns (uint256 nonce) {
        nonce = gate.nonces(acct) + 1;
        bytes32 leaf = gate.computePermissionHash(acct, permission, nonce);
        vm.prank(acct);
        gate.setPolicyRoot(acct, leaf);
    }

    /// @notice ERR_INVALID_LENGTH was never asserted through a gate: calldata
    ///         shorter than 4 bytes must revert CallDataValidationFailed(1).
    function test_ShortCalldata_RevertsInvalidLength() public {
        Permission memory permission;
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        _installSingleLeaf(address(account), permission);

        bytes32 userOpHash = keccak256("test");
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateValidatorBase.CallDataValidationFailed.selector, ERR_INVALID_LENGTH)
        );
        gate.validateUserOp(_packUserOp(address(account), hex"1234", _guardData(permission, userOpHash)), userOpHash);
    }

    /// @notice The stated purpose of hashPermissionWithAccount: consuming a
    ///         singleUse permission on one account must not consume the same
    ///         permission installed on another account.
    function test_SingleUse_CrossAccountIsolation() public {
        OwnerAccountMock accountB = new OwnerAccountMock(owner);

        Permission memory permission;
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.singleUse = true;

        uint256 nonceA = _installSingleLeaf(address(account), permission);
        uint256 nonceB = _installSingleLeaf(address(accountB), permission);

        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = _guardData(permission, userOpHash);

        // Consume on account A
        uint256 resultA = account.callValidate(
            address(gate), _packUserOp(address(account), hex"12345678", guardData), userOpHash
        );
        assertEq(resultA, 0);
        assertTrue(
            gate.usedPermissionHashes(
                address(account), gate.computePermissionHash(address(account), permission, nonceA)
            ),
            "A's permission must be consumed"
        );

        // Account B is unaffected: same permission still validates
        assertFalse(
            gate.usedPermissionHashes(
                address(accountB), gate.computePermissionHash(address(accountB), permission, nonceB)
            ),
            "B's permission must NOT be consumed by A's use"
        );
        uint256 resultB = accountB.callValidate(
            address(gate), _packUserOp(address(accountB), hex"12345678", guardData), userOpHash
        );
        assertEq(resultB, 0, "same permission must still work on account B");
    }

    /// @notice Behavior lock: execute(target, 0, "") has innerLength == 0, and the
    ///         gate falls back to validating the WHOLE wrapper bytes — so the only
    ///         permission that matches is (target, EXECUTE_SELECTOR). This is
    ///         intentional but non-obvious; freeze it so a change is deliberate.
    function test_EmptyInnerCalldata_FallsBackToWrapperSelector() public {
        address target = address(0xCAFE);
        bytes memory wrapped = abi.encodeWithSignature("execute(address,uint256,bytes)", target, uint256(0), bytes(""));

        // A permission for the wrapper selector itself validates
        Permission memory permission;
        permission.target = target;
        permission.selector = 0xb61d27f6; // execute(address,uint256,bytes)
        permission.rules = new ParamRule[](0);
        _installSingleLeaf(address(account), permission);

        bytes32 userOpHash = keccak256("test");
        uint256 result = gate.validateUserOp(
            _packUserOp(address(account), wrapped, _guardData(permission, userOpHash)), userOpHash
        );
        assertEq(result, 0, "empty-inner wrapper validates against the execute selector");
    }

    /// @notice Counterpart: a normal protocol permission must NOT match an
    ///         empty-inner wrapper (the wrapper selector is compared instead).
    function test_EmptyInnerCalldata_ProtocolPermissionRejectsIt() public {
        address target = address(0xCAFE);
        bytes memory wrapped = abi.encodeWithSignature("execute(address,uint256,bytes)", target, uint256(0), bytes(""));

        Permission memory permission;
        permission.target = target;
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        _installSingleLeaf(address(account), permission);

        bytes32 userOpHash = keccak256("test");
        vm.expectRevert(abi.encodeWithSelector(ClankerGateValidatorBase.CallDataValidationFailed.selector, uint8(2)));
        gate.validateUserOp(
            _packUserOp(address(account), wrapped, _guardData(permission, userOpHash)), userOpHash
        );
    }
}

/// @notice permission.authorizedCaller on the Safe gate (CG-02 enforcement at
///         src/ClankerGateSafe.sol) was never exercised — the Safe suites only
///         cover the separate authorizeCaller whitelist. Both gates must pass:
///         whitelist membership AND the per-permission caller pin.
contract SafeAuthorizedCallerTest is Test {
    ClankerGateSafe gate;
    MockSafeForGaps safe;
    address ownerAddr;
    address callerOne;
    address callerTwo;
    address target;

    function setUp() public {
        ownerAddr = address(0xABCD);
        callerOne = address(0x1001);
        callerTwo = address(0x1002);
        target = address(0xCAFE);

        safe = new MockSafeForGaps(ownerAddr);
        gate = new ClankerGateSafe();

        // Both callers are on the generic whitelist
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), callerOne);
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), callerTwo);
    }

    function _pinnedPermission() internal view returns (Permission memory p) {
        p.target = target;
        p.selector = 0x12345678;
        p.rules = new ParamRule[](0);
        p.authorizedCaller = callerOne;
    }

    function _install(Permission memory permission) internal returns (bytes32[] memory proof) {
        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);
        proof = new bytes32[](0);
    }

    function test_AuthorizedCaller_PinnedCallerPasses() public {
        Permission memory permission = _pinnedPermission();
        bytes32[] memory proof = _install(permission);

        vm.prank(callerOne);
        bool success = gate.execTransaction(address(safe), target, 0, hex"12345678", 0, proof, permission);
        assertTrue(success);
    }

    function test_AuthorizedCaller_OtherWhitelistedCallerRejected() public {
        Permission memory permission = _pinnedPermission();
        bytes32[] memory proof = _install(permission);

        // callerTwo passes the whitelist but not the per-permission pin
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateSafe.UnauthorizedCallerForPermission.selector, callerTwo, callerOne
            )
        );
        vm.prank(callerTwo);
        gate.execTransaction(address(safe), target, 0, hex"12345678", 0, proof, permission);
    }

    function test_AuthorizedCallerZero_AnyWhitelistedCallerPasses() public {
        Permission memory permission = _pinnedPermission();
        permission.authorizedCaller = address(0);
        bytes32[] memory proof = _install(permission);

        vm.prank(callerTwo);
        bool success = gate.execTransaction(address(safe), target, 0, hex"12345678", 0, proof, permission);
        assertTrue(success, "zero authorizedCaller must not restrict whitelisted callers");
    }
}
