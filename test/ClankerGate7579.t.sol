// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "../src/interfaces/IERC7579.sol";

contract MockERC7579Account is IERC7579Account {
    address private _owner;
    mapping(uint256 => mapping(address => bool)) private _installedModules;
    mapping(uint256 => mapping(address => bytes)) private _moduleData;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view override returns (address) {
        return _owner;
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    ) external override {
        _installedModules[moduleTypeId][module] = true;
        _moduleData[moduleTypeId][module] = initData;
        
        ClankerGate7579(module).onInstall(initData);
    }

    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata
    ) external override {
        _installedModules[moduleTypeId][module] = false;
        ClankerGate7579(module).onUninstall("");
    }

    function isModuleInstalled(uint256 moduleTypeId, address module) external view override returns (bool) {
        return _installedModules[moduleTypeId][module];
    }

    function callValidate(
        address module,
        bytes calldata userOp,
        bytes32 userOpHash,
        bytes calldata guardData
    ) external returns (uint256) {
        return ClankerGate7579(module).validateUserOp(userOp, userOpHash, guardData);
    }
}

contract ClankerGate7579Test is Test {
    using ECDSA for bytes32;

    ClankerGate7579 gate;
    MockERC7579Account account;
    uint256 ownerKey;
    address owner;

    function setUp() public virtual {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        gate = new ClankerGate7579();
        account = new MockERC7579Account(owner);
    }

    function _encodeUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData
    ) internal pure returns (bytes memory) {
        return abi.encode(
            sender,
            nonce,
            bytes(""),
            callData,
            uint256(100000),
            uint256(100000),
            uint256(21000),
            uint256(1000000000),
            uint256(100000000),
            bytes("")
        );
    }

    function _createBasicPermission() internal pure returns (Permission memory) {
        Permission memory permission;
        permission.target = address(0); // Use address(0) for direct calls (allows any target)
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;
        return permission;
    }
}

// ============================================================
//                    MODULE INSTALLATION TESTS
// ============================================================

contract ModuleInstallationTests is ClankerGate7579Test {
    function test_OnInstall() public {
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(uint256(1)), address(0))
        );

        (address configOwner, bytes32 policyRoot, uint256 nonce, address sigValidator, bool installed) = 
            gate.getAccountConfig(address(account));
        
        assertEq(configOwner, owner);
        assertEq(policyRoot, bytes32(uint256(1)));
        assertEq(nonce, 1);
        assertEq(sigValidator, address(0));
        assertTrue(installed);
        assertTrue(gate.isModuleInstalled(address(account)));
    }

    function test_OnUninstall() public {
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(uint256(1)), address(0))
        );

        vm.prank(address(account));
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(gate), "");

        (,,,, bool installed) = gate.getAccountConfig(address(account));
        assertFalse(installed);
        assertFalse(gate.isModuleInstalled(address(account)));
    }

    function test_RevertWhen_NotInstalled() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = abi.encode(new bytes32[](0), permission, hex"");

        vm.expectRevert(ClankerGate7579.NotInstalled.selector);
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }
}

// ============================================================
//                    POLICY MANAGEMENT TESTS
// ============================================================

contract PolicyManagementTests is ClankerGate7579Test {
    function setUp() public override {
        super.setUp();
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
    }

    function test_SetPolicyRoot_ByOwner() public {
        vm.prank(owner);
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));

        (, bytes32 policyRoot, uint256 nonce,,) = gate.getAccountConfig(address(account));
        assertEq(policyRoot, bytes32(uint256(1)));
        assertEq(nonce, 2);
    }

    function test_SetPolicyRoot_ByAccount() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(2)));

        (, bytes32 policyRoot, uint256 nonce,,) = gate.getAccountConfig(address(account));
        assertEq(policyRoot, bytes32(uint256(2)));
        assertEq(nonce, 2);
    }

    function test_RevertWhen_SetPolicyRoot_Unauthorized() public {
        address unauthorized = address(0xDEAD);
        vm.prank(unauthorized);
        vm.expectRevert(ClankerGate7579.Unauthorized.selector);
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
    }
}

// ============================================================
//                    VALIDATION TESTS
// ============================================================

contract ValidationTests is ClankerGate7579Test {
    function setUp() public override {
        super.setUp();
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
    }

    function test_ValidateUserOp_ZeroRules() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_EQ_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 0, bytes32(uint256(123)), new bytes32[](0));

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";
        bytes memory userOp = _encodeUserOp(address(account), 0, callData);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_LTE_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000064";
        bytes memory userOp = _encodeUserOp(address(account), 0, callData);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_IN_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);

        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8";
        bytes memory userOp = _encodeUserOp(address(account), 0, callData);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_IN_Fail() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);

        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";
        bytes memory userOp = _encodeUserOp(address(account), 0, callData);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }

    function test_RevertWhen_InvalidProof() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(ClankerGate7579.InvalidProof.selector);
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }

    function test_RevertWhen_UnauthorizedSigner() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        uint256 wrongKey = 0x5678;
        address wrongSigner = vm.addr(wrongKey);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.UnauthorizedSigner.selector, owner, wrongSigner));
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }

    function test_RevertWhen_PermissionExpired() public {
        Permission memory permission = _createBasicPermission();
        permission.validUntil = uint48(block.timestamp);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        vm.warp(block.timestamp + 1);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.PermissionExpired.selector, block.timestamp, permission.validUntil));
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }

    function test_RevertWhen_ChainIdMismatch() public {
        Permission memory permission = _createBasicPermission();
        permission.chainId = 999;

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.ChainIdMismatch.selector, permission.chainId, block.chainid));
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }
}

// ============================================================
//                    SIGNATURE VALIDATOR TESTS
// ============================================================

contract SignatureValidatorTests is ClankerGate7579Test {
    MockERC7579Account customAccount;
    address customValidator;
    uint256 validatorKey;

    function setUp() public override {
        super.setUp();
        validatorKey = 0xABCD;
        customValidator = vm.addr(validatorKey);
    }

    function test_SignatureValidation_UsesAccountOwner() public {
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );

        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_SignatureValidation_UsesCustomValidator() public {
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), customValidator)
        );

        Permission memory permission = _createBasicPermission();
        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
    }
}

// ============================================================
//                    SINGLE USE TESTS
// ============================================================

contract SingleUseTests7579 is ClankerGate7579Test {
    function setUp() public override {
        super.setUp();
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
    }

    function test_SingleUsePermission_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.singleUse = true;

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);
        bytes32 accountPermissionHash = ClankerGateCore.hashPermissionWithAccount(address(account), permission);
        assertTrue(gate.usedPermissionHashes(address(account), accountPermissionHash));
    }

    function test_SingleUsePermission_RevertOnReplay() public {
        Permission memory permission = _createBasicPermission();
        permission.singleUse = true;

        bytes32 leaf = ClankerGateCore.hashPermission(permission);

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory userOp = _encodeUserOp(address(account), 0, hex"12345678");
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        // First execution
        uint256 result = account.callValidate(address(gate), userOp, userOpHash, guardData);
        assertEq(result, 0);

        bytes32 accountPermissionHash = ClankerGateCore.hashPermissionWithAccount(address(account), permission);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, accountPermissionHash));
        account.callValidate(address(gate), userOp, userOpHash, guardData);
    }
}

// ============================================================
//                    COMPUTE PERMISSION HASH TESTS
// ============================================================

contract ComputePermissionHashTests is ClankerGate7579Test {
    function test_ComputePermissionHash() public {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule(0, 0, bytes32(uint256(100)), new bytes32[](0));

        bytes32 hash = gate.computePermissionHash(
            address(0x1111),
            0x12345678,
            rules,
            0,
            0,
            0,
            false
        );

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = rules;
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        assertEq(hash, ClankerGateCore.hashPermission(permission));
    }
}
