// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "../src/interfaces/IERC7579.sol";
import {PackedUserOperation} from "../src/interfaces/IERC4337.sol";

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

    /// @notice Call validateUserOp on the module with a PackedUserOperation (2-arg ERC-7579 form)
    function callValidate(
        address module,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        return ClankerGate7579(module).validateUserOp(userOp, userOpHash);
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

    /// @notice Build a minimal PackedUserOperation for testing.
    ///         `sigField` should be abi.encode(proof, permission, ownerSig).
    function _packUserOp(
        address sender,
        bytes memory callData,
        bytes memory sigField
    ) internal pure returns (PackedUserOperation memory u) {
        u.sender = sender;
        u.callData = callData;
        u.signature = sigField;
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
        permission.maxValue = 0;
        return permission;
    }
}

// ============================================================
//                    MODULE TYPE TESTS
// ============================================================

contract ModuleTypeTests is ClankerGate7579Test {
    function test_isModuleType() public {
        assertTrue(gate.isModuleType(1), "isModuleType(1) should be true (Validator)");
        assertFalse(gate.isModuleType(2), "isModuleType(2) should be false (not Executor)");
        assertFalse(gate.isModuleType(0), "isModuleType(0) should be false");
        assertFalse(gate.isModuleType(3), "isModuleType(3) should be false");
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

    /// @notice M-5: After uninstall then reinstall the nonce must increase monotonically.
    function test_onUninstall_reinstallGetsFreshNonce() public {
        // First install — nonce should be 1 (first epoch)
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
        (,, uint256 nonce1,,) = gate.getAccountConfig(address(account));
        assertEq(nonce1, 1, "first install nonce should be 1");

        // Uninstall
        vm.prank(address(account));
        account.uninstallModule(MODULE_TYPE_VALIDATOR, address(gate), "");
        (,,,, bool installedAfterUninstall) = gate.getAccountConfig(address(account));
        assertFalse(installedAfterUninstall, "should not be installed after uninstall");

        // Reinstall — nonce should be 2 (next epoch, strictly greater)
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
        (,, uint256 nonce2,,) = gate.getAccountConfig(address(account));
        assertEq(nonce2, 2, "reinstall nonce should be 2 (greater than previous)");

        // A singleUse permission hash computed under nonce1 is different from nonce2,
        // so stale markings from the first install cannot collide with the new install.
        assertTrue(nonce2 > nonce1, "reinstall epoch must be strictly greater than previous");
    }

    function test_RevertWhen_NotInstalled() public {
        Permission memory permission = _createBasicPermission();

        bytes32[] memory proof = new bytes32[](0);
        bytes memory sigField = abi.encode(proof, permission, hex"");
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);
        bytes32 userOpHash = keccak256("test");

        vm.expectRevert(ClankerGate7579.NotInstalled.selector);
        // msg.sender of validateUserOp must be the account; prank to simulate that
        vm.prank(address(account));
        gate.validateUserOp(userOp, userOpHash);
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
        assertEq(nonce, 1);
    }

    function test_SetPolicyRoot_ByAccount() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(2)));

        (, bytes32 policyRoot, uint256 nonce,,) = gate.getAccountConfig(address(account));
        assertEq(policyRoot, bytes32(uint256(2)));
        assertEq(nonce, 1);
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

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0);
    }

    function test_ValidateRule_EQ_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 0, bytes32(uint256(123)), new bytes32[](0));

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0);
    }

    function test_ValidateRule_LTE_Pass() public {
        Permission memory permission = _createBasicPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000064";
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
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

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8";
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
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

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, sigField);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_RevertWhen_InvalidProof() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(proof, permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        vm.expectRevert(ClankerGate7579.InvalidProof.selector);
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_RevertWhen_UnauthorizedSigner() public {
        Permission memory permission = _createBasicPermission();
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        uint256 wrongKey = 0x5678;

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.UnauthorizedSigner.selector, owner, address(0)));
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_RevertWhen_PermissionExpired() public {
        Permission memory permission = _createBasicPermission();
        permission.validUntil = uint48(block.timestamp);

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        vm.warp(block.timestamp + 1);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.PermissionExpired.selector, block.timestamp, permission.validUntil));
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_RevertWhen_ChainIdMismatch() public {
        Permission memory permission = _createBasicPermission();
        permission.chainId = 999;

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.ChainIdMismatch.selector, permission.chainId, block.chainid));
        account.callValidate(address(gate), userOp, userOpHash);
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
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
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
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0);
    }
}

// ============================================================
//              isValidSignatureWithSender TESTS (D6)
// ============================================================

contract IsValidSignatureWithSenderTests is ClankerGate7579Test {
    function setUp() public override {
        super.setUp();
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
    }

    /// @notice D6: valid owner signature over a hash returns 0x1626ba7e
    function test_isValidSignatureWithSender_validSig() public {
        bytes32 hash = keccak256("some data to sign");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // msg.sender must be the account (the module was installed on it)
        vm.prank(address(account));
        bytes4 result = gate.isValidSignatureWithSender(address(0xBEEF), hash, sig);
        assertEq(result, bytes4(0x1626ba7e), "valid owner sig should return ERC-1271 magic value");
    }

    /// @notice D6: bad signature returns 0xffffffff
    function test_isValidSignatureWithSender_invalidSig() public {
        bytes32 hash = keccak256("some data to sign");
        uint256 wrongKey = 0x9999;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(account));
        bytes4 result = gate.isValidSignatureWithSender(address(0xBEEF), hash, sig);
        assertEq(result, bytes4(0xffffffff), "invalid sig should return 0xffffffff");
    }

    /// @notice D6: not-installed account returns 0xffffffff
    function test_isValidSignatureWithSender_notInstalled() public {
        bytes32 hash = keccak256("some data");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        address notInstalled = address(0xDEAD1234);
        vm.prank(notInstalled);
        bytes4 result = gate.isValidSignatureWithSender(address(0xBEEF), hash, sig);
        assertEq(result, bytes4(0xffffffff), "not-installed account should return 0xffffffff");
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

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0);
        // Verify replay is blocked - second call should revert
        vm.expectRevert();
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_SingleUsePermission_RevertOnReplay() public {
        Permission memory permission = _createBasicPermission();
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        // First execution
        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0);

        // Verify replay is blocked - second call should revert
        vm.expectRevert();
        account.callValidate(address(gate), userOp, userOpHash);
    }
}

// ============================================================
//                    COMPUTE PERMISSION HASH TESTS
// ============================================================

contract ComputePermissionHashTests is ClankerGate7579Test {
    function test_ComputePermissionHash() public {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule(0, 0, bytes32(uint256(100)), new bytes32[](0));

        // Correct arg order: (target, selector, rules, validAfter, validUntil, chainId, singleUse, maxValue)
        bytes32 hash1 = gate.computePermissionHash(
            address(0x1111),
            0x12345678,
            rules,
            0,         // validAfter
            0,         // validUntil
            0,         // chainId
            false,     // singleUse
            0          // maxValue
        );

        // Verify consistency - calling with same params gives same hash
        bytes32 hash2 = gate.computePermissionHash(
            address(0x1111),
            0x12345678,
            rules,
            0,
            0,
            0,
            false,
            0
        );

        assertEq(hash1, hash2);

        // Verify different params give different hash — pass chainId=1 (correct position)
        bytes32 hash3 = gate.computePermissionHash(
            address(0x1111),
            0x12345678,
            rules,
            0,         // validAfter
            0,         // validUntil
            1,         // chainId = 1 (different)
            false,     // singleUse
            0          // maxValue
        );

        assertTrue(hash1 != hash3);
    }
}

// ============================================================
//              AUTHORIZED CALLER ENFORCEMENT TESTS (H-2)
// ============================================================

contract AuthorizedCallerTests7579 is ClankerGate7579Test {
    function setUp() public override {
        super.setUp();
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );
    }

    /// @notice H-2: A permission whose authorizedCaller does NOT match msg.sender (the account)
    /// must revert UnauthorizedCallerForPermission.
    function test_authorizedCaller_enforced() public {
        address nonMatchingCaller = address(0xDEAD5678);

        Permission memory permission = _createBasicPermission();
        permission.authorizedCaller = nonMatchingCaller; // Does NOT match msg.sender (== account)

        // Compute leaf using the on-chain helper so authorizedCaller is baked in.
        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        // msg.sender inside validateUserOp is address(account) != nonMatchingCaller → must revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGate7579.UnauthorizedCallerForPermission.selector,
                address(account),
                nonMatchingCaller
            )
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }

    /// @notice H-2: A permission with authorizedCaller == address(0) must allow any caller
    /// (i.e., validation proceeds as normal).
    function test_authorizedCaller_zeroAllowsAny() public {
        Permission memory permission = _createBasicPermission();
        permission.authorizedCaller = address(0); // No restriction

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0, "zero authorizedCaller must allow any caller");
    }
}

// ============================================================
//                    EIP-1271 OWNER TESTS (M-4)
// ============================================================

/// @notice Minimal EIP-1271 wallet that accepts signatures valid under a known EOA key.
contract EIP1271Wallet7579 {
    address public immutable signer;
    bytes4 constant MAGIC = 0x1626ba7e;

    constructor(address _signer) {
        signer = _signer;
    }

    function isValidSignature(bytes32 hash, bytes memory sig) external view returns (bytes4) {
        if (sig.length != 65) return bytes4(0xffffffff);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        address recovered = ecrecover(hash, v, r, s);
        return (recovered == signer) ? MAGIC : bytes4(0xffffffff);
    }
}

contract EIP1271OwnerTests7579 is ClankerGate7579Test {
    /// @notice M-4: signatureValidator is a contract (EIP-1271 wallet); gate routes to isValidSignature.
    function test_eip1271Owner_7579() public {
        // Deploy a 1271 wallet that signs with ownerKey
        EIP1271Wallet7579 wallet = new EIP1271Wallet7579(owner);

        // Install module with the 1271 wallet as the signatureValidator
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(wallet))
        );

        Permission memory permission = _createBasicPermission();
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("eip1271test7579");
        // Sign with ownerKey — wallet.isValidSignature will recover this and return magic
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0, "EIP-1271 contract signatureValidator should validate successfully");
    }

    /// @notice M-4: signatureValidator is a contract but returns invalid magic — gate reverts.
    function test_eip1271Owner_7579_badSig_reverts() public {
        EIP1271Wallet7579 wallet = new EIP1271Wallet7579(owner);

        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(wallet))
        );

        Permission memory permission = _createBasicPermission();
        bytes32 leaf = gate.computePermissionHashWithAccount(
            address(account),
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        vm.prank(owner);
        gate.setPolicyRoot(address(account), leaf);

        uint256 wrongKey = 0x9999;
        bytes32 userOpHash = keccak256("eip1271test7579bad");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory sigField = abi.encode(new bytes32[](0), permission, signature);
        PackedUserOperation memory userOp = _packUserOp(address(account), hex"12345678", sigField);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate7579.UnauthorizedSigner.selector, address(wallet), address(0)));
        account.callValidate(address(gate), userOp, userOpHash);
    }
}
