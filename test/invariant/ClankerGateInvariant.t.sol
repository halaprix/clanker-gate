// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test, Vm} from "forge-std/Test.sol";
import {ClankerGate4337} from "../../src/ClankerGate4337.sol";
import {ClankerGateCore, ParamRule, Permission} from "../../src/ClankerGateCore.sol";
import {IEntryPoint} from "../../src/interfaces/IERC4337.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

contract MockAccount {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view returns (address) {
        return _owner;
    }
}

contract InvariantHandler {
    ClankerGate4337 public gate;
    MockAccount public account;
    uint256 public ownerKey;
    address public owner;

    uint256 public ghost_nonce;
    bytes32 public ghost_lastRoot;

    constructor(address _gate, address _account, uint256 _ownerKey) {
        gate = ClankerGate4337(_gate);
        account = MockAccount(_account);
        ownerKey = _ownerKey;
        owner = vm.addr(_ownerKey);
    }

    /// @notice Encode UserOperation as bytes for validateUserOp (which now takes bytes)
    function _encodeUserOp(IEntryPoint.UserOperation memory userOp) internal pure returns (bytes memory) {
        return abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData,
            userOp.signature
        );
    }

    function setPolicyRoot(bytes32 root) external {
        ghost_lastRoot = root;
        ghost_nonce++;
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);
    }

    function validateWithPermission(Permission memory permission, bytes memory callData) external returns (uint256) {
        bytes32[] memory proof = new bytes32[](0);

        bytes32 userOpHash = keccak256(abi.encode(block.timestamp, ghost_nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;

        bytes memory guardData = abi.encode(proof, permission, signature);

        try gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData) returns (uint256 result) {
            return result;
        } catch {
            return 1;
        }
    }
}

contract ClankerGateInvariantTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Encode UserOperation as bytes for validateUserOp (which now takes bytes)
    function _encodeUserOp(IEntryPoint.UserOperation memory userOp) internal pure returns (bytes memory) {
        return abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData,
            userOp.signature
        );
    }

    ClankerGate4337 gate;
    MockAccount account;
    InvariantHandler handler;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);

        gate = new ClankerGate4337();
        account = new MockAccount(owner);
        handler = new InvariantHandler(address(gate), address(account), ownerKey);

        // Set initial policy root
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
    }

    // Invariant 1: Nonce always increments on setPolicyRoot
    function invariant_NonceIncrementsOnSetPolicyRoot() public view {
        uint256 nonce = gate.nonces(address(account));
        assertGt(nonce, 0, "Nonce should be at least 1 after setup");
    }

    // Invariant 2: Root zero means no validation possible
    function test_RootZeroBlocksValidation() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(0));

        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(ClankerGate4337.RootNotSet.selector);
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);

        // Restore root
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
    }

    // Invariant 3: Expired permissions are always rejected
    function test_ExpiredPermissionsRejected() public {
        // Skip forward in time so we can have a valid past timestamp
        vm.warp(1000);
        
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = uint48(block.timestamp - 1); // Already expired
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.PermissionExpired.selector,
            block.timestamp,
            permission.validUntil
        ));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    // Invariant 4: Future permissions are rejected (using test prefix for expectRevert)
    function test_FuturePermissionsRejected() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(block.timestamp + 1 hours); // Not yet valid
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.PermissionNotYetValid.selector,
            block.timestamp,
            permission.validAfter
        ));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    // Invariant 5: ChainId mismatch is always rejected
    function test_ChainIdMismatchRejected() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 999; // Wrong chain
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.ChainIdMismatch.selector,
            permission.chainId,
            block.chainid
        ));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    // Invariant 6: OP_IN only allows values in set
    function test_OP_INOnlyAllowsValuesInSet() public {
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));

        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues); // OP_IN
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Value 200 is in set - should pass
        bytes memory callDataPass = abi.encodePacked(
            bytes4(0x12345678),
            bytes32(uint256(200))
        );

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callDataPass;

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0, "Value in set should pass");

        // Value 999 is NOT in set - should revert
        bytes memory callDataFail = abi.encodePacked(
            bytes4(0x12345678),
            bytes32(uint256(999))
        );

        userOp.callData = callDataFail;

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateCore.ValueNotInSet.selector,
            0,
            bytes32(uint256(999)),
            allowedValues
        ));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    // Invariant 7: Single-use permissions can only be used once
    function test_SingleUseOnlyOnce() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        // First use - should pass
        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);

        // Verify it's marked as used (with account-scoped hash)
        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)));
        assertTrue(gate.usedPermissionHashes(address(account), accountPermissionHash));

        // Second use - should revert
        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateCore.PermissionAlreadyUsed.selector,
            accountPermissionHash
        ));
        vm.prank(address(account));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    // Invariant 8: Only authorized signer can validate
    function test_OnlyAuthorizedSigner() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        // Sign with wrong key
        uint256 wrongKey = 0x12345678;
        address wrongSigner = vm.addr(wrongKey);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.UnauthorizedSigner.selector,
            owner,
            wrongSigner
        ));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }
}
