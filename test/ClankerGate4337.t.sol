// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {IEntryPoint, IAccount} from "../src/interfaces/IERC4337.sol";

contract MockAccount is IAccount {
    address public owner;
    ClankerGate4337 public gate;

    constructor(address _owner) {
        owner = _owner;
    }

    function setGate(address _gate) external {
        gate = ClankerGate4337(_gate);
    }

    function validateUserOp(bytes calldata, bytes32, uint256)
        external
        pure
        returns (uint256)
    {
        return 0;
    }
}

contract ClankerGateTest is Test {
    using ECDSA for bytes32;

    ClankerGate4337 gate;
    MockAccount account;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        gate = new ClankerGate4337();
        account = new MockAccount(owner);
        account.setGate(address(gate));
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
}

// ============================================================
//                    CORE VALIDATION TESTS
// ============================================================

contract CoreValidationTests is ClankerGateTest {
    function test_SetPolicyRoot() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
        assertEq(gate.policyRoots(address(account)), bytes32(uint256(1)));
        assertEq(gate.nonces(address(account)), 1);
    }

    function test_RevertWhen_RootNotSet() public {
        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);

        bytes32 userOpHash = keccak256("test");
        bytes memory guardData =
            abi.encode(new bytes32[](0), Permission(address(0), bytes4(0), new ParamRule[](0), 0, 0, 0, false, 0, address(0)), hex"");

        vm.expectRevert(ClankerGate4337.RootNotSet.selector);
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ValidateUserOp_ZeroRules() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_RevertWhen_SelectorMismatch() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0xdeadbeef;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 1);
    }

    function test_RevertWhen_CalldataOutOfRange() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(1000, 0, bytes32(uint256(123)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.CalldataOutOfRange.selector, 1004));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_RevertWhen_UnauthorizedSigner() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        uint256 wrongKey = 0x5678;
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        address wrongSigner = vm.addr(wrongKey);
        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.UnauthorizedSigner.selector, owner, wrongSigner));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_RevertWhen_InvalidProof() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1)); // Invalid sibling
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(ClankerGate4337.InvalidProof.selector);
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ValidateRule_EQ_Pass() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 0, bytes32(uint256(123)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_LTE_Pass() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"123456780000000000000000000000000000000000000000000000000000000000000064";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_RevertWhen_RuleViolation_LTE() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"1234567800000000000000000000000000000000000000000000000000000000000002bc"; // 700 > 100

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector, 0, 4, bytes32(uint256(100)), bytes32(uint256(700))
            )
        );
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ValidateRule_IN_Pass() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues); // OP_IN = 5
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8"; // 200 in allowed

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_ValidateRule_IN_Fail() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ValidateRule_IN_MultipleAddresses() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");
        address addr3 = makeAddr("addr3");
        
        bytes32[] memory allowedReceivers = new bytes32[](3);
        allowedReceivers[0] = bytes32(uint256(uint160(addr1)));
        allowedReceivers[1] = bytes32(uint256(uint160(addr2)));
        allowedReceivers[2] = bytes32(uint256(uint160(addr3)));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedReceivers);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        
        bytes memory callData = new bytes(36);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);
        assembly {
            mstore(add(add(callData, 32), 4), addr2)
        }
        userOp.callData = callData;

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_SingleUsePermission_Pass() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
        
        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)));
        assertTrue(gate.usedPermissionHashes(address(account), accountPermissionHash));
    }

    function test_SingleUsePermission_RevertOnReplay() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);

        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)));
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, accountPermissionHash));
        vm.prank(address(account));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }
}

// ============================================================
//                    SESSION LIFECYCLE TESTS
// ============================================================

contract SessionLifecycleTests is ClankerGateTest {
    using MessageHashUtils for bytes32;

    function test_RevertWhen_PermissionExpired() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = uint48(block.timestamp);

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        vm.warp(block.timestamp + 1);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.PermissionExpired.selector, block.timestamp, permission.validUntil));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_RevertWhen_PermissionNotYetValid() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(block.timestamp + 3600);
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.PermissionNotYetValid.selector, block.timestamp, permission.validAfter));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ValidTimeWindow() public {
        vm.warp(10000);
        uint256 currentTime = block.timestamp;
        
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(currentTime - 3600);
        permission.validUntil = uint48(currentTime + 3600);
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_RevertWhen_ChainIdMismatch() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 999;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.ChainIdMismatch.selector, permission.chainId, block.chainid));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ChainIdWildcard_ZeroMeansAllChains() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        IEntryPoint.UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = hex"12345678";

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);
    }

    function test_NonceIncrementedOnSetPolicyRoot() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
        assertEq(gate.nonces(address(account)), 1);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(2)));
        assertEq(gate.nonces(address(account)), 2);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(0));
        assertEq(gate.nonces(address(account)), 3);
    }
}
