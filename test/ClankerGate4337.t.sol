// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {PackedUserOperation, IEntryPoint, IAccount} from "../src/interfaces/IERC4337.sol";

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

    /// @notice Build a PackedUserOperation for gate.validateUserOp (v0.7 2-arg form).
    /// accountGasLimits/gasFees/nonce etc. can be zero — gate only reads sender/callData/signature.
    function _packUserOp(address sender, bytes memory callData, bytes memory sigField)
        internal pure returns (PackedUserOperation memory u)
    {
        u.sender = sender;
        u.callData = callData;
        u.signature = sigField;
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
        bytes32 userOpHash = keccak256("test");
        bytes memory guardData =
            abi.encode(new bytes32[](0), Permission(address(0), bytes4(0), 0, 0, false, 0, 0, address(0), new ParamRule[](0)), hex"");

        vm.expectRevert(ClankerGate4337.RootNotSet.selector);
        gate.validateUserOp(_packUserOp(address(account), hex"", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        // A8: selector mismatch is a structural breach → revert CallDataValidationFailed
        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.CallDataValidationFailed.selector, uint8(2)));
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.CalldataOutOfRange.selector, 1004));
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        // A8: signature failure is packed in validationData (sigFailed bit = 1); does NOT revert.
        uint256 vd = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(vd & 1, 1, "sigFailed bit must be set for bad signature");

        // A singleUse permission must NOT be marked used when signature fails.
        bytes32 permHash = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)));
        assertFalse(gate.usedPermissionHashes(address(account), permHash), "singleUse must not be consumed on sig failure");
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(ClankerGate4337.InvalidProof.selector);
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory callData = hex"12345678000000000000000000000000000000000000000000000000000000000000007b";
        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory callData = hex"123456780000000000000000000000000000000000000000000000000000000000000064";
        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000002bc"; // 700 > 100
        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector, 0, 4, bytes32(uint256(100)), bytes32(uint256(700))
            )
        );
        gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8"; // 200 in allowed
        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";
        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory callData = new bytes(36);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);
        assembly {
            mstore(add(add(callData, 32), 4), addr2)
        }
        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(result, 0);

        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, gate.nonces(address(account)));
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, accountPermissionHash));
        vm.prank(address(account));
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        // A8: expiry is returned in packed validationData (EntryPoint enforces), NOT a revert.
        uint256 vd = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(vd & 1, 0, "sigFailed bit must be 0 for good signature");
        assertEq(uint48(vd >> 160), permission.validUntil, "validUntil must be packed correctly");
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        // A8: not-yet-valid is returned in packed validationData (EntryPoint enforces), NOT a revert.
        uint256 vd = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(vd & 1, 0, "sigFailed bit must be 0 for good signature");
        assertEq(uint48(vd >> 208), permission.validAfter, "validAfter must be packed correctly");
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        // A8: validUntil/validAfter are packed into the return value (sigFailed bit must be 0).
        uint256 vd = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(vd & 1, 0, "sigFailed bit must be 0 for valid window");
        assertEq(uint48(vd >> 160), permission.validUntil, "validUntil packed correctly");
        assertEq(uint48(vd >> 208), permission.validAfter, "validAfter packed correctly");
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(ClankerGate4337.ChainIdMismatch.selector, permission.chainId, block.chainid));
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

        bytes memory guardData = abi.encode(proof, permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
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

// ============================================================
//              AUTHORIZED CALLER ENFORCEMENT TESTS (H-2)
// ============================================================

contract AuthorizedCallerTests4337 is ClankerGateTest {
    /// @notice H-2: A permission whose authorizedCaller does NOT match the account sender
    /// must revert UnauthorizedCallerForPermission.
    function test_authorizedCaller_enforced() public {
        address nonMatchingCaller = address(0xDEAD1234);

        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;
        permission.maxValue = 0;
        permission.authorizedCaller = nonMatchingCaller; // Does NOT match account sender

        // Compute leaf using the on-chain helper so authorizedCaller is baked in.
        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        // sender == address(account) != nonMatchingCaller → must revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGate4337.UnauthorizedCallerForPermission.selector,
                address(account),
                nonMatchingCaller
            )
        );
        gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
    }

    /// @notice H-2: A permission with authorizedCaller == address(0) must allow any sender
    /// (i.e., validation proceeds as normal).
    function test_authorizedCaller_zeroAllowsAny() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;
        permission.maxValue = 0;
        permission.authorizedCaller = address(0); // No restriction

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 result = gate.validateUserOp(_packUserOp(address(account), hex"12345678", guardData), userOpHash);
        assertEq(result, 0, "zero authorizedCaller must allow any sender");
    }
}

// ============================================================
//               POLICY ADMIN SEPARATION TESTS (H-4)
// ============================================================

contract PolicyAdminTests4337 is ClankerGateTest {
    /// @notice H-4: The session signer (owner()) must NOT be able to call setPolicyRoot.
    function test_sessionSignerCannotSetPolicyRoot() public {
        // owner is the signing key returned by account.owner(), NOT the account itself
        vm.prank(owner);
        vm.expectRevert(ClankerGate4337.UnauthorizedCaller.selector);
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
    }

    /// @notice The account itself (also the default policyAdmin when none is set) can set the root.
    function test_accountCanSetPolicyRoot() public {
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), bytes32(uint256(42)));
        assertEq(gate.policyRoots(address(account)), bytes32(uint256(42)));
    }

    /// @notice H-4: An explicit policyAdmin can set the root; an unrelated address cannot.
    function test_policyAdminCanSetPolicyRoot() public {
        address admin = address(0xAD4337);

        // Account sets an explicit policyAdmin
        vm.prank(address(account));
        gate.setPolicyAdmin(address(account), admin);
        assertEq(gate.policyAdmin(address(account)), admin);

        // policyAdmin can now set the root
        vm.prank(admin);
        gate.setPolicyRoot(address(account), bytes32(uint256(99)));
        assertEq(gate.policyRoots(address(account)), bytes32(uint256(99)));

        // An unrelated address still cannot
        address unrelated = address(0xDEAD);
        vm.prank(unrelated);
        vm.expectRevert(ClankerGate4337.UnauthorizedCaller.selector);
        gate.setPolicyRoot(address(account), bytes32(uint256(0)));
    }

    /// @notice H-4: Only the account itself may call setPolicyAdmin (not even the current admin).
    function test_onlyAccountCanSetPolicyAdmin() public {
        address admin = address(0xAD4338);

        // A random address cannot set policyAdmin
        vm.prank(owner);
        vm.expectRevert(ClankerGate4337.UnauthorizedCaller.selector);
        gate.setPolicyAdmin(address(account), admin);

        // Account itself can set policyAdmin
        vm.prank(address(account));
        gate.setPolicyAdmin(address(account), admin);
        assertEq(gate.policyAdmin(address(account)), admin);

        // Even the newly-set admin cannot further rotate policyAdmin (only account can)
        address admin2 = address(0xAD4339);
        vm.prank(admin);
        vm.expectRevert(ClankerGate4337.UnauthorizedCaller.selector);
        gate.setPolicyAdmin(address(account), admin2);

        // But the account still can
        vm.prank(address(account));
        gate.setPolicyAdmin(address(account), admin2);
        assertEq(gate.policyAdmin(address(account)), admin2);
    }
}

// ============================================================
//                    EIP-1271 OWNER TESTS (M-4)
// ============================================================

/// @notice Minimal EIP-1271 wallet that accepts exactly one known (hash, sig) pair.
contract EIP1271OwnerWallet {
    address public immutable signer;
    bytes4 constant MAGIC = 0x1626ba7e;

    constructor(address _signer) {
        signer = _signer;
    }

    /// @notice Recover the ECDSA signer and return magic value if it matches.
    function isValidSignature(bytes32 hash, bytes memory sig) external view returns (bytes4) {
        // Minimal ECDSA recovery without library dependency
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

/// @notice An account whose owner() returns the EIP-1271 wallet contract address.
contract EIP1271OwnerAccount is IAccount {
    address public owner; // The 1271 wallet contract

    constructor(address _wallet) {
        owner = _wallet;
    }

    function validateUserOp(bytes calldata, bytes32, uint256) external pure returns (uint256) {
        return 0;
    }
}

contract EIP1271OwnerTests is ClankerGateTest {
    /// @notice M-4: Account owner is a contract wallet (EIP-1271); gate must accept it.
    function test_eip1271Owner_4337() public {
        // Deploy a 1271 wallet that signs with ownerKey
        EIP1271OwnerWallet wallet = new EIP1271OwnerWallet(owner);

        // Deploy an account whose owner() returns the wallet (a contract)
        EIP1271OwnerAccount eip1271Account = new EIP1271OwnerAccount(address(wallet));

        // Set up a permission and compute its leaf
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(eip1271Account), permission, 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(eip1271Account));
        gate.setPolicyRoot(address(eip1271Account), leaf);

        // Sign the userOpHash with ownerKey — the 1271 wallet will recover this
        bytes32 userOpHash = keccak256("eip1271test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory guardData = abi.encode(proof, permission, signature);

        // The gate calls isValidSignature on the wallet (contract owner). Should pass.
        uint256 result = gate.validateUserOp(
            _packUserOp(address(eip1271Account), hex"12345678", guardData),
            userOpHash
        );
        assertEq(result, 0, "EIP-1271 contract owner should validate successfully");
    }
}
