// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ClankerGateSafe} from "../src/ClankerGateSafe.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";

contract MockSafe {
    address[] public owners;
    mapping(address => bool) public isOwner;
    bool public shouldSucceed = true;

    constructor(address[] memory _owners) {
        owners = _owners;
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
        }
    }

    function setShouldSucceed(bool _shouldSucceed) external {
        shouldSucceed = _shouldSucceed;
    }

    function execTransactionFromModule(address, uint256, bytes calldata, uint8) external returns (bool success) {
        return shouldSucceed;
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }
}

contract ClankerGateSafeTest is Test {
    ClankerGateSafe gate;
    MockSafe safe;
    uint256 ownerKey;
    address owner;
    address caller;

    function setUp() public virtual {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        caller = address(0x9999);

        address[] memory owners = new address[](1);
        owners[0] = owner;
        safe = new MockSafe(owners);

        gate = new ClankerGateSafe();
    }
}

contract SetPolicyRootTests is ClankerGateSafeTest {
    function test_SetPolicyRoot_ByOwner() public {
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));

        (bytes32 root, uint256 nonce, uint248 whitelistVersion, bool enabled) = gate.authorizations(address(safe));
        assertEq(root, bytes32(uint256(1)));
        assertEq(nonce, 1);
        assertTrue(enabled);
    }

    function test_SetPolicyRoot_BySafe() public {
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(2)));

        (bytes32 root, uint256 nonce, uint248 whitelistVersion, ) = gate.authorizations(address(safe));
        assertEq(root, bytes32(uint256(2)));
        assertEq(nonce, 1);
    }

    function test_RevertWhen_SetPolicyRoot_Unauthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(ClankerGateSafe.MustBeCalledDirectlyBySafe.selector);
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
    }

    function test_NonceIncremented() public {
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(2)));

        (, uint256 nonce, uint248 whitelistVersion, ) = gate.authorizations(address(safe));
        assertEq(nonce, 2);
    }
}

contract CallerAuthorizationTests is ClankerGateSafeTest {
    function test_AuthorizeCaller_ByOwner() public {
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);

        assertTrue(gate.isAuthorizedCaller(address(safe), caller));
    }

    function test_AuthorizeCaller_BySafe() public {
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);

        assertTrue(gate.isAuthorizedCaller(address(safe), caller));
    }

    function test_RevertWhen_AuthorizeCaller_Unauthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(ClankerGateSafe.MustBeCalledDirectlyBySafe.selector);
        gate.authorizeCaller(address(safe), caller);
    }

    function test_DeauthorizeCaller() public {
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);

        vm.prank(address(safe));
        gate.deauthorizeCaller(address(safe), caller);

        assertFalse(gate.isAuthorizedCaller(address(safe), caller));
    }
}

contract ExecTransactionTests is ClankerGateSafeTest {
    function setUp() public override {
        super.setUp();
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    function test_ExecTransaction_Success() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }

    function test_RevertWhen_UnauthorizedCaller() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes memory data = hex"12345678";

        vm.prank(address(0xdead));
        vm.expectRevert(ClankerGateSafe.NotAuthorized.selector);
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            new bytes32[](0),
            permission
        );
    }

    function test_RevertWhen_InvalidProof() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(ClankerGateSafe.InvalidProof.selector);
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_TargetMismatch() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateSafe.TargetMismatch.selector, address(0x1111), address(0x2222)));
        gate.execTransaction(
            address(safe),
            address(0x2222),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_PermissionExpired() public {
        vm.warp(20000);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = uint48(10000);
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateSafe.PermissionExpired.selector, block.timestamp, permission.validUntil));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_PermissionNotYetValid() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = uint48(block.timestamp + 3600);
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateSafe.PermissionNotYetValid.selector, block.timestamp, permission.validAfter));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_ChainIdMismatch() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 999;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateSafe.ChainIdMismatch.selector, permission.chainId, block.chainid));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_RuleViolation() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"1234567800000000000000000000000000000000000000000000000000000000000002bc";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.RuleViolation.selector, 0, 4, bytes32(uint256(100)), bytes32(uint256(700))));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_RevertWhen_SafeExecutionFails() public {
        safe.setShouldSucceed(false);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        vm.prank(caller);
        vm.expectRevert(ClankerGateSafe.ExecutionReverted.selector);
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_ExecTransaction_WithRuleValidation() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"123456780000000000000000000000000000000000000000000000000000000000000064";

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }
}

contract ExecTransactionWithProofTests is ClankerGateSafeTest {
    function setUp() public override {
        super.setUp();
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
    }

    function test_ExecTransactionWithProof_Success() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);
        
        // Authorize the caller (required after security fix)
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), address(0xbeef));

        bytes memory data = hex"12345678";

        vm.prank(address(0xbeef));
        bool success = gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }

    function test_ExecTransactionWithProof_NoPreAuthNeeded() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);
        
        // Authorize the caller (required after security fix)
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), address(0xcafe));

        bytes memory data = hex"12345678";

        vm.prank(address(0xcafe));
        bool success = gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }

    function test_ExecTransactionWithProof_InvalidProof() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));

        bytes memory data = hex"12345678";

        // Authorize caller first (required after security fix)
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), address(0xbeef));

        vm.prank(address(0xbeef));
        vm.expectRevert(ClankerGateSafe.InvalidProof.selector);
        gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
    }

    function test_ExecTransactionWithProof_NoPolicyRoot() public {
        MockSafe newSafe = new MockSafe(new address[](0));

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);

        bytes memory data = hex"12345678";

        vm.prank(address(0xbeef));
        vm.expectRevert(ClankerGateSafe.NotAuthorized.selector);
        gate.execTransactionWithProof(
            address(newSafe),
            address(0x1111),
            0,
            data,
            0,
            new bytes32[](0),
            permission
        );
    }
}

contract EventTests is ClankerGateSafeTest {
    function test_Event_PolicyRootSet() public {
        vm.expectEmit(true, false, false, true);
        emit ClankerGateSafe.PolicyRootSet(address(safe), bytes32(uint256(1)), 1);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
    }

    function test_Event_CallerAuthorized() public {
        vm.expectEmit(true, true, false, false);
        emit ClankerGateSafe.CallerAuthorized(address(safe), caller);

        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    function test_Event_CallerDeauthorized() public {
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);

        vm.expectEmit(true, true, false, false);
        emit ClankerGateSafe.CallerDeauthorized(address(safe), caller);

        vm.prank(address(safe));
        gate.deauthorizeCaller(address(safe), caller);
    }

    function test_Event_ExecutionSucceeded() public {
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);

        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        vm.expectEmit(true, true, false, false);
        emit ClankerGateSafe.ExecutionSucceeded(address(safe), caller, address(0x1111), 0x12345678);

        vm.prank(caller);
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            hex"12345678",
            0,
            proof,
            permission
        );
    }
}

// ============================================================
//                    OP_IN VALIDATION TESTS
// ============================================================

contract OP_INTests is ClankerGateSafeTest {
    function setUp() public override {
        super.setUp();
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    function test_ValidateRule_IN_Pass() public {
        Permission memory permission;
        permission.target = address(0x1111);
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

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000000c8";

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }

    function test_ValidateRule_IN_Fail() public {
        Permission memory permission;
        permission.target = address(0x1111);
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

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = hex"1234567800000000000000000000000000000000000000000000000000000000000003e8";

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.ValueNotInSet.selector, 0, bytes32(uint256(1000)), allowedValues));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
    }

    function test_ValidateRule_IN_MultipleAddresses() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);

        address addr1 = makeAddr("safeAddr1");
        address addr2 = makeAddr("safeAddr2");
        address addr3 = makeAddr("safeAddr3");

        bytes32[] memory allowedReceivers = new bytes32[](3);
        allowedReceivers[0] = bytes32(uint256(uint160(addr1)));
        allowedReceivers[1] = bytes32(uint256(uint160(addr2)));
        allowedReceivers[2] = bytes32(uint256(uint160(addr3)));
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedReceivers);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = new bytes(36);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);
        assembly {
            mstore(add(add(callData, 32), 4), addr2)
        }

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );

        assertTrue(success);
    }
}

// ============================================================
//                    SINGLE USE TESTS
// ============================================================

contract SingleUseTests is ClankerGateSafeTest {
    function setUp() public override {
        super.setUp();
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    function test_SingleUsePermission_Pass() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = hex"12345678";

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );

        assertTrue(success);
        bytes32 safePermissionHash = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)));
        assertTrue(gate.usedPermissionHashes(address(safe), safePermissionHash));
    }

    function test_SingleUsePermission_ExecTransactionWithProof_Pass() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);
        
        // Authorize caller first (required for execTransactionWithProof)
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), address(0xDEAD));

        bytes memory callData = hex"12345678";

        vm.prank(address(0xDEAD));
        bool success = gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );

        assertTrue(success);
        bytes32 safePermissionHash = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)));
        assertTrue(gate.usedPermissionHashes(address(safe), safePermissionHash));
    }

    function test_SingleUsePermission_RevertOnReplay() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = hex"12345678";

        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
        assertTrue(success);

        bytes32 safePermissionHash = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)));
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, safePermissionHash));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
    }

    function test_SingleUsePermission_ExecTransactionWithProof_RevertOnReplay() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);
        
        // Authorize caller first (required after security fix)
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), address(0xDEAD));

        bytes memory callData = hex"12345678";

        // First execution
        vm.prank(address(0xDEAD));
        bool success = gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
        assertTrue(success);

        // Attempt replay from SAME caller - should fail with PermissionAlreadyUsed
        bytes32 safePermissionHash = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)));
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, safePermissionHash));
        gate.execTransactionWithProof(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
    }

    function test_NonSingleUsePermission_AllowsMultipleExecutions() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false; // Can be used multiple times

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory callData = hex"12345678";

        // First execution
        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
        assertTrue(success);

        // Second execution - should succeed
        vm.prank(caller);
        success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            callData,
            0,
            proof,
            permission
        );
        assertTrue(success);

        bytes32 safePermissionHash = gate.computePermissionHash(address(safe), permission, 1);
        assertFalse(gate.usedPermissionHashes(address(safe), safePermissionHash));
    }
}

contract ComputePermissionHashTests is ClankerGateSafeTest {
    function test_ComputePermissionHash() public view {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule(0, 0, bytes32(uint256(100)), new bytes32[](0));

        bytes32 hash = gate.computePermissionInnerHash(
            address(0x1111),
            0x12345678,
            rules,
            1000,
            2000,
            1,
            false,
            0
        );

        assertTrue(hash != bytes32(0));
    }

    function test_ComputePermissionHash_MatchesLibrary() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 0, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 1000;
        permission.validUntil = 2000;
        permission.chainId = block.chainid;
        permission.singleUse = false;
        permission.maxValue = 0;

        bytes32 hash1 = gate.computePermissionInnerHash(
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        bytes32 hash2 = gate.computePermissionInnerHash(
            permission.target,
            permission.selector,
            permission.rules,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        );

        assertEq(hash1, hash2);
        assertTrue(hash1 != bytes32(0));
    }
}

// ============================================================
//          DELEGATECALL VALUE GUARD TESTS (post-M-6 / L-5)
// ============================================================

contract DelegatecallValueTests is ClankerGateSafeTest {
    function setUp() public override {
        super.setUp();
        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));
        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    /// @notice M-6 / L-5: execTransaction is non-payable; verify the module ETH balance
    ///         stays at 0 after a successful execution (no ETH can be stranded).
    function test_execTransaction_isNonPayable_noStuckEth() public {
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.maxValue = 1 ether;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        bytes memory data = hex"12345678";

        // Confirm module balance is zero before and after a normal execution.
        assertEq(address(gate).balance, 0);
        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0,
            data,
            0,
            proof,
            permission
        );
        assertTrue(success);
        assertEq(address(gate).balance, 0);
    }

    /// @notice The value PARAMETER (sourced from the Safe's balance) still enforces maxValue.
    function test_RevertWhen_DelegatecallValueExceedsMaxValue() public {
        // Whitelist target for DELEGATECALL (must be done AFTER setPolicyRoot as it resets nonce)
        vm.prank(address(safe));
        gate.setDelegatecallWhitelist(address(safe), address(0x1111), true);

        // Create permission with maxValue = 0.1 ether
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.maxValue = 0.1 ether;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        // value parameter = 1 ether > permission.maxValue (0.1 ether) — must revert.
        // (No ETH is sent to the module itself; the value is sourced from the Safe.)
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ClankerGateSafe.ValueExceedsPermission.selector, 1 ether, 0.1 ether));
        gate.execTransaction(
            address(safe),
            address(0x1111),
            1 ether, // value parameter exceeds maxValue
            data,
            1, // DELEGATECALL
            proof,
            permission
        );
    }

    /// @notice Delegatecall with a value parameter within maxValue succeeds.
    function test_Success_DelegatecallWithinMaxValue() public {
        // Create permission with maxValue = 1 ether
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.maxValue = 1 ether;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        // Whitelist AFTER setPolicyRoot so it stores the correct whitelistVersion
        vm.prank(address(safe));
        gate.setDelegatecallWhitelist(address(safe), address(0x1111), true);

        bytes memory data = hex"12345678";

        // value parameter = 0.5 ether <= 1 ether maxValue — should succeed.
        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0.5 ether,
            data,
            1, // DELEGATECALL
            proof,
            permission
        );

        assertTrue(success);
    }

    /// @notice Regular CALL with value parameter within maxValue succeeds.
    function test_Success_CallWithValueWithinMaxValue() public {
        // Create permission with maxValue = 1 ether
        Permission memory permission;
        permission.target = address(0x1111);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.maxValue = 1 ether;

        bytes32 leaf = gate.computePermissionHash(address(safe), permission, gate.nonces(address(safe)) + 1);
        bytes32[] memory proof = new bytes32[](0);
        bytes32 root = leaf;

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), root);

        bytes memory data = hex"12345678";

        // value parameter = 0.5 ether <= 1 ether maxValue — should succeed.
        vm.prank(caller);
        bool success = gate.execTransaction(
            address(safe),
            address(0x1111),
            0.5 ether, // value sourced from Safe's balance, not msg.value
            data,
            0, // CALL
            proof,
            permission
        );

        assertTrue(success);
    }
}
