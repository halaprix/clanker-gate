// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {ClankerGateSafe} from "../src/ClankerGateSafe.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";
import {IEntryPoint, IAccount} from "../src/interfaces/IERC4337.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "../src/interfaces/IERC7579.sol";

// ============================================================
//                         HELPERS
// ============================================================

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

contract Mock4337Account is IAccount {
    uint256 public ownerKey;
    address public _owner;

    constructor(uint256 _ownerKey, address __owner) {
        ownerKey = _ownerKey;
        _owner = __owner;
    }

    function owner() external view override returns (address) {
        return _owner;
    }

    function validateUserOp(bytes calldata, bytes32, uint256) external pure returns (uint256) {
        return 0;
    }
}

contract Mock7579Account is IERC7579Account {
    uint256 public ownerKey;
    address public owner_;
    mapping(uint256 => mapping(address => bool)) private _installedModules;

    constructor(uint256 _ownerKey, address __owner) {
        ownerKey = _ownerKey;
        owner_ = __owner;
    }

    function owner() external view override returns (address) {
        return owner_;
    }

    function setOwnerKey(uint256 _ownerKey, address __owner) external {
        ownerKey = _ownerKey;
        owner_ = __owner;
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external override {
        _installedModules[moduleTypeId][module] = true;
        ClankerGate7579(module).onInstall(initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata) external override {
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

/// @notice Contract that calls validateUserOp with a specific msg.value
contract CallerWithValue {
    function callValidateUserOp4337(
        address gate,
        bytes calldata userOp,
        bytes32 userOpHash,
        bytes calldata guardData
    ) external payable returns (uint256) {
        return ClankerGate4337(gate).validateUserOp(userOp, userOpHash, guardData);
    }

    function callValidateUserOp7579(
        address gate,
        bytes calldata userOp,
        bytes32 userOpHash,
        bytes calldata guardData
    ) external payable returns (uint256) {
        return ClankerGate7579(gate).validateUserOp(userOp, userOpHash, guardData);
    }
}

// ============================================================
//                   CG-10 VALUE VALIDATION TESTS
// ============================================================

contract CG10_Safe_ValueValidation is Test {
    using ECDSA for bytes32;

    ClankerGateSafe gate;
    MockSafe safe;
    uint256 ownerKey;
    address owner;
    address caller;

    function setUp() public {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        caller = address(0x9999);

        address[] memory owners = new address[](1);
        owners[0] = owner;
        safe = new MockSafe(owners);

        gate = new ClankerGateSafe();

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), bytes32(uint256(1)));

        vm.prank(address(safe));
        gate.authorizeCaller(address(safe), caller);
    }

    function _buildPermission(address target, bytes4 selector, uint256 maxValue)
        internal
        pure
        returns (Permission memory)
    {
        Permission memory p;
        p.target = target;
        p.selector = selector;
        p.rules = new ParamRule[](0);
        p.validAfter = 0;
        p.validUntil = 0;
        p.chainId = 0;
        p.singleUse = false;
        p.maxValue = maxValue;
        return p;
    }

    /// @notice CG-10: maxValue=1e18, value=1e18 -> OK
    function testCG10_Safe_ValueEqualToMax_Pass() public {
        Permission memory permission = _buildPermission(address(0x1234), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        vm.prank(caller);
        gate.execTransaction({
            safe: address(safe),
            to: address(0x1234),
            value: 1e18,
            data: hex"12345678",
            operation: 0,
            proof: proof,
            permission: permission
        });
    }

    /// @notice CG-10: maxValue=1e18, value=2e18 -> FAIL
    function testCG10_Safe_ValueExceedsMax_Reverts() public {
        Permission memory permission = _buildPermission(address(0x1234), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateSafe.ValueExceedsPermission.selector,
            2e18,
            1e18
        ));
        vm.prank(caller);
        gate.execTransaction({
            safe: address(safe),
            to: address(0x1234),
            value: 2e18,
            data: hex"12345678",
            operation: 0,
            proof: proof,
            permission: permission
        });
    }

    /// @notice CG-10: maxValue=0, value=1 -> FAIL (no ETH transfer allowed)
    function testCG10_Safe_MaxValueZero_AnyValueReverts() public {
        Permission memory permission = _buildPermission(address(0x1234), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateSafe.ValueExceedsPermission.selector,
            1,
            0
        ));
        vm.prank(caller);
        gate.execTransaction({
            safe: address(safe),
            to: address(0x1234),
            value: 1,
            data: hex"12345678",
            operation: 0,
            proof: proof,
            permission: permission
        });
    }

    /// @notice CG-10: maxValue=0, value=0 -> OK (no ETH sent is allowed)
    function testCG10_Safe_MaxValueZero_ZeroValuePasses() public {
        Permission memory permission = _buildPermission(address(0x1234), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(safe));
        gate.setPolicyRoot(address(safe), leaf);

        vm.prank(caller);
        gate.execTransaction({
            safe: address(safe),
            to: address(0x1234),
            value: 0,
            data: hex"12345678",
            operation: 0,
            proof: proof,
            permission: permission
        });
    }
}

// ============================================================
//              CG-10 4337 VALIDATOR VALUE TESTS
// ============================================================

contract CG10_4337_ValueValidation is Test {
    using ECDSA for bytes32;

    ClankerGate4337 gate;
    Mock4337Account account;
    uint256 ownerKey;
    address owner;
    CallerWithValue callerContract;

    function setUp() public {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        gate = new ClankerGate4337();
        account = new Mock4337Account(ownerKey, owner);
        callerContract = new CallerWithValue();
    }

    function _encodeUserOp(address sender, bytes memory callData) internal pure returns (bytes memory) {
        return abi.encode(
            sender,     // address sender
            uint256(0),  // uint256 nonce
            hex"",       // bytes initCode
            callData,    // bytes callData
            uint256(0),  // uint256 callGasLimit
            uint256(0),  // uint256 verificationGasLimit
            uint256(0),  // uint256 preVerificationGas
            uint256(0),  // uint256 maxFeePerGas
            uint256(0),  // uint256 maxPriorityFeePerGas
            hex"",       // bytes paymasterAndData
            hex""        // bytes signature
        );
    }

    function _buildPermission(address target, bytes4 selector, uint256 maxValue)
        internal
        pure
        returns (Permission memory)
    {
        Permission memory p;
        p.target = target;
        p.selector = selector;
        p.rules = new ParamRule[](0);
        p.validAfter = 0;
        p.validUntil = 0;
        p.chainId = 0;
        p.singleUse = false;
        p.maxValue = maxValue;
        return p;
    }

    function _signUserOp(bytes32 userOpHash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        return abi.encode(r, s, v);
    }

    /// @notice CG-10: maxValue=1e18, msg.value=1e18 -> OK
    function testCG10_4337_ValueEqualToMax_Pass() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        // Call with msg.value = 1e18 (equal to maxValue)
        uint256 result = callerContract.callValidateUserOp4337{value: 1e18}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
        assertEq(result, 0);
    }

    /// @notice CG-10: maxValue=1e18, msg.value=2e18 -> FAIL
    function testCG10_4337_ValueExceedsMax_Reverts() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        // Call with msg.value = 2e18 (exceeds maxValue = 1e18)
        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.ValueExceedsPermission.selector,
            2e18,
            1e18
        ));
        callerContract.callValidateUserOp4337{value: 2e18}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
    }

    /// @notice CG-10: maxValue=0, msg.value=1 -> FAIL (no ETH allowed)
    function testCG10_4337_MaxValueZero_AnyValueReverts() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        // Call with msg.value = 1 (maxValue = 0 -> no ETH allowed)
        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate4337.ValueExceedsPermission.selector,
            1,
            0
        ));
        callerContract.callValidateUserOp4337{value: 1}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
    }

    /// @notice CG-10: maxValue=0, msg.value=0 -> OK
    function testCG10_4337_MaxValueZero_ZeroValuePasses() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        uint256 result = callerContract.callValidateUserOp4337{value: 0}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
        assertEq(result, 0);
    }
}

// ============================================================
//              CG-10 7579 VALIDATOR VALUE TESTS
// ============================================================

contract CG10_7579_ValueValidation is Test {
    using ECDSA for bytes32;

    ClankerGate7579 gate;
    Mock7579Account account;
    uint256 ownerKey;
    address owner;
    CallerWithValue callerContract;

    function setUp() public {
        ownerKey = 0x1234;
        owner = vm.addr(ownerKey);
        gate = new ClankerGate7579();
        account = new Mock7579Account(ownerKey, owner);
        callerContract = new CallerWithValue();

        // Install module on account
        bytes memory initData = abi.encode(account.owner(), bytes32(uint256(1)), address(0));
        account.installModule(MODULE_TYPE_VALIDATOR, address(gate), initData);
    }

    function _encodeUserOp(address sender, bytes memory callData) internal pure returns (bytes memory) {
        return abi.encode(
            sender,     // address sender
            uint256(0),  // uint256 nonce
            hex"",       // bytes initCode
            callData,   // bytes callData
            uint256(0), // uint256 callGasLimit
            uint256(0), // uint256 verificationGasLimit
            uint256(0), // uint256 preVerificationGas
            uint256(0), // uint256 maxFeePerGas
            uint256(0), // uint256 maxPriorityFeePerGas
            hex""        // bytes paymasterAndData
        );
    }

    function _buildPermission(address target, bytes4 selector, uint256 maxValue)
        internal
        pure
        returns (Permission memory)
    {
        Permission memory p;
        p.target = target;
        p.selector = selector;
        p.rules = new ParamRule[](0);
        p.validAfter = 0;
        p.validUntil = 0;
        p.chainId = 0;
        p.singleUse = false;
        p.maxValue = maxValue;
        return p;
    }

    function _signUserOp(bytes32 userOpHash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        return abi.encode(r, s, v);
    }

    /// @notice CG-10: maxValue=1e18, msg.value=1e18 -> OK
    function testCG10_7579_ValueEqualToMax_Pass() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        uint256 result = callerContract.callValidateUserOp7579{value: 1e18}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
        assertEq(result, 0);
    }

    /// @notice CG-10: maxValue=1e18, msg.value=2e18 -> FAIL
    function testCG10_7579_ValueExceedsMax_Reverts() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 1e18);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate7579.ValueExceedsPermission.selector,
            2e18,
            1e18
        ));
        callerContract.callValidateUserOp7579{value: 2e18}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
    }

    /// @notice CG-10: maxValue=0, msg.value=1 -> FAIL (no ETH allowed)
    function testCG10_7579_MaxValueZero_AnyValueReverts() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGate7579.ValueExceedsPermission.selector,
            1,
            0
        ));
        callerContract.callValidateUserOp7579{value: 1}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
    }

    /// @notice CG-10: maxValue=0, msg.value=0 -> OK
    function testCG10_7579_MaxValueZero_ZeroValuePasses() public {
        Permission memory permission = _buildPermission(address(0), 0x12345678, 0);

        bytes32 leaf = ClankerGateCore.hashPermission(permission);
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory signature = _signUserOp(userOpHash);

        bytes memory guardData = abi.encode(proof, permission, signature);
        bytes memory userOpBytes = _encodeUserOp(address(account), hex"12345678");

        uint256 result = callerContract.callValidateUserOp7579{value: 0}(
            address(gate),
            userOpBytes,
            userOpHash,
            guardData
        );
        assertEq(result, 0);
    }
}
