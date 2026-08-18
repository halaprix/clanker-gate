// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ClankerGateValidatorBase} from "../src/ClankerGateValidatorBase.sol";
import {Test} from "forge-std/Test.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";
import {ClankerGateCore, Permission, ParamRule} from "../src/ClankerGateCore.sol";
import {PackedUserOperation, IAccount} from "../src/interfaces/IERC4337.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "../src/interfaces/IERC7579.sol";

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

// A fake "router" target and inner function selector
address constant ROUTER    = address(0x00000000000000000000000000000000DeaDBeef);
address constant OTHER     = address(0x0000000000000000000000000000000000000001);
bytes4  constant INNER_SEL = bytes4(keccak256("swap(uint256)"));

// ---------------------------------------------------------------------------
// Minimal mock account for the 4337 gate (needs owner())
// ---------------------------------------------------------------------------

contract MockAccount4337 is IAccount {
    address public owner;
    constructor(address o) { owner = o; }
    function validateUserOp(bytes calldata, bytes32, uint256) external pure returns (uint256) { return 0; }
}

// ---------------------------------------------------------------------------
// Minimal mock account for the 7579 gate (needs owner() + callValidate)
// ---------------------------------------------------------------------------

contract MockAccount7579 is IERC7579Account {
    address private _owner;
    mapping(uint256 => mapping(address => bool)) private _installed;

    constructor(address owner_) { _owner = owner_; }

    function owner() external view override returns (address) { return _owner; }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external override {
        _installed[moduleTypeId][module] = true;
        ClankerGate7579(module).onInstall(initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata) external override {
        _installed[moduleTypeId][module] = false;
        ClankerGate7579(module).onUninstall("");
    }

    function isModuleInstalled(uint256 moduleTypeId, address module) external view override returns (bool) {
        return _installed[moduleTypeId][module];
    }

    /// Relays validateUserOp to the module so msg.sender == address(this) == account
    function callValidate(
        address module,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        return ClankerGate7579(module).validateUserOp(userOp, userOpHash);
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by both suites
// ---------------------------------------------------------------------------

contract WrappedExecuteIntegrationBase is Test {
    /// Build execute(address,uint256,bytes) wrapper — ERC-4337 style
    function _wrap4337(address target, uint256 value, bytes memory inner)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", target, value, inner);
    }

    /// Build ERC-7579 execute(bytes32,bytes) for single+default mode (mode == bytes32(0))
    function _wrap7579Single(address target, uint256 value, bytes memory inner)
        internal pure returns (bytes memory)
    {
        bytes32 mode = bytes32(0); // callType=0x00 (single), execType=0x00 (default)
        bytes memory execData = abi.encodePacked(target, uint256(value), inner);
        return abi.encodeWithSignature("execute(bytes32,bytes)", mode, execData);
    }

    /// Build ERC-7579 execute with batch callType (0x01) — must be rejected
    function _wrap7579Batch() internal pure returns (bytes memory) {
        bytes32 mode = bytes32(bytes1(0x01)); // callType = batch
        bytes memory execData = new bytes(52); // minimal length (won't be reached)
        return abi.encodeWithSignature("execute(bytes32,bytes)", mode, execData);
    }

    /// Build a minimal PackedUserOperation (gate only reads sender/callData/signature)
    function _packUserOp(address sender, bytes memory callData, bytes memory sig)
        internal pure returns (PackedUserOperation memory u)
    {
        u.sender = sender;
        u.callData = callData;
        u.signature = sig;
    }

    /// Build inner calldata for INNER_SEL(amount)
    function _inner(uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(INNER_SEL, amount);
    }
}

// ===========================================================================
//  ClankerGate4337 — wrapped-execute integration tests
// ===========================================================================

contract WrappedExecuteIntegration4337 is WrappedExecuteIntegrationBase {
    ClankerGate4337 gate;
    MockAccount4337 account;
    uint256 ownerKey = 0xA11CE;
    address owner;

    /// Shared permission: INNER_SEL on ROUTER, arg0 <= 1 ether, maxValue 1 ether
    Permission perm;
    bytes32[] emptyProof;
    bytes32 userOpHash;

    function setUp() public {
        gate    = new ClankerGate4337();
        owner   = vm.addr(ownerKey);
        account = new MockAccount4337(owner);

        emptyProof = new bytes32[](0);
        userOpHash = keccak256("wrappedIntegration");

        // Build permission
        perm.target   = ROUTER;
        perm.selector = INNER_SEL;
        perm.maxValue = 1 ether;
        perm.rules    = new ParamRule[](1);
        perm.rules[0] = ParamRule({
            offset: 0,
            op: 4, // OP_LTE
            value: bytes32(uint256(1 ether)),
            values: new bytes32[](0)
        });

        // The nonce-to-use in the leaf is nonces[account] + 1 = 1 (first setPolicyRoot call)
        bytes32 leaf = gate.computePermissionHash(address(account), perm, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);
    }

    /// Build guardData (empty proof, permission, owner-signed userOpHash)
    function _guardData() internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        return abi.encode(emptyProof, perm, sig);
    }

    // -----------------------------------------------------------------------
    // 1. execute(address,uint256,bytes) wrapper — compliant → passes
    // -----------------------------------------------------------------------

    /// @notice test_4337_executeAddrWrapper_compliantPasses
    /// callData = execute(ROUTER, 0, inner(0.5 ether)) — inner arg <= limit, value == 0 <= maxValue
    /// Expects validateUserOp to return 0 (valid).
    function test_4337_executeAddrWrapper_compliantPasses() public {
        bytes memory callData = _wrap4337(ROUTER, 0, _inner(0.5 ether));
        uint256 result = gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
        assertEq(result, 0, "compliant wrapped call must return 0 (valid)");
    }

    // -----------------------------------------------------------------------
    // 2. execute wrapper — inner arg violates rule → RuleViolation revert
    // -----------------------------------------------------------------------

    /// @notice test_4337_executeAddrWrapper_ruleViolationReverts
    /// inner arg = 2 ether > 1 ether limit → must revert with RuleViolation
    function test_4337_executeAddrWrapper_ruleViolationReverts() public {
        bytes memory callData = _wrap4337(ROUTER, 0, _inner(2 ether));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector,
                uint256(0),       // ruleIndex
                uint8(4),         // OP_LTE
                bytes32(uint256(1 ether)),
                bytes32(uint256(2 ether))
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    // -----------------------------------------------------------------------
    // 3. execute wrapper — value > maxValue → ValueExceedsPermission
    // -----------------------------------------------------------------------

    /// @notice test_4337_executeAddrWrapper_valueExceedsReverts
    /// execute(ROUTER, 2 ether, inner(0.5 ether)) with maxValue=1 ether → must revert
    function test_4337_executeAddrWrapper_valueExceedsReverts() public {
        bytes memory callData = _wrap4337(ROUTER, 2 ether, _inner(0.5 ether));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.ValueExceedsPermission.selector,
                uint256(2 ether),
                uint256(1 ether)
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    // -----------------------------------------------------------------------
    // 4. execute wrapper — wrong target → TargetMismatch
    // -----------------------------------------------------------------------

    /// @notice test_4337_executeAddrWrapper_wrongTargetReverts
    /// execute(OTHER, 0, inner) — target != permission.target (ROUTER) → TargetMismatch
    function test_4337_executeAddrWrapper_wrongTargetReverts() public {
        bytes memory callData = _wrap4337(OTHER, 0, _inner(0.5 ether));
        // TargetMismatch(expected=permission.target=ROUTER, actual=OTHER)
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.TargetMismatch.selector,
                ROUTER,
                OTHER
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    function test_4337_directCallCannotReuseExternalTargetPermission() public {
        bytes memory callData = _inner(0.5 ether);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.DirectCallRequiresTargetZero.selector,
                ROUTER
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    function test_4337_zeroTargetWrapperStillEnforcesValue() public {
        perm.target = address(0);
        bytes32 leaf = gate.computePermissionHash(address(account), perm, 2);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes memory callData = _wrap4337(address(0), 2 ether, _inner(0.5 ether));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.ValueExceedsPermission.selector,
                uint256(2 ether),
                uint256(1 ether)
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    // -----------------------------------------------------------------------
    // 5. ERC-7579 single mode — compliant → passes
    // -----------------------------------------------------------------------

    /// @notice test_4337_erc7579Wrapper_compliantPasses
    /// callData = execute(bytes32(0), abi.encodePacked(ROUTER, 0, inner(0.5 ether)))
    /// ERC-7579 single+default mode; inner target/value/rule enforced on inner call.
    function test_4337_erc7579Wrapper_compliantPasses() public {
        bytes memory callData = _wrap7579Single(ROUTER, 0, _inner(0.5 ether));
        uint256 result = gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
        assertEq(result, 0, "7579 single-mode compliant call must return 0 (valid)");
    }

    // -----------------------------------------------------------------------
    // 6. ERC-7579 single mode — value > maxValue → ValueExceedsPermission
    //    and wrong target → TargetMismatch (each sub-case in its own test)
    // -----------------------------------------------------------------------

    /// @notice test_4337_erc7579Wrapper_valueAndTargetEnforced (value branch)
    /// 7579 mode with value > maxValue → ValueExceedsPermission
    function test_4337_erc7579Wrapper_valueExceeds() public {
        bytes memory callData = _wrap7579Single(ROUTER, 2 ether, _inner(0.5 ether));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.ValueExceedsPermission.selector,
                uint256(2 ether),
                uint256(1 ether)
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    /// @notice test_4337_erc7579Wrapper_wrongTargetReverts
    /// 7579 mode with wrong target → TargetMismatch
    function test_4337_erc7579Wrapper_wrongTargetReverts() public {
        bytes memory callData = _wrap7579Single(OTHER, 0, _inner(0.5 ether));
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.TargetMismatch.selector,
                ROUTER,
                OTHER
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }

    // -----------------------------------------------------------------------
    // 7. ERC-7579 batch mode → UnsupportedCallType
    // -----------------------------------------------------------------------

    /// @notice test_4337_erc7579Batch_rejected
    /// 7579 mode with callType 0x01 (batch) → must revert UnsupportedCallType
    function test_4337_erc7579Batch_rejected() public {
        bytes memory callData = _wrap7579Batch();
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedCallType.selector, bytes1(0x01))
        );
        gate.validateUserOp(
            _packUserOp(address(account), callData, _guardData()),
            userOpHash
        );
    }
}

// ===========================================================================
//  ClankerGate7579 — wrapped-execute integration tests
// ===========================================================================

contract WrappedExecuteIntegration7579 is WrappedExecuteIntegrationBase {
    ClankerGate7579 gate;
    MockAccount7579 account;
    uint256 ownerKey = 0xBEEF7579;
    address owner;

    Permission perm;
    bytes32[] emptyProof;
    bytes32 userOpHash;
    uint256 installNonce; // config.nonce after onInstall

    function setUp() public {
        gate    = new ClankerGate7579();
        owner   = vm.addr(ownerKey);
        account = new MockAccount7579(owner);
        emptyProof = new bytes32[](0);
        userOpHash = keccak256("7579wrappedIntegration");

        // Install module: initOwner=owner, initPolicyRoot=0, signatureValidator=0
        vm.prank(address(account));
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(gate),
            abi.encode(owner, bytes32(0), address(0))
        );

        // Fetch the install-epoch nonce — this is the nonce used in leaf hashing
        (,, uint256 n,,,) = gate.getAccountConfig(address(account));
        installNonce = n; // should be 1

        // Build permission
        perm.target   = ROUTER;
        perm.selector = INNER_SEL;
        perm.maxValue = 1 ether;
        perm.rules    = new ParamRule[](1);
        perm.rules[0] = ParamRule({
            offset: 0,
            op: 4, // OP_LTE
            value: bytes32(uint256(1 ether)),
            values: new bytes32[](0)
        });

        // Single-leaf root: hash scoped to account + installNonce
        bytes32 leaf = gate.computePermissionHash(address(account), perm, installNonce);
        // Set root as the account (also the policyAdmin by default)
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);
    }

    /// Build guardData for 7579 gate (same encoding)
    function _guardData() internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        return abi.encode(emptyProof, perm, sig);
    }

    // -----------------------------------------------------------------------
    // 8. Mirror: execute(address,uint256,bytes) wrapper — compliant → passes
    // -----------------------------------------------------------------------

    /// @notice test_7579_executeAddrWrapper_compliantPasses
    /// Mirrors test_4337_executeAddrWrapper_compliantPasses for the 7579 gate.
    /// validateUserOp is called via callValidate so msg.sender == account.
    function test_7579_executeAddrWrapper_compliantPasses() public {
        bytes memory callData = _wrap4337(ROUTER, 0, _inner(0.5 ether));
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0, "7579: compliant wrapped call must return 0 (valid)");
    }

    // -----------------------------------------------------------------------
    // 9. Mirror: ERC-7579 single mode — compliant → passes
    // -----------------------------------------------------------------------

    /// @notice test_7579_erc7579Wrapper_compliantPasses
    /// 7579 single+default mode; target/value/rule enforced on the inner call.
    function test_7579_erc7579Wrapper_compliantPasses() public {
        bytes memory callData = _wrap7579Single(ROUTER, 0, _inner(0.5 ether));
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        uint256 result = account.callValidate(address(gate), userOp, userOpHash);
        assertEq(result, 0, "7579: 7579-single compliant call must return 0 (valid)");
    }

    // -----------------------------------------------------------------------
    // 10. Mirror: 7579 batch mode → UnsupportedCallType
    // -----------------------------------------------------------------------

    /// @notice test_7579_erc7579Batch_rejected
    /// 7579 mode with callType 0x01 (batch) → must revert UnsupportedCallType.
    function test_7579_erc7579Batch_rejected() public {
        bytes memory callData = _wrap7579Batch();
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.UnsupportedCallType.selector, bytes1(0x01))
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }

    // -----------------------------------------------------------------------
    // 11. 7579 gate: value > maxValue → ValueExceedsPermission
    // -----------------------------------------------------------------------

    /// @notice test_7579_executeAddrWrapper_valueExceedsReverts
    function test_7579_executeAddrWrapper_valueExceedsReverts() public {
        bytes memory callData = _wrap4337(ROUTER, 2 ether, _inner(0.5 ether));
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.ValueExceedsPermission.selector,
                uint256(2 ether),
                uint256(1 ether)
            )
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }

    // -----------------------------------------------------------------------
    // 12. 7579 gate: wrong target → TargetMismatch
    // -----------------------------------------------------------------------

    /// @notice test_7579_executeAddrWrapper_wrongTargetReverts
    function test_7579_executeAddrWrapper_wrongTargetReverts() public {
        bytes memory callData = _wrap4337(OTHER, 0, _inner(0.5 ether));
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        // TargetMismatch(expected=permission.target=ROUTER, actual=OTHER)
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.TargetMismatch.selector,
                ROUTER,
                OTHER
            )
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }

    function test_7579_directCallCannotReuseExternalTargetPermission() public {
        PackedUserOperation memory userOp =
            _packUserOp(address(account), _inner(0.5 ether), _guardData());

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateValidatorBase.DirectCallRequiresTargetZero.selector,
                ROUTER
            )
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }

    // -----------------------------------------------------------------------
    // 13. 7579 gate: inner rule violation → RuleViolation
    // -----------------------------------------------------------------------

    /// @notice test_7579_executeAddrWrapper_ruleViolationReverts
    function test_7579_executeAddrWrapper_ruleViolationReverts() public {
        bytes memory callData = _wrap4337(ROUTER, 0, _inner(2 ether));
        PackedUserOperation memory userOp = _packUserOp(address(account), callData, _guardData());
        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector,
                uint256(0),
                uint8(4),
                bytes32(uint256(1 ether)),
                bytes32(uint256(2 ether))
            )
        );
        account.callValidate(address(gate), userOp, userOpHash);
    }
}
