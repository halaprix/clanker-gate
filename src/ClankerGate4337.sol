// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {PackedUserOperation, IEntryPoint, IAccount} from "./interfaces/IERC4337.sol";
import {ClankerGateCore, Permission, ParamRule, DOMAIN_SEPARATOR_TYPEHASH, ERR_INVALID_LENGTH, ERR_SELECTOR_MISMATCH, ERR_RULE_VIOLATION} from "./ClankerGateCore.sol";

/// @title ClankerGate4337 - ERC-4337 Validator Module
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice Stateful validator for ERC-4337 Smart Accounts using Merkle proof-based policies
/// @dev 
///     This contract validates UserOperations against policy rules stored in Merkle trees.
///     Each account sets a Merkle root representing their allowed permissions.
///     
///     ## Usage
///     
///     1. Account owner calls `setPolicyRoot(root)` with Merkle root of permissions
///     2. Executor submits UserOperation with proof and permission in guardData
///     3. Contract validates: proof, time window, chainId, target, calldata rules, signature
///     
///     ## guardData Format
///     
///     `abi.encode(proof, permission, signature)`
///     
///     ## Security Notes
///     
///     - singleUse permissions are scoped to the account to prevent cross-account collision attacks
///     - Non-execute() calldata must have permission.target == address(0) or match the implicit target
///     - This contract assumes accounts implement `owner()` per our IAccount interface
contract ClankerGate4337 {
    bytes32 private immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_SEPARATOR_TYPEHASH,
            keccak256("ClankerGate"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice Mapping from account address to their policy Merkle root
    mapping(address => bytes32) public policyRoots;

    /// @notice Mapping from account address to their nonce
    mapping(address => uint256) public nonces;

    /// @notice Mapping from (account, permissionHash) to used status (for singleUse permissions)
    /// @dev Uses nested mapping to prevent cross-account singleUse collision attacks
    mapping(address => mapping(bytes32 => bool)) public usedPermissionHashes;

    /// @notice Mapping from account to its designated policy admin.
    /// @dev Zero address means "no explicit admin": only the account itself may administer the policy.
    ///      This separates the policy-mutation authority (policyAdmin) from the session signer
    ///      (resolved via `owner()` / `_getOwner`). The session signer can NEVER call
    ///      `setPolicyRoot` or `setPolicyRootWithPermission`.
    mapping(address => address) public policyAdmin;

    /// @notice Emitted when an account sets or updates their policy root
    event PolicyRootSet(address indexed account, bytes32 root, uint256 nonce);

    /// @notice Emitted when an account changes its policy admin
    event PolicyAdminSet(address indexed account, address admin);

    /// @notice Emitted on successful validation
    event ValidationSucceeded(address indexed account, bytes32 permissionHash);

    // Error codes - using unique names to avoid shadowing
    uint8 constant ERR_ROOT_NOT_SET = 0;
    uint8 constant ERR_INVALID_PROOF_V = 1;
    uint8 constant ERR_UNAUTHORIZED_SIGNER_V = 2;
    uint8 constant ERR_TARGET_MISMATCH_V = 6;
    uint8 constant ERR_NOT_YET_VALID_V = 7;
    uint8 constant ERR_EXPIRED_V = 8;
    uint8 constant ERR_CHAIN_MISMATCH_V = 9;
    uint8 constant ERR_NO_OWNER_V = 10;

    // Named shift constants for _packValidationData (L-9)
    uint256 private constant VALID_UNTIL_SHIFT = 160;
    uint256 private constant VALID_AFTER_SHIFT  = 208;

    // Custom errors
    error RootNotSet();
    error InvalidProof();
    error UnauthorizedSigner(address expected, address actual);
    error TargetMismatch(address expected, address actual);
    error PermissionNotYetValid(uint256 currentTime, uint256 validAfter);
    error PermissionExpired(uint256 currentTime, uint256 validUntil);
    error ChainIdMismatch(uint256 expected, uint256 actual);
    error AccountHasNoOwner(address account);
    error DirectCallRequiresTargetZero(address target);
    error ValueExceedsPermission(uint256 value, uint256 maxValue);
    error UnauthorizedCaller();
    error UnauthorizedCallerForPermission(address actual, address expected);
    /// @dev Reverts when calldata structural checks fail (selector/length mismatch).
    error CallDataValidationFailed(uint8 errorCode);

    /// @notice Sets the Merkle root for an account's policy tree.
    /// @dev Only the account itself or its designated policyAdmin may call this.
    ///      The session signer (resolved via `owner()`) is intentionally NOT authorized here —
    ///      see `_assertPolicyAdmin` and `policyAdmin` for the separation of concerns (H-4).
    /// @param account The account address to set the policy root for
    /// @param root The Merkle root of the permission tree (0 to disable)
    function setPolicyRoot(address account, bytes32 root) external {
        _assertPolicyAdmin(account);
        policyRoots[account] = root;
        nonces[account]++;
        emit PolicyRootSet(account, root, nonces[account]);
    }

    /// @notice Sets the policy root by computing leaf from permission in THIS contract's context
    /// @dev This ensures address(this) in hashPermission matches during validation.
    ///      Only the account itself or its designated policyAdmin may call this (H-4).
    ///
    ///      L-3: The nonce parameter has been removed. The function now derives the nonce
    ///      internally as `nonces[account] + 1` (matching setPolicyRoot's post-increment),
    ///      so the stored root always validates without requiring callers to compute the
    ///      correct nonce value.
    ///
    ///      Nonce-epoch semantics:
    ///        - ERC-4337 (this contract) and Safe: nonce increments on EVERY setPolicyRoot /
    ///          setPolicyRootWithPermission call. Each leaf is therefore bound to a unique epoch.
    ///        - ERC-7579 (ClankerGate7579): assigns a fresh install-epoch nonce at install time
    ///          and does NOT increment per setPolicyRoot call. The 7579 validator's epoch is
    ///          controlled by reinstallation, not by per-call increments.
    /// @param account The account address
    /// @param permission The permission to compute leaf from
    function setPolicyRootWithPermission(address account, Permission memory permission) external {
        _assertPolicyAdmin(account);
        uint256 newNonce = nonces[account] + 1;
        bytes32 leaf = ClankerGateCore.hashPermissionWithAccount(account, permission, newNonce);
        policyRoots[account] = leaf;
        nonces[account] = newNonce;
        emit PolicyRootSet(account, leaf, newNonce);
    }

    /// @notice Sets the policy admin for an account.
    /// @dev Only the account itself may designate a policyAdmin. Once set, both the account
    ///      and the policyAdmin may call `setPolicyRoot`/`setPolicyRootWithPermission`, but
    ///      the session signer (owner()) can never do so (H-4).
    /// @param account The account to configure
    /// @param admin The new policy admin address (zero = reset to account-only)
    function setPolicyAdmin(address account, address admin) external {
        require(msg.sender == account, UnauthorizedCaller());
        policyAdmin[account] = admin;
        emit PolicyAdminSet(account, admin);
    }

    /// @notice Compute permission hash in this contract's context
    /// @param account The account to scope the permission to
    /// @param permission The permission to hash
    /// @param nonce The nonce to bind
    /// @return The computed leaf hash
    function computePermissionHash(address account, Permission memory permission, uint256 nonce) external view returns (bytes32) {
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
    }

    /// @notice Validates a UserOperation against the account's policy.
    /// @dev The userOp.signature field contains abi.encode(proof, permission, ownerSig).
    ///      The userOpHash is computed by the EntryPoint over the userOp (excluding the
    ///      signature field); this validator trusts that hash (M-1). The ownerSig
    ///      authenticates userOpHash and must be produced by the account's owner.
    /// @param userOp ERC-4337 v0.7 PackedUserOperation; gate reads sender, callData, signature
    /// @param userOpHash Hash of the UserOperation computed by the EntryPoint
    /// @return validationData 0 for valid, packed validation data for invalid
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData) {
        address sender = userOp.sender;
        bytes memory callData = userOp.callData;

        bytes32 root = policyRoots[sender];

        if (root == bytes32(0)) {
            revert RootNotSet();
        }

        (bytes32[] memory proof, Permission memory permission, bytes memory ownerSig) =
            abi.decode(userOp.signature, (bytes32[], Permission, bytes));

        if (!ClankerGateCore.verifyMerkleProof(root, proof, permission, sender, nonces[sender])) {
            revert InvalidProof();
        }


        // Validate permission constraints.
        // chainId mismatch (errorCode 9) is a structural breach → revert.
        // Time-window failures (7 = not-yet-valid, 8 = expired) are returned in packed validationData
        // so the EntryPoint can enforce the window (M-2, M-3).
        (bool permissionValid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        if (!permissionValid) {
            if (errorCode == 9) {
                revert ChainIdMismatch(permission.chainId, block.chainid);
            }
            // errorCode 7 or 8: let validAfter/validUntil propagate via packed return below
        }

        // H-2: Enforce permission.authorizedCaller (bound to the userOp sender).
        // Note: In the ERC-4337 EntryPoint flow there is no separate on-chain submitter identity
        // distinct from the account itself, so we bind to `sender` (the smart account). This is a
        // redundant-but-honest safety pin — it ensures the field is honoured rather than silently
        // ignored, while being honest that Safe's executor-binding semantics don't apply here.
        if (permission.authorizedCaller != address(0) && permission.authorizedCaller != sender) {
            revert UnauthorizedCallerForPermission(sender, permission.authorizedCaller);
        }

        // Decode execute() wrapper — supports both execute(address,uint256,bytes) and ERC-7579 single-call
        (, address actualTarget, uint256 innerOffset, uint256 innerLength, uint256 callValue) =
            ClankerGateCore.decodeAnyExecuteMemory(callData);

        // CG-10: Validate msg.value against permission.maxValue
        if (callValue > permission.maxValue) {
            revert ValueExceedsPermission(callValue, permission.maxValue);
        }

        // Validate target - for execute() wrapper, check target matches
        // For direct calls, we cannot extract target from calldata, so we skip this check
        // (permission.target must be address(0) to allow any target in direct calls)
        if (actualTarget != address(0) && actualTarget != permission.target) {
            revert TargetMismatch(permission.target, actualTarget);
        }

        // Validate calldata rules
        // CG-13 fix: use identity precompile (memory copy) instead of O(N) byte-by-byte loop
        bytes memory innerCallData;
        if (innerLength > 0) {
            innerCallData = new bytes(innerLength);
            bytes memory src;
            assembly {
                src := add(callData, 32)
                mstore(innerCallData, innerLength)
            }
            assembly {
                // identity precompile at 0x04 for efficient memory-to-memory copy
                pop(staticcall(gas(), 0x04, add(src, innerOffset), innerLength, add(innerCallData, 32), innerLength))
            }
        } else {
            innerCallData = callData;
        }

        (bool valid, uint8 valErrorCode, uint256 ruleIndex) =
            ClankerGateCore.validateCallDataMemoryExtended(innerCallData, permission);
        if (!valid) {
            if (valErrorCode == ERR_INVALID_LENGTH || valErrorCode == ERR_SELECTOR_MISMATCH) {
                // Structural/policy breach → revert (D4)
                revert CallDataValidationFailed(valErrorCode);
            }
            // Rule violations already revert inside the library; the library returns false only
            // for ERR_INVALID_LENGTH / ERR_SELECTOR_MISMATCH (the library reverts on rule violations).
            revert CallDataValidationFailed(valErrorCode);
        }

        // Validate signature — supports ECDSA (EOA) and EIP-1271 (contract owners) via SignatureCheckerLib (M-4).
        // Signature failure is returned as packed sigFailed bit; it does NOT revert (M-2).
        address expectedSigner = _getOwner(sender);
        bool sigFailed = !SignatureCheckerLib.isValidSignatureNow(expectedSigner, userOpHash, ownerSig);

        // A failed-signature op must not consume a singleUse permission (M-2).
        if (sigFailed) {
            return _packValidationData(true, permission.validUntil, permission.validAfter);
        }

        // Check singleUse permission - use account-scoped hash to prevent collision attacks
        bytes32 permissionHash = ClankerGateCore.hashPermissionWithAccount(sender, permission, nonces[sender]);
        if (permission.singleUse) {
            // CG-01: Prevent anyone from directly calling validateUserOp to front-run and mark singleUse.
            // Only sender (the account) can mark its own permissions as used.
            require(msg.sender == sender, UnauthorizedCaller());
            if (usedPermissionHashes[sender][permissionHash]) {
                revert ClankerGateCore.PermissionAlreadyUsed(permissionHash);
            }
            usedPermissionHashes[sender][permissionHash] = true;
        }

        emit ValidationSucceeded(sender, permissionHash);
        return _packValidationData(false, permission.validUntil, permission.validAfter);
    }

    /// @notice Asserts that msg.sender is authorized to administer the policy for `account`.
    /// @dev H-4: The policy admin is intentionally SEPARATE from the session signer (`owner()`).
    ///      - If no explicit policyAdmin has been set (zero), only the account itself may act.
    ///      - If a policyAdmin is set, both the account and that admin may act.
    ///      The session signer (resolved via `_getOwner` / `owner()`) is deliberately excluded
    ///      from this check so it cannot widen its own permissions.
    function _assertPolicyAdmin(address account) internal view {
        address admin = policyAdmin[account];
        if (admin == address(0)) {
            if (msg.sender != account) revert UnauthorizedCaller();
        } else if (msg.sender != account && msg.sender != admin) {
            revert UnauthorizedCaller();
        }
    }

    /// @notice Gets the owner of an account.
    /// @dev `owner()` resolves the SIGNING authority (session signer) for UserOp validation.
    ///      This is intentionally distinct from `policyAdmin`, which controls policy mutation
    ///      (H-4). Do NOT use this function for policy-admin authorization.
    /// @param account The account address
    /// @return owner The owner address
    function _getOwner(address account) internal view returns (address owner) {
        // CG-11: Use low-level staticcall with bounded output (32 bytes) to prevent
        // return data bomb attacks. Malicious contracts could return massive payloads
        // to exhaust memory with high-level try/catch which allocates full return data.
        // H-1: Use owner() (0x8da5cb5b) as the sole external selector.
        // implementation() (0x5c60da1b) must NOT be called — proxy accounts expose it and
        // would cause the implementation contract address to be treated as the owner.
        bool success;
        assembly {
            mstore(0x00, 0x8da5cb5b00000000000000000000000000000000000000000000000000000000)
            success := staticcall(gas(), account, 0x00, 0x04, 0x00, 0x20)
            if success {
                owner := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
        }
        if (!success || owner == address(0)) revert AccountHasNoOwner(account);
    }

    /// @notice Packs validation data according to ERC-4337 format
    /// @param sigFailed Whether signature validation failed
    /// @param validUntil Unix timestamp after which the validation is invalid (0 = no expiry)
    /// @param validAfter Unix timestamp after which the validation is valid (0 = immediately)
    /// @return Packed validation data
    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (uint256) {
        return (uint256(validUntil) << VALID_UNTIL_SHIFT) | (uint256(validAfter) << VALID_AFTER_SHIFT) | (sigFailed ? 1 : 0);
    }

    /// @notice Computes the unscoped permission hash for off-chain use.
    /// @dev Returns the intermediate hash BEFORE account/nonce scoping.
    ///      This is NOT a Merkle leaf — it is missing account and nonce binding.
    ///      Use the account-scoped `computePermissionHash(account, permission, nonce)`
    ///      overload to obtain the actual Merkle leaf.
    function computePermissionInnerHash(
        address target,
        bytes4 selector,
        ParamRule[] calldata rules,
        uint48 validAfter,
        uint48 validUntil,
        uint256 chainId,
        bool singleUse,
        uint256 maxValue
    ) external view returns (bytes32) {
        Permission memory permission;
        permission.target = target;
        permission.selector = selector;
        permission.rules = rules;
        permission.validAfter = validAfter;
        permission.validUntil = validUntil;
        permission.chainId = chainId;
        permission.singleUse = singleUse;
        permission.maxValue = maxValue;
        return ClankerGateCore.hashPermission(permission, DOMAIN_SEPARATOR);
    }

    /// @notice Computes permission hash scoped to an account
    /// @dev Use this for singleUse permission tracking
    function computePermissionHashWithAccount(
        address account,
        address target,
        bytes4 selector,
        ParamRule[] calldata rules,
        uint48 validAfter,
        uint48 validUntil,
        uint256 chainId,
        bool singleUse,
        uint256 maxValue
    ) external view returns (bytes32) {
        Permission memory permission;
        permission.target = target;
        permission.selector = selector;
        permission.rules = rules;
        permission.validAfter = validAfter;
        permission.validUntil = validUntil;
        permission.chainId = chainId;
        permission.singleUse = singleUse;
        permission.maxValue = maxValue;
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonces[account]);
    }
}