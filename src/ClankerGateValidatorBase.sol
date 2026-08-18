// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ClankerGateCore, Permission, ParamRule, DOMAIN_SEPARATOR_TYPEHASH} from "./ClankerGateCore.sol";

/// @title ClankerGateHashing - Shared permission-hashing surface
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice Domain separator, singleUse registry, and the off-chain hash helpers
///         shared by every ClankerGate contract (4337, 7579, Safe).
abstract contract ClankerGateHashing {
    bytes32 internal immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_SEPARATOR_TYPEHASH,
            keccak256("ClankerGate"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice Mapping from account => permissionHash => used (for singleUse permissions)
    /// @dev Uses nested mapping to prevent cross-account singleUse collision attacks
    mapping(address => mapping(bytes32 => bool)) public usedPermissionHashes;

    /// @notice Returns the current policy/install epoch nonce for an account.
    function _nonceOf(address account) internal view virtual returns (uint256);

    /// @notice Marks a singleUse permission as used, reverting if already used.
    function _markUsed(address account, bytes32 permissionHash) internal virtual {
        if (usedPermissionHashes[account][permissionHash]) {
            revert ClankerGateCore.PermissionAlreadyUsed(permissionHash);
        }
        usedPermissionHashes[account][permissionHash] = true;
    }

    /// @notice Compute permission hash in this contract's context
    /// @param account The account to scope the permission to
    /// @param permission The permission to hash
    /// @param nonce The nonce to bind
    /// @return The computed leaf hash
    function computePermissionHash(address account, Permission memory permission, uint256 nonce) external view returns (bytes32) {
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
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

    /// @notice Compute permission hash scoped to an account
    /// @dev Uses the account's current nonce. Use this for singleUse permission tracking.
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
        return ClankerGateCore.hashPermissionWithAccount(account, permission, _nonceOf(account));
    }
}

/// @title ClankerGateValidatorBase - Shared UserOp validation pipeline
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice The single implementation of the policy validation pipeline shared by the
///         ERC-4337 and ERC-7579 validators. Adapters supply storage access and signer
///         resolution through three hooks; every security-relevant check lives here, once.
/// @dev Check ordering is load-bearing and mirrors the previously duplicated
///      per-adapter pipelines exactly:
///      root → proof → permission window/chain → authorizedCaller → decode+extract →
///      maxValue → target rule → calldata rules → signature → singleUse.
abstract contract ClankerGateValidatorBase is ClankerGateHashing {
    /// @notice Emitted on successful validation
    event ValidationSucceeded(address indexed account, bytes32 permissionHash);

    // Named shift constants for _packValidationData (L-9)
    uint256 private constant VALID_UNTIL_SHIFT = 160;
    uint256 private constant VALID_AFTER_SHIFT  = 208;

    // Pipeline errors — one selector namespace for every adapter (integrators decode one set)
    error PolicyRootNotSet();
    error InvalidProof();
    error ChainIdMismatch(uint256 expected, uint256 actual);
    error UnauthorizedCallerForPermission(address actual, address expected);
    error ValueExceedsPermission(uint256 value, uint256 maxValue);
    error DirectCallRequiresTargetZero(address target);
    error TargetMismatch(address expected, address actual);
    error AccountHasNoOwner(address account);
    /// @dev Reverts when calldata structural checks fail (selector/length mismatch).
    error CallDataValidationFailed(uint8 errorCode);

    /// @notice Returns the account's current policy Merkle root (zero = not set).
    function _policyRootOf(address account) internal view virtual returns (bytes32);

    /// @notice Resolves the session signer whose signature authenticates userOpHash.
    function _resolveSigner(address account) internal view virtual returns (address);

    /// @notice Validates a UserOperation's payload against the account's policy.
    /// @dev `signature` is abi.encode(bytes32[] proof, Permission permission, bytes ownerSig).
    ///      chainId mismatch is a structural breach → revert. Time-window failures
    ///      (not-yet-valid / expired) are returned in packed validationData so the
    ///      EntryPoint can enforce the window (M-2, M-3). Signature failure is returned
    ///      as the packed sigFailed bit and must not consume a singleUse permission (M-2).
    /// @param account The account whose policy gates this operation
    /// @param callData The UserOperation callData to validate
    /// @param userOpHash Hash of the UserOperation computed by the EntryPoint
    /// @param signature The UserOperation signature blob
    /// @return validationData 0 for valid, packed validation data otherwise
    function _validate(
        address account,
        bytes memory callData,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal returns (uint256 validationData) {
        bytes32 root = _policyRootOf(account);
        if (root == bytes32(0)) {
            revert PolicyRootNotSet();
        }
        uint256 nonce = _nonceOf(account);

        (bytes32[] memory proof, Permission memory permission, bytes memory ownerSig) =
            abi.decode(signature, (bytes32[], Permission, bytes));

        if (!ClankerGateCore.verifyMerkleProof(root, proof, permission, account, nonce)) {
            revert InvalidProof();
        }

        // Validate permission constraints.
        // chainId mismatch (errorCode 9) is a structural breach → revert.
        // Time-window failures (7 = not-yet-valid, 8 = expired) are returned in packed
        // validationData so the EntryPoint can enforce the window (M-2, M-3).
        (bool permissionValid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        if (!permissionValid && errorCode == 9) {
            revert ChainIdMismatch(permission.chainId, block.chainid);
        }

        // H-2: Enforce permission.authorizedCaller. In both the 4337 and 7579 flows the
        // only on-chain identity to bind is the account itself (there is no separate
        // executor identity as in Safe) — a redundant-but-honest safety pin that ensures
        // the field is honoured rather than silently ignored.
        if (permission.authorizedCaller != address(0) && permission.authorizedCaller != account) {
            revert UnauthorizedCallerForPermission(account, permission.authorizedCaller);
        }

        // Decode execute() wrapper — supports both execute(address,uint256,bytes) and ERC-7579
        // single-call — and extract the inner calldata (CG-13: the slice lives in Core).
        (ClankerGateCore.ExecKind execKind, address actualTarget, uint256 callValue, bytes memory innerCallData) =
            ClankerGateCore.decodeAndExtractInner(callData);

        // CG-10: Validate the call value against permission.maxValue
        if (callValue > permission.maxValue) {
            revert ValueExceedsPermission(callValue, permission.maxValue);
        }

        // A direct call executes against the account itself. It must be explicitly
        // authorized with target == address(0); otherwise a selector collision on
        // the account could reuse a permission intended for an external protocol.
        if (execKind == ClankerGateCore.ExecKind.Direct && permission.target != address(0)) {
            revert DirectCallRequiresTargetZero(permission.target);
        }

        // Wrapped calls always have an explicit target, including address(0).
        if (execKind != ClankerGateCore.ExecKind.Direct && actualTarget != permission.target) {
            revert TargetMismatch(permission.target, actualTarget);
        }

        // Validate calldata rules. Rule violations revert inside the library; it returns
        // false only for structural failures (invalid length / selector mismatch), which
        // are policy breaches → revert (D4).
        (bool valid, uint8 valErrorCode, ) =
            ClankerGateCore.validateCallDataMemoryExtended(innerCallData, permission);
        if (!valid) {
            revert CallDataValidationFailed(valErrorCode);
        }

        // Validate signature — supports ECDSA (EOA) and EIP-1271 (contract owners) via
        // SignatureCheckerLib (M-4, CG-07). Signature failure is returned as the packed
        // sigFailed bit; it does NOT revert (M-2).
        bool sigFailed = !SignatureCheckerLib.isValidSignatureNow(_resolveSigner(account), userOpHash, ownerSig);

        // A failed-signature op must not consume a singleUse permission (M-2).
        if (sigFailed) {
            return _packValidationData(true, permission.validUntil, permission.validAfter);
        }

        // Check singleUse permission - use account-scoped hash to prevent collision attacks
        bytes32 permissionHash = ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
        if (permission.singleUse) {
            _markUsed(account, permissionHash);
        }

        emit ValidationSucceeded(account, permissionHash);
        return _packValidationData(false, permission.validUntil, permission.validAfter);
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
}
