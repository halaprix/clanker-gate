// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {PackedUserOperation} from "./interfaces/IERC4337.sol";
import {ClankerGateCore, Permission} from "./ClankerGateCore.sol";
import {ClankerGateValidatorBase} from "./ClankerGateValidatorBase.sol";

/// @title ClankerGate4337 - ERC-4337 Validator Module
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice Stateful validator for ERC-4337 Smart Accounts using Merkle proof-based policies
/// @dev
///     This contract validates UserOperations against policy rules stored in Merkle trees.
///     Each account sets a Merkle root representing their allowed permissions.
///     The validation pipeline itself lives in ClankerGateValidatorBase; this adapter
///     supplies the 4337-specific storage, signer resolution, and singleUse guard.
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
contract ClankerGate4337 is ClankerGateValidatorBase {
    /// @notice Mapping from account address to their policy Merkle root
    mapping(address => bytes32) public policyRoots;

    /// @notice Mapping from account address to their nonce
    mapping(address => uint256) public nonces;

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

    // Custom errors
    error UnauthorizedCaller();

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

    /// @notice Validates a UserOperation against the account's policy.
    /// @dev The userOp.signature field contains abi.encode(proof, permission, ownerSig).
    ///      The userOpHash is computed by the EntryPoint over the userOp (excluding the
    ///      signature field); this validator trusts that hash (M-1). The ownerSig
    ///      authenticates userOpHash and must be produced by the account's owner.
    ///      The pipeline lives in ClankerGateValidatorBase._validate.
    /// @param userOp ERC-4337 v0.7 PackedUserOperation; gate reads sender, callData, signature
    /// @param userOpHash Hash of the UserOperation computed by the EntryPoint
    /// @return validationData 0 for valid, packed validation data for invalid
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData) {
        return _validate(userOp.sender, userOp.callData, userOpHash, userOp.signature);
    }

    // ============ ClankerGateValidatorBase hooks ============

    function _policyRootOf(address account) internal view override returns (bytes32) {
        return policyRoots[account];
    }

    function _nonceOf(address account) internal view override returns (uint256) {
        return nonces[account];
    }

    function _resolveSigner(address account) internal view override returns (address) {
        return _getOwner(account);
    }

    /// @dev CG-01: Prevent anyone from directly calling validateUserOp to front-run and mark
    ///      singleUse. Only sender (the account) can mark its own permissions as used.
    function _markUsed(address account, bytes32 permissionHash) internal override {
        require(msg.sender == account, UnauthorizedCaller());
        super._markUsed(account, permissionHash);
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
}
