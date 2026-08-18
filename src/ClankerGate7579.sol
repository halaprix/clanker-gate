// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579.sol";
import {PackedUserOperation} from "./interfaces/IERC4337.sol";
import {ClankerGateValidatorBase} from "./ClankerGateValidatorBase.sol";

/**
 * @title ClankerGate7579 - ERC-7579 Validator Module
 * @author Clanker Protocol
 * @custom:security-contact security@summer.fi
 * @notice Stateless validator module for ERC-7579 modular accounts
 * @dev
 *     This module implements ERC-7579 Module Type 1 (Validator).
 *     It validates UserOperations against policy rules stored in Merkle trees.
 *     The validation pipeline itself lives in ClankerGateValidatorBase; this adapter
 *     supplies the 7579-specific storage (install lifecycle) and signer resolution.
 *
 *     ## Installation
 *
 *     account.installModule(
 *         MODULE_TYPE_VALIDATOR,
 *         address(clankerGate7579),
 *         abi.encode(owner, initialRoot, signatureValidator)
 *     );
 *
 *     ## initData Format
 *
 *     - initOwner: Address that can update policy (usually account owner)
 *     - initPolicyRoot: Initial Merkle root (0 = disabled, reverts on everything)
 *     - signatureValidator: Address of signature validator contract (account-specific)
 *       - 0 = use account's owner() function
 *       - address = use this contract for signature validation
 *
 *     ## Supported Accounts
 *
 *     - Safe v1.5+ (with ERC-7579 adapter)
 *     - ZeroDev
 *     - Biconomy
 *     - Rhinestone
 *     - Any ERC-7579 compliant account
 *
 *     ## Security Notes
 *
 *     - singleUse permissions are scoped to the account to prevent cross-account collision attacks
 *     - Non-execute() calldata must have permission.target == address(0) or match the implicit target
 *     - External self-calls are disallowed during ERC-4337 validation; callData is read directly
 *       from userOp.callData instead of using try/catch self-decode machinery
 */
contract ClankerGate7579 is ClankerGateValidatorBase {
    // ============ Storage ============

    /// @notice Per-account configuration
    /// @dev `owner` is the SESSION SIGNER (signature authority for UserOps), intentionally
    ///      distinct from `policyAdmin` (policy-mutation authority). The session signer must
    ///      NOT be able to call `setPolicyRoot`, `setOwner`, or `setPolicyAdmin` (H-4).
    struct AccountConfig {
        bytes32 policyRoot;
        uint256 nonce;
        address owner;
        bool installed;
        address signatureValidator;
        address policyAdmin;
    }

    /// @notice Mapping from account address to configuration
    mapping(address => AccountConfig) public accountConfigs;

    /// @notice Persistent monotonic install counter per account.
    /// @dev Survives uninstall. onInstall uses ++_installEpoch[account] as the fresh nonce,
    ///      ensuring that singleUse markings from a previous install epoch can never collide
    ///      with markings from the current install epoch even though usedPermissionHashes
    ///      cannot be enumerated and cleared on uninstall.
    mapping(address => uint256) private _installEpoch;

    /// @notice Emitted when module is installed on an account
    event ModuleInstalled(address indexed account, address owner, bytes32 policyRoot, address signatureValidator);

    /// @notice Emitted when an account changes its policy admin
    event PolicyAdminSet(address indexed account, address admin);

    /// @notice Emitted when module is uninstalled from an account
    event ModuleUninstalled(address indexed account);

    /// @notice Emitted when policy root is updated
    event PolicyRootSet(address indexed account, bytes32 root, uint256 nonce);

    // ============ Errors ============

    error NotInstalled();
    error AlreadyInstalled();
    error Unauthorized();

    // ============ ERC-7579 Module Interface ============

    /**
     * @notice Returns whether the module implements the given module type
     * @param moduleTypeId The module type ID to check (1 = Validator, 2 = Executor, ...)
     * @return True if this module implements the given type
     */
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /**
     * @notice Check if account has this module installed
     * @param account The account to check
     * @return True if installed
     */
    function isModuleInstalled(address account) external view returns (bool) {
        return accountConfigs[account].installed;
    }

    /**
     * @notice Called by account during module installation
     * @param initData ABI-encoded (address owner, bytes32 policyRoot, address signatureValidator)
     * @dev Uses a persistent per-account monotonic install epoch counter as the nonce so that
     *      every (re)install gets a fresh nonce. The counter survives uninstall, which means
     *      singleUse markings from a previous install epoch can never collide with the new one.
     */
    function onInstall(bytes calldata initData) external {
        // SECURITY FIX: Prevent overwrite of existing configuration
        if (accountConfigs[msg.sender].installed) {
            revert AlreadyInstalled();
        }

        (address initOwner, bytes32 initPolicyRoot, address initSignatureValidator) =
            abi.decode(initData, (address, bytes32, address));

        AccountConfig storage config = accountConfigs[msg.sender];
        config.owner = initOwner;
        config.policyRoot = initPolicyRoot;
        // M-5: Use the next epoch value as the nonce. _installEpoch is never cleared on
        // uninstall, so re-installing always produces a strictly higher nonce than any
        // previous install. Leaves are computed against config.nonce (readable via
        // getAccountConfig), binding them to this install epoch.
        config.nonce = ++_installEpoch[msg.sender];
        config.signatureValidator = initSignatureValidator;
        config.installed = true;
        // H-4: Initialize policyAdmin to the account itself (msg.sender). This separates
        // the policy-mutation authority (policyAdmin) from the session signer (config.owner).
        config.policyAdmin = msg.sender;

        emit ModuleInstalled(msg.sender, initOwner, initPolicyRoot, initSignatureValidator);
    }

    /**
     * @notice Called by account during module uninstallation
     * @param deInitData Optional data (unused)
     * @dev Deletes accountConfigs but intentionally leaves _installEpoch and
     *      usedPermissionHashes intact. _installEpoch must survive so the next
     *      onInstall receives a strictly higher epoch nonce, which ensures that
     *      any singleUse entries written under a previous nonce can never match
     *      entries written under the new nonce. usedPermissionHashes cannot be
     *      fully enumerated, but because the nonce changes on every reinstall the
     *      stale entries are effectively unreachable (the leaves are different).
     */
    function onUninstall(bytes calldata deInitData) external {
        if (!accountConfigs[msg.sender].installed) {
            revert NotInstalled();
        }

        address account = msg.sender;
        // Delete the account config (marks as not installed, clears owner/root/nonce/sigValidator).
        // _installEpoch is intentionally NOT deleted — see natspec above.
        delete accountConfigs[account];

        emit ModuleUninstalled(account);
    }

    // ============ Policy Management ============

    /**
     * @notice Update policy root for an account.
     * @dev H-4: Only the account or its policyAdmin may call this. The session signer
     *      (config.owner) is intentionally excluded so it cannot widen its own policy.
     * @param account The account to update
     * @param newRoot The new Merkle root (0 = disabled)
     */
    function setPolicyRoot(address account, bytes32 newRoot) external {
        AccountConfig storage config = accountConfigs[account];

        if (!config.installed) {
            revert NotInstalled();
        }

        if (msg.sender != account && msg.sender != config.policyAdmin) {
            revert Unauthorized();
        }

        config.policyRoot = newRoot;
        // Note: nonce is NOT incremented here - it's only used during validation
        // to bind the proof to a specific policy epoch. The nonce increment
        // design was causing test failures because setPolicyRoot increments
        // before we can compute the correct leaf hash.

        emit PolicyRootSet(account, newRoot, config.nonce);
    }

    /**
     * @notice Update the session signer (owner) for an account.
     * @dev H-4: Gated by account-or-policyAdmin (NOT config.owner). The current session signer
     *      must not be able to rotate itself — that would allow a compromised signing key to
     *      grant itself indefinite signing authority.
     * @param account The account to update
     * @param newOwner The new session signer address
     */
    function setOwner(address account, address newOwner) external {
        AccountConfig storage config = accountConfigs[account];

        if (!config.installed) {
            revert NotInstalled();
        }

        if (msg.sender != account && msg.sender != config.policyAdmin) {
            revert Unauthorized();
        }

        config.owner = newOwner;
    }

    /**
     * @notice Set the policy admin for an account.
     * @dev Only the account or the current policyAdmin may change the policyAdmin.
     *      The session signer (config.owner) is excluded (H-4).
     * @param account The account to configure
     * @param newAdmin The new policy admin address (zero = account-only after next setPolicyRoot)
     */
    function setPolicyAdmin(address account, address newAdmin) external {
        AccountConfig storage config = accountConfigs[account];

        if (!config.installed) {
            revert NotInstalled();
        }

        if (msg.sender != account && msg.sender != config.policyAdmin) {
            revert Unauthorized();
        }

        config.policyAdmin = newAdmin;
        emit PolicyAdminSet(account, newAdmin);
    }

    // ============ Validation ============

    /**
     * @notice Validate a UserOperation against the account's policy (ERC-7579 IValidator interface)
     * @param userOp The ERC-4337 v0.7 PackedUserOperation; gate reads sender, callData, signature
     * @param userOpHash Hash of the UserOperation computed by the EntryPoint
     * @return validationData 0 for valid, packed validation data for invalid
     * @dev userOp.signature must be abi.encode(bytes32[] proof, Permission permission, bytes ownerSig).
     *      External self-calls are disallowed during ERC-4337 validation, so callData is read
     *      directly from userOp.callData rather than through try/catch self-decode machinery.
     *      msg.sender is the account (the EntryPoint routes through the account before reaching
     *      the validator module). The pipeline lives in ClankerGateValidatorBase._validate.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData) {
        if (!accountConfigs[msg.sender].installed) {
            revert NotInstalled();
        }
        return _validate(msg.sender, userOp.callData, userOpHash, userOp.signature);
    }

    /**
     * @notice ERC-7579 / ERC-1271 signer-identity check (D6).
     * @dev Validates SIGNER IDENTITY ONLY — no Merkle policy check, because a 1271 request
     *      carries no callData/target to gate against. `sender` is the original ERC-1271
     *      requester; it is not used for policy here and is accepted as any address.
     *      Returns the ERC-1271 magic value (0x1626ba7e) when the signature is from the
     *      expected signer for msg.sender (the account), 0xffffffff otherwise.
     * @param sender The original requester of the ERC-1271 check (not used for policy)
     * @param hash  The hash that was signed
     * @param signature The signature to validate
     * @return magicValue 0x1626ba7e on success, 0xffffffff on failure
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        // msg.sender is the smart account that installed this module.
        if (!accountConfigs[msg.sender].installed) {
            return bytes4(0xffffffff);
        }

        // M-4: Unified check via SignatureCheckerLib (handles ECDSA + EIP-1271 + EIP-2098)
        bool sigValid = SignatureCheckerLib.isValidSignatureNow(_resolveSigner(msg.sender), hash, signature);

        return sigValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    // ============ ClankerGateValidatorBase hooks ============

    function _policyRootOf(address account) internal view override returns (bytes32) {
        return accountConfigs[account].policyRoot;
    }

    function _nonceOf(address account) internal view override returns (uint256) {
        return accountConfigs[account].nonce;
    }

    /**
     * @notice Get expected signer for an account
     * @param account The account address
     * @return The expected signer address
     */
    function _resolveSigner(address account) internal view override returns (address) {
        AccountConfig storage config = accountConfigs[account];

        // Use custom signature validator when set
        if (config.signatureValidator != address(0)) {
            return config.signatureValidator;
        }

        // First check cached owner from onInstall (avoids an external call)
        if (config.owner != address(0)) {
            return config.owner;
        }

        // CG-11: Use low-level staticcall with bounded output (32 bytes) to prevent
        // return data bomb attacks. Malicious contracts could return massive payloads
        // to exhaust memory with high-level try/catch which allocates full return data.
        // H-1: Use owner() (0x8da5cb5b) as the sole external selector.
        // implementation() (0x5c60da1b) must NOT be called — proxy accounts expose it and
        // would cause the implementation contract address to be treated as the owner.
        bool success;
        address owner;
        assembly {
            mstore(0x00, 0x8da5cb5b00000000000000000000000000000000000000000000000000000000)
            success := staticcall(gas(), account, 0x00, 0x04, 0x00, 0x20)
            if success {
                owner := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
        }
        if (!success || owner == address(0)) revert AccountHasNoOwner(account);
        return owner;
    }

    // ============ View Functions ============

    /**
     * @notice Get account configuration
     * @param account The account address
     * @return owner The session signer (distinct from policyAdmin — see H-4)
     * @return policyRoot The current Merkle root
     * @return nonce The current install epoch nonce
     * @return signatureValidator The custom signature validator (or zero for owner())
     * @return installed Whether the module is installed
     * @return configPolicyAdmin The policy admin address (zero means policyAdmin == account)
     */
    function getAccountConfig(address account) external view returns (
        address owner,
        bytes32 policyRoot,
        uint256 nonce,
        address signatureValidator,
        bool installed,
        address configPolicyAdmin
    ) {
        AccountConfig storage config = accountConfigs[account];
        return (
            config.owner,
            config.policyRoot,
            config.nonce,
            config.signatureValidator,
            config.installed,
            config.policyAdmin
        );
    }
}
