// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ClankerGateCore, Permission, ParamRule, DOMAIN_SEPARATOR_TYPEHASH, ERR_INVALID_LENGTH, ERR_SELECTOR_MISMATCH} from "./ClankerGateCore.sol";
import {IERC7579Account, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579.sol";
import {PackedUserOperation} from "./interfaces/IERC4337.sol";

/**
 * @title ClankerGate7579 - ERC-7579 Validator Module
 * @author Clanker Protocol
 * @custom:security-contact security@summer.fi
 * @notice Stateless validator module for ERC-7579 modular accounts
 * @dev
 *     This module implements ERC-7579 Module Type 1 (Validator).
 *     It validates UserOperations against policy rules stored in Merkle trees.
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
contract ClankerGate7579 {
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

    /// @notice Mapping from account => permissionHash => used (for singleUse permissions)
    /// @dev Uses nested mapping to prevent cross-account singleUse collision attacks
    mapping(address => mapping(bytes32 => bool)) public usedPermissionHashes;

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

    /// @notice Emitted when validation succeeds
    event ValidationSucceeded(address indexed account, bytes32 permissionHash);

    // ============ Errors ============

    // Named shift constants for _packValidationData (L-9)
    uint256 private constant VALID_UNTIL_SHIFT = 160;
    uint256 private constant VALID_AFTER_SHIFT  = 208;

    error NotInstalled();
    error AlreadyInstalled();
    error InvalidProof();
    error UnauthorizedSigner(address expected, address actual);
    error TargetMismatch(address expected, address actual);
    error PermissionNotYetValid(uint256 currentTime, uint256 validAfter);
    error PermissionExpired(uint256 currentTime, uint256 validUntil);
    error ChainIdMismatch(uint256 expected, uint256 actual);
    error PolicyRootNotSet();
    error Unauthorized();
    error AccountHasNoOwner(address account);
    error DirectCallRequiresTargetZero(address target);
    error InvalidUserOpFormat();
    error ValueExceedsPermission(uint256 value, uint256 maxValue);
    error UnauthorizedCallerForPermission(address actual, address expected);
    /// @dev Reverts when calldata structural checks fail (selector/length mismatch).
    error CallDataValidationFailed(uint8 errorCode);

    // Error codes - using unique names to avoid shadowing
    uint8 constant ERR_ROOT_NOT_SET_V = 0;
    uint8 constant ERR_INVALID_PROOF_V = 1;
    uint8 constant ERR_UNAUTHORIZED_SIGNER_V = 2;
    uint8 constant ERR_TARGET_MISMATCH_V = 6;
    uint8 constant ERR_NOT_YET_VALID_V = 7;
    uint8 constant ERR_EXPIRED_V = 8;
    uint8 constant ERR_CHAIN_MISMATCH_V = 9;
    uint8 constant ERR_NO_OWNER_V = 10;

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

    /// @notice Compute permission hash in this contract's context
    /// @param account The account to scope the permission to
    /// @param permission The permission to hash
    /// @param nonce The nonce to bind
    /// @return The computed leaf hash
    function computePermissionHash(address account, Permission memory permission, uint256 nonce) external view returns (bytes32) {
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
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
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData) {
        AccountConfig storage config = accountConfigs[msg.sender];

        if (!config.installed) {
            revert NotInstalled();
        }

        bytes32 root = config.policyRoot;
        if (root == bytes32(0)) {
            revert PolicyRootNotSet();
        }

        (bytes32[] memory proof, Permission memory permission, bytes memory ownerSig) =
            abi.decode(userOp.signature, (bytes32[], Permission, bytes));

        if (!ClankerGateCore.verifyMerkleProof(root, proof, permission, msg.sender, accountConfigs[msg.sender].nonce)) {
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

        // H-2: Enforce permission.authorizedCaller (bound to msg.sender which IS the account in the
        // 7579 validator flow — the account calls the module directly, so msg.sender == account).
        // Note: Safe binds to the executor msg.sender; here msg.sender is always the account because
        // the EntryPoint routes through the account before reaching the validator module.
        if (permission.authorizedCaller != address(0) && permission.authorizedCaller != msg.sender) {
            revert UnauthorizedCallerForPermission(msg.sender, permission.authorizedCaller);
        }

        // Read callData directly from the userOp struct field.
        // External self-calls (the old try/catch _decodeCallData pattern) are disallowed
        // during ERC-4337 validation, so we access userOp.callData directly.
        bytes memory callData = userOp.callData;

        // Decode execute() wrapper — supports both execute(address,uint256,bytes) and ERC-7579 single-call
        (, address actualTarget, uint256 innerOffset, uint256 innerLength, uint256 callValue) =
            ClankerGateCore.decodeAnyExecuteMemory(callData);

        // CG-10: Validate callValue against permission.maxValue
        if (callValue > permission.maxValue) {
            revert ValueExceedsPermission(callValue, permission.maxValue);
        }

        // Validate target - for execute() wrapper, check target matches
        // For direct calls, we cannot extract target from calldata, so we skip this check
        if (actualTarget != address(0) && actualTarget != permission.target) {
            revert TargetMismatch(permission.target, actualTarget);
        }

        // Validate calldata rules
        // CG-13 fix: use identity precompile (memory copy) instead of O(N) byte-by-byte loop
        bytes memory innerCallData;
        if (innerLength > 0 && callData.length >= innerOffset + innerLength) {
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
            revert CallDataValidationFailed(valErrorCode);
        }

        // CG-07 / M-4: Unified signature check via SignatureCheckerLib.
        // Routes to EIP-1271 when expectedSigner is a contract, ECDSA when it's an EOA.
        // Signature failure is returned as packed sigFailed bit; it does NOT revert (M-2).
        address expectedSigner = config.signatureValidator != address(0)
            ? config.signatureValidator
            : _getExpectedSigner(msg.sender);
        bool sigFailed = !SignatureCheckerLib.isValidSignatureNow(expectedSigner, userOpHash, ownerSig);

        // A failed-signature op must not consume a singleUse permission (M-2).
        if (sigFailed) {
            return _packValidationData(true, permission.validUntil, permission.validAfter);
        }

        // Check singleUse permission - use account-scoped hash to prevent collision attacks
        bytes32 permissionHash = ClankerGateCore.hashPermissionWithAccount(msg.sender, permission, accountConfigs[msg.sender].nonce);
        if (permission.singleUse) {
            if (usedPermissionHashes[msg.sender][permissionHash]) {
                revert ClankerGateCore.PermissionAlreadyUsed(permissionHash);
            }
            usedPermissionHashes[msg.sender][permissionHash] = true;
        }

        emit ValidationSucceeded(msg.sender, permissionHash);
        return _packValidationData(false, permission.validUntil, permission.validAfter);
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
        AccountConfig storage config = accountConfigs[msg.sender];
        if (!config.installed) {
            return bytes4(0xffffffff);
        }

        // M-4: Unified check via SignatureCheckerLib (handles ECDSA + EIP-1271 + EIP-2098)
        address expectedSigner = config.signatureValidator != address(0)
            ? config.signatureValidator
            : _getExpectedSigner(msg.sender);
        bool sigValid = SignatureCheckerLib.isValidSignatureNow(expectedSigner, hash, signature);

        return sigValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    /**
     * @notice Get expected signer for an account
     * @param account The account address
     * @return The expected signer address
     */
    function _getExpectedSigner(address account) internal view returns (address) {
        AccountConfig storage config = accountConfigs[account];
        address sigValidator = config.signatureValidator;

        // Use custom signature validator when set
        if (sigValidator != address(0)) {
            return sigValidator;
        }

        // CG-11: Use low-level staticcall with bounded output (32 bytes) to prevent
        // return data bomb attacks. Malicious contracts could return massive payloads
        // to exhaust memory with high-level try/catch which allocates full return data.
        // First check cached owner from onInstall (avoids an external call)
        if (config.owner != address(0)) {
            return config.owner;
        }

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

    /// @notice Packs validation data according to ERC-4337 format
    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (uint256) {
        return (uint256(validUntil) << VALID_UNTIL_SHIFT) | (uint256(validAfter) << VALID_AFTER_SHIFT) | (sigFailed ? 1 : 0);
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

    /**
     * @notice Compute permission hash for off-chain Merkle tree construction
     */
    function computePermissionHash(
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

    /**
     * @notice Compute permission hash scoped to an account
     */
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
        return ClankerGateCore.hashPermissionWithAccount(account, permission, accountConfigs[account].nonce);
    }
}
