// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ClankerGateCore, Permission, ParamRule, DOMAIN_SEPARATOR_TYPEHASH, ERR_INVALID_LENGTH, ERR_SELECTOR_MISMATCH} from "./ClankerGateCore.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";

/// @title ClankerGateSafe - Gnosis Safe Module
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice Safe Module that validates transactions through policy rules before execution
/// @dev 
///     This module enables Safe accounts to enforce granular transaction policies.
///     Unlike the ERC-4337 version, this module can execute transactions on behalf of the Safe.
///     
///     ## Key Differences from ERC-4337 Version
///     
///     1. **Execution**: Can execute transactions, not just validate
///     2. **Caller Authorization**: Validates that caller is authorized via Merkle proof
///     3. **Direct Integration**: Works with Safe's module system
///     
///     ## Usage
///     
///     1. Safe enables this module via `enableModule(moduleAddress)`
///     2. Owner sets policy root via `setPolicyRoot(root)`
///     3. Authorized callers invoke `execTransaction()` with proof
///     
///     ## Security Model
///     
///     - Only authorized callers (with valid proof) can execute transactions
///     - Each transaction must pass policy validation
///     - Owner can revoke access by updating policy root
///     - DELEGATECALL requires target to be whitelisted
interface ISafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bool success);
    function isOwner(address owner) external view returns (bool);
    function getOwners() external view returns (address[] memory);
}

/// @notice Caller authorization stored per Safe
struct CallerAuth {
    bytes32 policyRoot;
    uint256 nonce;
    uint248 whitelistVersion; // CG-20b: Version to invalidate old whitelist entries on rotation
    bool enabled;
}

contract ClankerGateSafe is ReentrancyGuardTransient {
    using ClankerGateCore for Permission;

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

    /// @notice Mapping from Safe address to caller authorizations
    mapping(address => CallerAuth) public authorizations;

    /// @notice Get the current nonce for a Safe
    /// @param safe The Safe address
    /// @return The current nonce
    function nonces(address safe) external view returns (uint256) {
        return authorizations[safe].nonce;
    }

    /// @notice Mapping from Safe => caller => authorized
    mapping(address => mapping(address => bool)) public isAuthorizedCaller;

    /// @notice Mapping from Safe => permissionHash => used (for singleUse permissions)
    /// @dev Uses nested mapping to prevent cross-account singleUse collision attacks
    mapping(address => mapping(bytes32 => bool)) public usedPermissionHashes;

    /// @notice Mapping from Safe => target => whitelist version (0 = not whitelisted)
    /// @dev CG-20b: Check against authorizations[safe].whitelistVersion - entries from old versions are invalid
    mapping(address => mapping(address => uint248)) public delegatecallWhitelistVersion;

    /// @notice Emitted when policy root is set
    event PolicyRootSet(address indexed safe, bytes32 root, uint256 nonce);

    /// @notice Emitted when caller is authorized
    event CallerAuthorized(address indexed safe, address indexed caller);

    /// @notice Emitted when caller is deauthorized
    event CallerDeauthorized(address indexed safe, address indexed caller);

    /// @notice Emitted on successful execution
    event ExecutionSucceeded(address indexed safe, address indexed caller, address target, bytes4 selector);

    /// @notice Emitted when delegatecall whitelist is updated
    event DelegatecallWhitelistUpdated(address indexed safe, address indexed target, bool allowed);

    // Error codes
    uint8 constant ERR_NOT_YET_VALID = 7;
    uint8 constant ERR_EXPIRED = 8;
    uint8 constant ERR_CHAIN_MISMATCH = 9;
    uint8 constant ERR_TARGET_MISMATCH = 6;
    uint8 constant ERR_RULE_VIOLATION = 5;
    uint8 constant ERR_UNAUTHORIZED = 10;
    uint8 constant ERR_DELEGATECALL_NOT_ALLOWED = 11;

    // Custom errors
    error NotAuthorized();
    error InvalidProof();
    error ExecutionReverted();
    error TargetMismatch(address expected, address actual);
    error PermissionNotYetValid(uint256 currentTime, uint256 validAfter);
    error PermissionExpired(uint256 currentTime, uint256 validUntil);
    error ChainIdMismatch(uint256 expected, uint256 actual);
    error DelegatecallNotAllowed(address target);
    error ValueExceedsPermission(uint256 value, uint256 maxValue);
    error MustBeCalledDirectlyBySafe();
    error UnauthorizedCallerForPermission(address caller, address expected);

    /// @notice Sets the policy root for a Safe (only callable by Safe or owner)
    /// @param safe The Safe address
    /// @param root The new policy root
    function setPolicyRoot(address safe, bytes32 root) external {
        require(msg.sender == safe, MustBeCalledDirectlyBySafe());
        
        authorizations[safe].policyRoot = root;
        authorizations[safe].nonce++;
        authorizations[safe].whitelistVersion++; // CG-20b: Invalidate old whitelist entries
        authorizations[safe].enabled = true;
        
        emit PolicyRootSet(safe, root, authorizations[safe].nonce);
    }

    /// @notice Compute permission hash in this contract's context
    /// @param account The account to scope the permission to
    /// @param permission The permission to hash
    /// @param nonce The nonce to bind
    /// @return The computed leaf hash
    function computePermissionHash(address account, Permission memory permission, uint256 nonce) external view returns (bytes32) {
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
    }

    /// @notice Authorizes a caller to execute transactions on behalf of Safe
    /// @param safe The Safe address
    /// @param caller The caller to authorize
    function authorizeCaller(address safe, address caller) external {
        require(msg.sender == safe, MustBeCalledDirectlyBySafe());
        
        isAuthorizedCaller[safe][caller] = true;
        emit CallerAuthorized(safe, caller);
    }

    /// @notice Removes caller authorization
    /// @param safe The Safe address
    /// @param caller The caller to deauthorize
    function deauthorizeCaller(address safe, address caller) external {
        require(msg.sender == safe, MustBeCalledDirectlyBySafe());
        
        isAuthorizedCaller[safe][caller] = false;
        emit CallerDeauthorized(safe, caller);
    }

    /// @notice Updates the delegatecall whitelist for a Safe
    /// @param safe The Safe address
    /// @param target The target address
    /// @param allowed Whether delegatecall is allowed
    function setDelegatecallWhitelist(address safe, address target, bool allowed) external {
        require(msg.sender == safe, MustBeCalledDirectlyBySafe());
        
        if (allowed) {
            // CG-20b: Store the current whitelist version - entry is valid as long as
            // its version matches the current whitelistVersion in CallerAuth
            delegatecallWhitelistVersion[safe][target] = authorizations[safe].whitelistVersion;
        } else {
            // Clear by setting to a version that will never match
            delegatecallWhitelistVersion[safe][target] = 0;
        }
        emit DelegatecallWhitelistUpdated(safe, target, allowed);
    }

    /// @notice Execute a transaction through the Safe with policy validation
    /// @param safe The Safe to execute from
    /// @param to Target contract
    /// @param value ETH value
    /// @param data Transaction calldata
    /// @param operation 0=CALL, 1=DELEGATECALL
    /// @param proof Merkle proof
    /// @param permission The permission authorizing this transaction
    /// @return success Whether execution succeeded
    function execTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32[] calldata proof,
        Permission calldata permission
    ) external payable nonReentrant returns (bool success) {
        // Check caller is authorized
        if (!isAuthorizedCaller[safe][msg.sender]) {
            revert NotAuthorized();
        }

        _validateAndExecute(safe, to, value, data, operation, proof, permission);
        return true;
    }

    /// @notice Execute a transaction without pre-authorized caller (uses proof each time)
    /// @dev This function now requires the caller to be explicitly authorized OR
    ///      the permission to include a caller field. For security, proof alone is NOT enough.
    /// @param safe The Safe to execute from
    /// @param to Target contract
    /// @param value ETH value
    /// @param data Transaction calldata
    /// @param operation 0=CALL, 1=DELEGATECALL
    /// @param proof Merkle proof
    /// @param permission The permission authorizing this transaction
    /// @return success Whether execution succeeded
    function execTransactionWithProof(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32[] calldata proof,
        Permission calldata permission
    ) external payable nonReentrant returns (bool success) {
        // SECURITY FIX: Caller must be authorized even with proof
        // Proof validates WHAT can be done, but caller must be authorized for WHO can do it
        if (!isAuthorizedCaller[safe][msg.sender]) {
            revert NotAuthorized();
        }

        _validateAndExecute(safe, to, value, data, operation, proof, permission);
        return true;
    }

    /// @notice Internal function to validate and execute a transaction
    function _validateAndExecute(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32[] calldata proof,
        Permission calldata permission
    ) internal {
        CallerAuth storage auth = authorizations[safe];

        // Check Safe has policy enabled
        bytes32 root = auth.policyRoot;
        if (root == bytes32(0) || !auth.enabled) {
            revert NotAuthorized();
        }

        // Verify Merkle proof
        if (!ClankerGateCore.verifyMerkleProof(root, proof, permission, safe, authorizations[safe].nonce)) {
            revert InvalidProof();
        }

        // CG-10: Validate value against permission.maxValue
        if (value > permission.maxValue) {
            revert ValueExceedsPermission(value, permission.maxValue);
        }

        // For DELEGATECALL (operation == 1), msg.value is preserved from the original call.
        // The `value` parameter may be 0 but actual msg.value could be non-zero.
        // Add an explicit guard to prevent double-spending of msg.value.
        if (operation == 1 && msg.value > permission.maxValue) {
            revert ValueExceedsPermission(msg.value, permission.maxValue);
        }

        // Validate permission constraints
        (bool permissionValid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        if (!permissionValid) {
            if (errorCode == ERR_NOT_YET_VALID) {
                revert PermissionNotYetValid(block.timestamp, permission.validAfter);
            } else if (errorCode == ERR_EXPIRED) {
                revert PermissionExpired(block.timestamp, permission.validUntil);
            } else {
                revert ChainIdMismatch(permission.chainId, block.chainid);
            }
        }

        // CG-02: Check caller is authorized for this permission
        if (permission.authorizedCaller != address(0) && permission.authorizedCaller != msg.sender) {
            revert UnauthorizedCallerForPermission(msg.sender, permission.authorizedCaller);
        }

        // Validate target
        if (to != permission.target) {
            revert TargetMismatch(permission.target, to);
        }

        // Check DELEGATECALL whitelist (CG-20b: versioned to invalidate on rotation)
        if (operation == 1) { // DELEGATECALL
            if (delegatecallWhitelistVersion[safe][to] != authorizations[safe].whitelistVersion) {
                revert DelegatecallNotAllowed(to);
            }
        }

        // Validate calldata rules
        (bool valid, uint8 valErrorCode, uint256 ruleIndex) = 
            ClankerGateCore.validateCallDataExtended(data, permission);
        if (!valid) {
            if (valErrorCode == ERR_INVALID_LENGTH || valErrorCode == ERR_SELECTOR_MISMATCH) {
                revert("Invalid calldata");
            }
            revert("Rule violation");
        }

        // Check singleUse permission - use account-scoped hash to prevent collision attacks
        bytes32 permissionHash = ClankerGateCore.hashPermissionWithAccount(safe, permission, authorizations[safe].nonce);
        if (permission.singleUse) {
            if (usedPermissionHashes[safe][permissionHash]) {
                revert ClankerGateCore.PermissionAlreadyUsed(permissionHash);
            }
            usedPermissionHashes[safe][permissionHash] = true;
        }

        // Execute through Safe
        bool success = ISafe(safe).execTransactionFromModule(to, value, data, operation);

        if (success) {
            bytes4 selector = data.length >= 4 ? bytes4(data[0:4]) : bytes4(0);
            emit ExecutionSucceeded(safe, msg.sender, to, selector);
        } else {
            revert ExecutionReverted();
        }
    }

    /// @notice Compute permission hash
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

    /// @notice Compute permission hash scoped to a Safe
    function computePermissionHashWithAccount(
        address safe,
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
        return ClankerGateCore.hashPermissionWithAccount(safe, permission, authorizations[safe].nonce);
    }
}