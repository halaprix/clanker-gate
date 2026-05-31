// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint, IAccount} from "./interfaces/IERC4337.sol";
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
    using ECDSA for bytes32;

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

    /// @notice Emitted when an account sets or updates their policy root
    event PolicyRootSet(address indexed account, bytes32 root, uint256 nonce);

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

    /// @notice Sets the Merkle root for an account's policy tree
    /// @param account The account address to set the policy root for
    /// @param root The Merkle root of the permission tree (0 to disable)
    function setPolicyRoot(address account, bytes32 root) external {
        // CG-22: Limit gas to prevent griefing from malicious owner() implementations
        _assertCallerIsAccountOrOwner(account, 30000);
        policyRoots[account] = root;
        nonces[account]++;
        emit PolicyRootSet(account, root, nonces[account]);
    }

    /// @notice Sets the policy root by computing leaf from permission in THIS contract's context
    /// @dev This ensures address(this) in hashPermission matches during validation
    /// @param account The account address
    /// @param permission The permission to compute leaf from
    /// @param nonce The nonce to bind to (use nonces[account] before incrementing)
    function setPolicyRootWithPermission(address account, Permission memory permission, uint256 nonce) external {
        _assertCallerIsAccountOrOwner(account, 30000);
        bytes32 leaf = ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
        policyRoots[account] = leaf;
        nonces[account]++;
        emit PolicyRootSet(account, leaf, nonces[account]);
    }

    /// @notice Compute permission hash in this contract's context
    /// @param account The account to scope the permission to
    /// @param permission The permission to hash
    /// @param nonce The nonce to bind
    /// @return The computed leaf hash
    function computePermissionHash(address account, Permission memory permission, uint256 nonce) external view returns (bytes32) {
        return ClankerGateCore.hashPermissionWithAccount(account, permission, nonce);
    }

    /// @notice Validates a UserOperation against the account's policy
    /// @param userOp ABI-encoded UserOperation (sender, nonce, initCode, callData, gas limits, fees, paymasterAndData, signature)
    /// @param userOpHash Hash of the UserOperation
    /// @param guardData ABI-encoded (bytes32[] proof, Permission permission, bytes signature)
    /// @return validationData 0 for valid, packed validation data for invalid
    function validateUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        bytes calldata guardData
    ) external returns (uint256 validationData) {
        // Gas optimization: extract only sender and callData via assembly
        // instead of full abi.decode which allocates memory for all 11 fields
        address sender;
        bytes memory callData;
        assembly {
            // sender is at offset 0 in the ABI-encoded tuple
            sender := calldataload(userOp.offset)
            
            // callData is the 4th field (index 3). In ABI encoding:
            // offset 0: sender (address, 32 bytes padded)
            // offset 32: nonce (uint256)
            // offset 64: initCode offset (uint256 pointer)
            // offset 96: callData offset (uint256 pointer)
            // The callData offset points to: length(32) + data
            let cdOffset := calldataload(add(userOp.offset, 96))
            let cdLen := calldataload(add(userOp.offset, cdOffset))
            
            // Allocate memory for callData
            callData := mload(0x40)
            mstore(callData, cdLen)
            
            // Copy callData bytes from calldata to memory
            calldatacopy(add(callData, 32), add(userOp.offset, add(cdOffset, 32)), cdLen)
            
            // Update free memory pointer (round up cdLen to 32-byte boundary)
            let roundedLen := and(add(cdLen, 31), not(31))
            mstore(0x40, add(add(callData, 32), roundedLen))
        }
        bytes32 root = policyRoots[sender];
        
        if (root == bytes32(0)) {
            revert RootNotSet();
        }

        (bytes32[] memory proof, Permission memory permission, bytes memory sig) =
            abi.decode(guardData, (bytes32[], Permission, bytes));

        if (!ClankerGateCore.verifyMerkleProof(root, proof, permission, sender, nonces[sender])) {
            revert InvalidProof();
        }

        // Validate permission constraints
        (bool permissionValid, uint8 errorCode) = ClankerGateCore.validatePermission(permission);
        if (!permissionValid) {
            if (errorCode == 7) { // ERR_NOT_YET_VALID from Core
                revert PermissionNotYetValid(block.timestamp, permission.validAfter);
            } else if (errorCode == 8) { // ERR_EXPIRED from Core
                revert PermissionExpired(block.timestamp, permission.validUntil);
            } else {
                revert ChainIdMismatch(permission.chainId, block.chainid);
            }
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
                return _packValidationData(true, 0, 0);
            }
            // For rule violations, we could return more info but ERC-4337 expects packed data
            return _packValidationData(true, 0, 0);
        }

        // Validate signature
        address signer = userOpHash.recover(sig);
        address owner = _getOwner(sender);
        if (signer != owner) {
            revert UnauthorizedSigner(owner, signer);
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
        return 0;
    }

    /// @notice Assert caller is account or owner (with bounded gas to prevent griefing)
    /// @param account The account to check
    /// @param gasLimit Maximum gas to allow for owner() call
    function _assertCallerIsAccountOrOwner(address account, uint64 gasLimit) internal {
        if (msg.sender == account) return;
        // CG-22: Use low-level call with bounded gas to prevent owner() griefing
        // H-1: Use owner() (0x8da5cb5b) as the sole selector; do NOT call implementation().
        bool success;
        address owner;
        assembly {
            mstore(0x00, 0x8da5cb5b00000000000000000000000000000000000000000000000000000000)
            success := call(gasLimit, account, 0, 0x00, 0x04, 0x00, 0x20)
            if success {
                owner := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
        }
        if (!success || msg.sender != owner) revert UnauthorizedCaller();
    }

    /// @notice Gets the owner of an account
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
        return (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
    }

    /// @notice Computes permission hash for off-chain Merkle tree construction
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