// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

// Comparison operators for parameter validation
uint8 constant OP_EQ = 0;
uint8 constant OP_GT = 1;
uint8 constant OP_LT = 2;
uint8 constant OP_GTE = 3;
uint8 constant OP_LTE = 4;
uint8 constant OP_IN = 5;
uint8 constant OP_SGT = 6;
uint8 constant OP_SLT = 7;

// Maximum number of rules per permission (gas griefing protection)
uint8 constant MAX_RULES = 10;

// Maximum number of values in OP_IN rule (gas griefing protection)
uint256 constant MAX_IN_VALUES = 20;

// Domain separator typehash for EIP-712
bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

// Error codes for validateCallDataExtended
uint8 constant ERR_INVALID_LENGTH = 1;
uint8 constant ERR_SELECTOR_MISMATCH = 2;
uint8 constant ERR_RULE_VIOLATION = 3;

// Error codes for validateCallDataExtended
struct ParamRule {
    uint256 offset;
    uint8 op;
    bytes32 value;
    bytes32[] values;
}

/// @notice Defines permissions for calling a specific function on a target contract
struct Permission {
    address target;
    bytes4 selector;
    ParamRule[] rules;
    uint48 validAfter;
    uint48 validUntil;
    uint256 chainId;
    bool singleUse;
    uint256 maxValue; /// @dev Maximum ETH value (msg.value) allowed. 0 = no ETH transfer allowed.
}

/// @title ClankerGateCore - Shared validation logic for all ClankerGate implementations
/// @author Clanker Protocol
/// @custom:security-contact security@summer.fi
/// @notice Provides common validation functions for policy-based transaction validation
/// @dev EXECUTE_SELECTOR = 0x61461954 is the selector for execute(address,uint256,bytes)
library ClankerGateCore {
    bytes4 internal constant EXECUTE_SELECTOR = 0x61461954;

    /// @notice Validates a permission against policy constraints
    function validatePermission(Permission memory permission) internal view returns (bool valid, uint8 errorCode) {
        uint256 currentTime = block.timestamp;
        
        if (permission.validAfter > 0 && currentTime < permission.validAfter) {
            return (false, 7);
        }
        if (permission.validUntil > 0 && currentTime > permission.validUntil) {
            return (false, 8);
        }
        if (permission.chainId != 0 && block.chainid != permission.chainId) {
            return (false, 9);
        }
        
        return (true, 0);
    }

    /// @notice Validates calldata against permission rules with extended error info
    /// @param callData The calldata to validate
    /// @param permission The permission to validate against
    /// @return valid Whether validation passed
    /// @return errorCode ERR_INVALID_LENGTH, ERR_SELECTOR_MISMATCH, or ERR_RULE_VIOLATION
    /// @return ruleIndex The index of the failing rule (if any)
    function validateCallDataExtended(
        bytes calldata callData, 
        Permission memory permission
    ) internal pure returns (bool valid, uint8 errorCode, uint256 ruleIndex) {
        if (callData.length < 4) {
            return (false, ERR_INVALID_LENGTH, 0);
        }

        bytes4 selector = bytes4(callData[0:4]);
        if (selector != permission.selector) {
            return (false, ERR_SELECTOR_MISMATCH, 0);
        }

        // Check MAX_RULES limit (gas griefing protection)
        if (permission.rules.length > MAX_RULES) {
            revert TooManyRules(permission.rules.length, MAX_RULES);
        }

        for (uint256 i; i < permission.rules.length; ++i) {
            ParamRule memory rule = permission.rules[i];
            uint256 absoluteOffset = 4 + rule.offset;

            if (absoluteOffset + 32 > callData.length) {
                revert CalldataOutOfRange(absoluteOffset);
            }

            bytes32 actualValue;
            assembly {
                let dataOffset := add(callData.offset, absoluteOffset)
                actualValue := calldataload(dataOffset)
            }

            if (!compareRule(rule.op, actualValue, rule.value, rule.values)) {
                if (rule.op == OP_IN) {
                    revert ValueNotInSet(i, actualValue, rule.values);
                }
                revert RuleViolation(i, rule.op, rule.value, actualValue);
            }
        }

        return (true, 0, 0);
    }

    /// @notice Validates calldata against permission rules (calldata version)
    /// @dev Kept for backwards compatibility. Use validateCallDataExtended for better error info.
    function validateCallData(bytes calldata callData, Permission memory permission) 
        internal 
        pure 
        returns (bool valid, uint256 ruleIndex) 
    {
        if (callData.length < 4) {
            return (false, 0);
        }

        bytes4 selector = bytes4(callData[0:4]);
        if (selector != permission.selector) {
            return (false, 0);
        }

        // Check MAX_RULES limit (gas griefing protection)
        if (permission.rules.length > MAX_RULES) {
            revert TooManyRules(permission.rules.length, MAX_RULES);
        }

        for (uint256 i; i < permission.rules.length; ++i) {
            ParamRule memory rule = permission.rules[i];
            uint256 absoluteOffset = 4 + rule.offset;

            if (absoluteOffset + 32 > callData.length) {
                revert CalldataOutOfRange(absoluteOffset);
            }

            bytes32 actualValue;
            assembly {
                let dataOffset := add(callData.offset, absoluteOffset)
                actualValue := calldataload(dataOffset)
            }

            if (!compareRule(rule.op, actualValue, rule.value, rule.values)) {
                if (rule.op == OP_IN) {
                    revert ValueNotInSet(i, actualValue, rule.values);
                }
                revert RuleViolation(i, rule.op, rule.value, actualValue);
            }
        }

        return (true, 0);
    }

    /// @notice Validates calldata against permission rules with extended error info (memory version)
    /// @param callData The calldata to validate
    /// @param permission The permission to validate against
    /// @return valid Whether validation passed
    /// @return errorCode ERR_INVALID_LENGTH, ERR_SELECTOR_MISMATCH, or ERR_RULE_VIOLATION
    /// @return ruleIndex The index of the failing rule (if any)
    function validateCallDataMemoryExtended(
        bytes memory callData, 
        Permission memory permission
    ) internal pure returns (bool valid, uint8 errorCode, uint256 ruleIndex) {
        if (callData.length < 4) {
            return (false, ERR_INVALID_LENGTH, 0);
        }

        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }
        
        if (selector != permission.selector) {
            return (false, ERR_SELECTOR_MISMATCH, 0);
        }

        // Check MAX_RULES limit (gas griefing protection)
        if (permission.rules.length > MAX_RULES) {
            revert TooManyRules(permission.rules.length, MAX_RULES);
        }

        for (uint256 i; i < permission.rules.length; ++i) {
            ParamRule memory rule = permission.rules[i];
            uint256 absoluteOffset = 4 + rule.offset;

            if (absoluteOffset + 32 > callData.length) {
                revert CalldataOutOfRange(absoluteOffset);
            }

            bytes32 actualValue;
            assembly {
                actualValue := mload(add(add(callData, 32), absoluteOffset))
            }

            if (!compareRule(rule.op, actualValue, rule.value, rule.values)) {
                if (rule.op == OP_IN) {
                    revert ValueNotInSet(i, actualValue, rule.values);
                }
                revert RuleViolation(i, rule.op, rule.value, actualValue);
            }
        }

        return (true, 0, 0);
    }

    /// @notice Validates calldata against permission rules (memory version)
    function validateCallDataMemory(bytes memory callData, Permission memory permission) 
        internal 
        pure 
        returns (bool valid, uint256 ruleIndex) 
    {
        if (callData.length < 4) {
            return (false, 0);
        }

        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }
        
        if (selector != permission.selector) {
            return (false, 0);
        }

        // Check MAX_RULES limit (gas griefing protection)
        if (permission.rules.length > MAX_RULES) {
            revert TooManyRules(permission.rules.length, MAX_RULES);
        }

        for (uint256 i; i < permission.rules.length; ++i) {
            ParamRule memory rule = permission.rules[i];
            uint256 absoluteOffset = 4 + rule.offset;

            if (absoluteOffset + 32 > callData.length) {
                revert CalldataOutOfRange(absoluteOffset);
            }

            bytes32 actualValue;
            assembly {
                actualValue := mload(add(add(callData, 32), absoluteOffset))
            }

            if (!compareRule(rule.op, actualValue, rule.value, rule.values)) {
                if (rule.op == OP_IN) {
                    revert ValueNotInSet(i, actualValue, rule.values);
                }
                revert RuleViolation(i, rule.op, rule.value, actualValue);
            }
        }

        return (true, 0);
    }

    /// @notice Compares a value using the specified operator
    /// @param op The comparison operator (OP_EQ, OP_GT, OP_LT, OP_GTE, OP_LTE, OP_IN, OP_SGT, OP_SLT)
    /// @param actual The actual value from calldata
    /// @param expected The expected value (used for OP_EQ, OP_GT, OP_LT, OP_GTE, OP_LTE, OP_SGT, OP_SLT)
    /// @param values The array of allowed values (used for OP_IN)
    /// @dev All comparisons treat bytes32 as unsigned integers except OP_SGT and OP_SLT 
    ///      which perform signed int256 comparison by casting bytes32 to int256.
    function compareRule(
        uint8 op, 
        bytes32 actual, 
        bytes32 expected,
        bytes32[] memory values
    ) internal pure returns (bool) {
        if (op == OP_EQ) return actual == expected;
        if (op == OP_GT) return actual > expected;
        if (op == OP_LT) return actual < expected;
        if (op == OP_GTE) return actual >= expected;
        if (op == OP_LTE) return actual <= expected;
        if (op == OP_IN) {
            if (values.length > MAX_IN_VALUES) revert TooManyValues(values.length, MAX_IN_VALUES);
            return inArray(actual, values);
        }
        if (op == OP_SGT) {
            int256 actualSigned;
            int256 expectedSigned;
            assembly {
                actualSigned := actual
                expectedSigned := expected
            }
            return actualSigned > expectedSigned;
        }
        if (op == OP_SLT) {
            int256 actualSigned;
            int256 expectedSigned;
            assembly {
                actualSigned := actual
                expectedSigned := expected
            }
            return actualSigned < expectedSigned;
        }
        revert InvalidOperator(op);
    }

    /// @notice Checks if a value exists in an array
    /// @param value The value to search for
    /// @param array The array to search in
    function inArray(bytes32 value, bytes32[] memory array) internal pure returns (bool) {
        for (uint256 i; i < array.length; ++i) {
            if (array[i] == value) {
                return true;
            }
        }
        return false;
    }

    /// @notice Computes the keccak256 hash of a permission
    /// @dev Uses domain separator to prevent cross-contract replay and double-hashing 
    ///      to prevent second pre-image attacks on Merkle tree. Rules are hashed individually
    ///      to ensure canonical encoding (reordering doesn't change the hash).
    function hashPermission(Permission memory permission) internal view returns (bytes32) {
        bytes32[] memory ruleHashes = new bytes32[](permission.rules.length);
        for (uint256 i; i < permission.rules.length; ++i) {
            ParamRule memory rule = permission.rules[i];
            ruleHashes[i] = keccak256(abi.encode(rule.offset, rule.op, rule.value, rule.values));
        }

        bytes32 encodedPermission = keccak256(abi.encode(
            permission.target,
            permission.selector,
            ruleHashes,
            permission.validAfter,
            permission.validUntil,
            permission.chainId,
            permission.singleUse,
            permission.maxValue
        ));

        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_SEPARATOR_TYPEHASH,
            keccak256("ClankerGate"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));

        return keccak256(abi.encode(domainSeparator, encodedPermission));
    }

    /// @notice Computes permission hash scoped to a specific account
    /// @dev Prevents cross-account singleUse collision attacks
    /// @param account The account address to scope the permission to
    /// @param permission The permission to hash
    function hashPermissionWithAccount(address account, Permission memory permission, uint256 nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(account, hashPermission(permission), nonce));
    }

    /// @notice Verifies a Merkle proof for a permission
    // CG-03: Added account+nonce to bind permission to policy epoch
    function verifyMerkleProof(
        bytes32 root, 
        bytes32[] memory proof, 
        Permission memory permission,
        address account,
        uint256 nonce
    ) internal view returns (bool) {
        bytes32 leaf = hashPermissionWithAccount(account, permission, nonce);
        return MerkleProof.verify(proof, root, leaf);
    }

    /// @notice Decodes execute() wrapper (calldata version)
    /// @dev Returns (address(0), 0, callData.length, 0) for non-execute calls
    /// @param callData The calldata to decode
    /// @return target The target address from execute() or address(0) for direct calls
    /// @return innerDataOffset Offset to inner data (0 for direct calls)
    /// @return innerDataLength Length of inner data
    /// @return value The ETH value from execute() or 0 for direct calls
    function decodeExecuteCall(bytes calldata callData)
        internal
        pure
        returns (address target, uint256 innerDataOffset, uint256 innerDataLength, uint256 value)
    {
        if (callData.length < 4) {
            return (address(0), 0, 0, 0);
        }

        bytes4 selector = bytes4(callData[0:4]);

        if (selector == EXECUTE_SELECTOR && callData.length >= 132) {
            target = address(bytes20(callData[16:36]));
            value = uint256(bytes32(callData[36:68]));
            uint256 dataOffset = uint256(bytes32(callData[68:100]));
            // CG-12: Read dataLength from dynamic position based on dataOffset pointer,
            // not hardcoded offset. This prevents ABI layout bypass attacks.
            uint256 dataLength = uint256(bytes32(callData[68 + dataOffset:68 + dataOffset + 32]));
            innerDataOffset = 68 + dataOffset + 32;
            innerDataLength = dataLength;
            
            // Bounds check: ensure inner data is within calldata
            if (innerDataOffset + innerDataLength > callData.length) {
                revert InvalidExecuteEncoding();
            }
            
            // Validate address zero-padding (security check)
            if (bytes12(callData[4:16]) != bytes12(0)) {
                revert InvalidAddressPadding();
            }
        } else {
            target = address(0);
            innerDataOffset = 0;
            innerDataLength = callData.length;
            value = 0;
        }
    }

    /// @notice Decodes execute() wrapper (memory version)
    /// @notice Decodes execute() wrapper (memory version)
    /// @dev Returns (address(0), 0, callData.length, 0) for non-execute calls
    function decodeExecuteCallMemory(bytes memory callData)
        internal
        pure
        returns (address target, uint256 innerDataOffset, uint256 innerDataLength, uint256 value)
    {
        if (callData.length < 4) {
            return (address(0), 0, 0, 0);
        }

        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }

        if (selector == EXECUTE_SELECTOR && callData.length >= 132) {
            bytes20 targetBytes;
            uint256 dataOffset;
            bytes12 padding;
            assembly {
                padding := mload(add(callData, 36))
                targetBytes := mload(add(add(callData, 32), 16))
                dataOffset := mload(add(add(callData, 32), 68))
            }
            
            // CG-12: Read dataLength from dynamic position based on dataOffset pointer,
            // not hardcoded offset. This prevents ABI layout bypass attacks.
            uint256 dataLength;
            unchecked {
                uint256 dataLengthPos = 68 + dataOffset;
                if (dataLengthPos + 32 <= callData.length) {
                    assembly {
                        dataLength := mload(add(add(callData, 32), dataLengthPos))
                    }
                }
            }
            
            // Decode value from bytes 36-68
            assembly {
                value := mload(add(add(callData, 32), 36))
            }
            
            // Validate address zero-padding
            if (padding != bytes12(0)) {
                revert InvalidAddressPadding();
            }
            
            target = address(targetBytes);
            innerDataOffset = 68 + dataOffset + 32;
            innerDataLength = dataLength;
            
            // Bounds check
            if (innerDataOffset + innerDataLength > callData.length) {
                revert InvalidExecuteEncoding();
            }
        } else {
            target = address(0);
            innerDataOffset = 0;
            innerDataLength = callData.length;
            value = 0;
        }
    }

    // Errors
    error CalldataOutOfRange(uint256 offset);
    error RuleViolation(uint256 ruleIndex, uint8 op, bytes32 expected, bytes32 actual);
    error ValueNotInSet(uint256 ruleIndex, bytes32 actual, bytes32[] expected);
    error PermissionAlreadyUsed(bytes32 permissionHash);
    error InvalidOperator(uint8 op);
    error TooManyRules(uint256 count, uint8 maxAllowed);
    error TooManyValues(uint256 count, uint256 maxAllowed);
    error InvalidExecuteEncoding();
    error InvalidAddressPadding();
    error ValueExceedsPermission(uint256 value, uint256 maxValue);
}