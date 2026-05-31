// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Module type identifiers
uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;

interface IERC7579Account {
    /**
     * @notice Check if account supports a specific module type
     * @param moduleTypeId The module type ID
     * @return True if supported
     */
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
    
    /**
     * @notice Install a module on the account
     * @param moduleTypeId The module type ID
     * @param module The module address
     * @param initData Initialization data
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external;
    
    /**
     * @notice Uninstall a module
     * @param moduleTypeId The module type ID
     * @param module The module address
     * @param deInitData Deinitialization data
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external;
    
    /**
     * @notice Check if module is installed
     * @param moduleTypeId The module type ID
     * @param module The module address
     * @return True if installed
     */
    function isModuleInstalled(uint256 moduleTypeId, address module) external view returns (bool);

    /**
     * @notice Get account owner
     * @return Owner address
     */
    function owner() external view returns (address);
}

/**
 * @notice ERC-7579 IValidator interface implemented by ClankerGate7579
 * @dev Module Type 1 (Validator). Key entry points:
 *
 *   - isModuleType(uint256 moduleTypeId) → bool
 *       Returns true iff moduleTypeId == MODULE_TYPE_VALIDATOR (1).
 *       Replaces the legacy moduleType() → uint256 form.
 *
 *   - validateUserOp(PackedUserOperation calldata, bytes32 userOpHash) → uint256
 *       Reads (proof, permission, ownerSig) from userOp.signature.
 *       Returns 0 on success, packed ERC-4337 validation data on failure.
 *
 *   - isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature) → bytes4
 *       Signer-identity-only check (no Merkle policy). Returns 0x1626ba7e on success,
 *       0xffffffff on failure. `sender` is the original ERC-1271 requester (not used
 *       for policy gating).
 *
 *   - onInstall(bytes calldata initData)
 *       initData = abi.encode(address owner, bytes32 policyRoot, address signatureValidator)
 *       Sets config.nonce = ++_installEpoch[msg.sender] (monotonic across reinstalls).
 *
 *   - onUninstall(bytes calldata deInitData)
 *       Deletes accountConfigs but preserves _installEpoch so reinstall always gets a
 *       fresh nonce that is strictly greater than any previous install's nonce.
 */
interface IERC7579Validator {
    function isModuleType(uint256 moduleTypeId) external pure returns (bool);
    function onInstall(bytes calldata initData) external;
    function onUninstall(bytes calldata deInitData) external;
}
