// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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
