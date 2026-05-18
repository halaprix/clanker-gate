// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

interface IAccount {
    function validateUserOp(bytes calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);

    function owner() external view returns (address);
}

interface IERC7579Account {
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external;
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external;
    function isModuleInstalled(uint256 moduleTypeId, address module) external view returns (bool);
}

interface IEntryPoint {
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash) external returns (uint256 validationData);

    function getUserOpHash(UserOperation calldata userOp) external view returns (bytes32);
}
