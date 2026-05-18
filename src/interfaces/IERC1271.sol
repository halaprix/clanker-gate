// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

/// @title IERC1271 - Interface for EIP-1271 smart contract signatures
/// @notice Used for signature validation of smart contract wallets (e.g., Safe)
interface IERC1271 {
    /// @notice Verifies if the signature is valid for the given hash
    /// @param hash The hash that was signed
    /// @param signature The signature bytes
    /// @return magicValue 0x1626ba7e if valid, otherwise invalid
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}
