# ClankerGate EIP Compliance

## EIP-4337: Account Abstraction via Entry Point

### Compliance Status: ✅ Compliant

| Requirement | Implementation | Location |
|---|---|---|
| validateUserOp returns validationData | Packed via `_packValidationData` | `ClankerGate4337.sol:validateUserOp` |
| Signature validation | ECDSA recovery (`userOpHash.recover(sig)`) | `ClankerGate4337.sol:validateUserOp` (line 226) |
| SIG_VALIDATION_FAILED = 1 | Packed as bit 0 | `ClankerGate4337.sol:_packValidationData` (line 304) |
| validUntil (bits 160-207) | `(uint256(validUntil) << 160)` | `ClankerGate4337.sol:_packValidationData` (line 304) |
| validAfter (bits 208-255) | `(uint256(validAfter) << 208)` | `ClankerGate4337.sol:_packValidationData` (line 304) |
| Entry point interaction guard | `require(msg.sender == sender)` for singleUse marking | `ClankerGate4337.sol:validateUserOp` (line 237) |
| Return data bomb mitigation | Bounded assembly staticcall (32 bytes max output) | `ClankerGate4337.sol:_getOwner` (lines 273-291) |

### Notes

- **singleUse permissions**: Require `msg.sender == account` (sender must be the Entry Point calling on behalf of the account) to prevent front-running attacks — only the account itself can mark its own permissions as used.
- **Return data bombs**: Mitigated via bounded assembly `staticcall` with a 32-byte output limit. Malicious `owner()` implementations that return massive payloads will not exhaust memory.
- **Validation failures**: Return packed data with SIG_VALIDATION_FAILED=1 on rule violations, allowing the Entry Point to distinguish signature failures from other failures.
- **Merkle proof binding**: Proofs are bound to `(account, nonce)` to prevent proof replay across accounts or policy epochs.

---

## EIP-7579: Modular Smart Contract Accounts

### Compliance Status: ✅ Compliant (Module Type 1 — Validator)

| Requirement | Implementation | Location |
|---|---|---|
| `MODULE_TYPE_VALIDATOR` (1) | Returns `MODULE_TYPE_VALIDATOR` constant | `ClankerGate7579.sol:moduleType` (line 126) |
| `onInstall(bytes)` | Decodes `initData`, stores `AccountConfig` | `ClankerGate7579.sol:onInstall` (lines 143-160) |
| `onUninstall(bytes)` | Clears account config, emits event | `ClankerGate7579.sol:onUninstall` (lines 166-184) |
| `isModuleInstalled(address)` | Returns `config.installed` | `ClankerGate7579.sol:isModuleInstalled` (line 135) |
| `validateUserOp` | Validates against Merkle policy tree | `ClankerGate7579.sol:validateUserOp` (lines 250-357) |
| Install guard | Prevents overwrite of existing configuration | `ClankerGate7579.sol:onInstall` (line 145) |

### Supported Account Types

- **Safe v1.5+** (with ERC-7579 adapter)
- **ZeroDev**, **Biconomy**, **Rhinestone**, **Kernel**
- **Any ERC-7579 compliant account**

### initData Format

`abi.encode(owner, policyRoot, signatureValidator)`

| Parameter | Type | Description |
|---|---|---|
| `owner` | `address` | Account that can update policies |
| `policyRoot` | `bytes32` | Initial Merkle root (0 = disabled) |
| `signatureValidator` | `address` | Signature validator contract (0 = use `owner()` fallback) |

### Dual-format UserOp Support

| Format | Fields | Decoder | Description |
|---|---|---|---|
| PackedUserOperation v0.7 | 11 | `decodeCallDataPacked` | ERC-4337 v0.7 entry point format |
| Legacy UserOperation | 10 | `decodeCallDataLegacy` | Pre-v0.7 entry point format |
| Auto-detection | — | `_decodeCallData` (try/catch) | Tries v0.7 first, falls back to legacy |

---

## EIP-1271: Standard Signature Validation for Contracts

### Compliance Status: ✅ Compliant

| Requirement | Implementation | Location |
|---|---|---|
| `isValidSignature(bytes32,bytes) returns bytes4` | Signature validator contract interface | `IERC1271.sol` |
| Magic value = `0x1626ba7e` | Compared to `IERC1271.isValidSignature.selector` | `ClankerGate7579.sol:validateUserOp` (line 333) |
| Malleability resistance | Uses `ECDSA.recover` (enforces low-s) | `ECDSA` library (OpenZeppelin) |
| Contract wallet support | Falls back to `owner()` if no `sigValidator` | `ClankerGate7579.sol:_getExpectedSigner` (lines 448-486) |

### EIP-1271 in ERC-4337 Context

- **ClankerGate4337**: Uses ECDSA for EOA accounts. Signature recovered via `userOpHash.recover(sig)` and compared against `_getOwner(sender)`.
- **ClankerGate7579**: Supports both EOA (ECDSA) and smart contract wallet (EIP-1271) signatures:
  - If `signatureValidator != address(0)` and has code → calls `isValidSignature(hash, signature) == 0x1626ba7e`
  - Otherwise → ECDSA recovery against the configured owner
- **Signature validator address** is configured during `onInstall` via the `initData` parameter.

### EIP-1271 Flow (ClankerGate7579)

```
validateUserOp
  ├── sigValidator.code.length > 0?
  │   ├── YES → IERC1271(sigValidator).isValidSignature(userOpHash, signature) == 0x1626ba7e
  │   └── NO  → ECDSA.recover(userOpHash, signature) == expectedSigner
  └── sigValid? → proceed or revert
```

---

## Security Measures (Cross-EIP)

| Measure | Applies To | Description |
|---|---|---|
| **Transient reentrancy guard** | Safe | Solady `ReentrancyGuardTransient` using `TSTORE`/`TLOAD` opcodes — zero-cost after transaction, no storage slot consumption |
| **Return data bomb protection** | 4337, 7579 | Bounded assembly `staticcall` with 32-byte output limit prevents malicious `owner()` implementations from exhausting memory |
| **Cross-account collision prevention** | 4337, 7579, Safe | Account-scoped singleUse permission hashes via nested `mapping(address => mapping(bytes32 => bool))` |
| **Merkle proof verification** | 4337, 7579, Safe | OpenZeppelin `MerkleProof` with `(account, nonce)` binding to prevent proof replay across accounts or policy epochs |
| **Domain separator** | 4337, 7579, Safe | Immutable `DOMAIN_SEPARATOR` cached at construction using EIP-712 typehash, preventing cross-contract signature replay |
| **Gas-bounded owner calls** | 4337 | `_assertCallerIsAccountOrOwner` limits gas to 30,000 when calling `owner()` to prevent griefing from malicious implementations |
| **DELEGATECALL whitelist** | Safe | Versioned whitelist (`whitelistVersion`) invalidates old entries on policy rotation (CG-20b) |
| **Install guard** | 7579 | `onInstall` reverts with `AlreadyInstalled` if the account already has a configuration, preventing overwrite attacks |
| **Front-running protection** | 4337 | singleUse permissions require `msg.sender == account` — prevents anyone from directly calling `validateUserOp` to mark permissions as used (CG-01) |

---

## Contract Reference

| Contract | File | EIPs Covered | Key Functions |
|---|---|---|---|
| `ClankerGate4337` | `src/ClankerGate4337.sol` | EIP-4337 | `validateUserOp`, `setPolicyRoot`, `_packValidationData` |
| `ClankerGate7579` | `src/ClankerGate7579.sol` | EIP-7579, EIP-1271 | `moduleType`, `onInstall`, `onUninstall`, `isModuleInstalled`, `validateUserOp` |
| `ClankerGateSafe` | `src/ClankerGateSafe.sol` | EIP-7579-compatible | `execTransaction`, `execTransactionWithProof`, `setPolicyRoot` |
| `ClankerGateCore` | `src/ClankerGateCore.sol` | Shared logic | `verifyMerkleProof`, `validatePermission`, `validateCallDataExtended`, `hashPermission` |
