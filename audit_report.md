# ClankerGate Security Audit Report

**Date:** March 2026
**Target Context:** `clanker-gate/src`
**Scope:** `ClankerGateCore.sol`, `ClankerGate4337.sol`, `ClankerGate7579.sol`, `ClankerGateSafe.sol`

---

## 1. Executive Summary
This document serves as the main security audit report gathering findings from specialized security analyses.

---

## 2. Findings Summary

| ID | Title | Severity | Status |
|---|---|---|---|
| [CG-01](#cg-01-unauthenticated-state-modification-in-erc-4337-validation-flow) | Unauthenticated State Modification in ERC-4337 Validation Flow | **HIGH** | Open |
| [CG-02](#cg-02-permission-structure-lacks-caller-authentication-fields) | Permission Structure Lacks Caller Authentication Fields | **MEDIUM** | Open |
| [CG-03](#cg-03-decoupled-state-epochs-policy-nonce-ignored-in-permission-hashing) | Decoupled State Epochs: Policy Nonce Ignored in Permission Hashing | **HIGH** | Open |
| [CG-04](#cg-04-incomplete-state-wiping-on-erc-7579-module-uninstall) | Incomplete State Wiping on ERC-7579 Module Uninstall | **MEDIUM** | Open |
| [CG-05](#cg-05-interface-standard-violations-in-erc-4337-and-erc-7579-validators) | Interface Standard Violations in ERC-4337 and ERC-7579 Validators | **CRITICAL** | Open |
| [CG-06](#cg-06-broken-promises-packeduseroperation-v07-hard-revert) | Broken Promises: PackedUserOperation v0.7 Hard-Revert | **HIGH** | Open |
| [CG-07](#cg-07-eoa-signer-expectation-assumed-for-signature-validator-contracts) | EOA Signer Expectation Assumed For Signature Validator Contracts | **HIGH** | Open |
| [CG-08](#cg-08-unbounded-array-loop-in-op_in-validation-footgunbundler-griefing) | Unbounded Array Loop in OP_IN Validation (Footgun/Bundler Griefing) | **MEDIUM** | Open |
| [CG-09](#cg-09-persistent-state-consumption-on-execution-revert-single-use-griefing) | Persistent State Consumption on Execution Revert (Single-Use Griefing) | **MEDIUM** | Open |
| [CG-10](#cg-10-unrestricted-native-eth-transfers-via-unchecked-value-execution) | Unrestricted Native ETH Transfers via Unchecked `value` Execution | **CRITICAL** | Open |
| [CG-11](#cg-11-return-data-bomb-against-trycatch-fallbacks-via-staticcall) | Return Data Bomb against `try/catch` Fallbacks via `staticcall` | **MEDIUM** | Open |
| [CG-12](#cg-12-hardcoded-calldata-layout-bypass-vector-169) | Hardcoded Calldata Layout Bypass (Vector 169) | **CRITICAL** | Open |
| [CG-13](#cg-13-on-byte-byte-calldata-copy-causes-user-self-dos-on-large-payloads) | O(N) Byte-by-Byte Calldata Copy Causes User Self-DoS on Large Payloads | **LOW** | Open |
| [CG-15](#cg-15-incorrect-bit-shift-in-_packvalidationdata-corrupts-erc-4337-timestamps) | Incorrect Bit Shift in `_packValidationData` Corrupts ERC-4337 Timestamps | **HIGH** | Open |
| [CG-18](#cg-18-domain-separator-uses-permissiontarget-instead-of-addressthis) | Domain Separator Uses `permission.target` Instead of `address(this)` — Cross-Contract Replay | **HIGH** | Open |
| [CG-19](#cg-19-policy-nonce-absent-from-permission-hash-singleuse-state-desync-on-rotation) | Policy Nonce Absent from Permission Hash — singleUse State Desync on Rotation | **MEDIUM** | Open |
| [CG-20b](#cg-20b-delegatecall-whitelist-not-cleared-on-policy-rotation) | Delegatecall Whitelist Not Cleared on Policy Rotation | **LOW** | Open |
| [CG-21](#cg-21-unsigned-comparison-type-confusion-in-op_gtop_lt-for-signed-parameters) | Unsigned Comparison Type-Confusion in `OP_GT`/`OP_LT` for Signed Parameters | **MEDIUM** | Open |
| [CG-22](#cg-22-setpolicyroot-allows-arbitrary-iaccountaccountowner-external-call) | `setPolicyRoot` Allows Arbitrary `IAccount(account).owner()` External Call | **LOW** | Open |
| [CG-23](#cg-23-prefer-custom-errors-over-require) | Prefer Custom Errors Over `require` | **LOW** | Open |
| [CG-24](#cg-24-loop-optimization-i-vs-i-and-explicit-zero-initialization) | Loop Optimization: `++i` vs `i++` | **INFO** | Open |
| [CG-25](#cg-25-floating-pragmas-in-production-contracts) | Floating Pragmas in Production Contracts | **INFO** | Open |
| [CG-26](#cg-26-missing-customsecurity-contact) | Missing `@custom:security-contact` | **INFO** | Open |

---

## 3. Detailed Findings

### [CG-01] Unauthenticated State Modification in ERC-4337 Validation Flow

**Severity:** HIGH
**Location:** `src/ClankerGate4337.sol` : `validateUserOp()`

**Description:**
The `validateUserOp()` function in `ClankerGate4337` is declared `external` and modifies the `usedPermissionHashes[userOp.sender][permissionHash]` state when a `singleUse` permission is passed. However, it fails to verify that the `msg.sender` calling it is authorized to modify the state for `userOp.sender`. 
In standard ERC-4337 flows, `validateUserOp` should only be called by the trusted `EntryPoint`, or if implemented as a module, by the `Account` itself.

**Security Impact:**
An attacker can monitor the mempool for a valid `UserOperation` that utilizes a `singleUse` permission. The attacker can extract the valid `userOp` and `guardData` and call `ClankerGate4337.validateUserOp` directly before the actual transaction is processed by the EntryPoint. This will successfully set `usedPermissionHashes[userOp.sender][permissionHash] = true;`. When the real transaction attempts to execute, it will revert due to `PermissionAlreadyUsed`, effectively creating a Denial of Service (DoS) griefing vector against any `singleUse` permission.

**Recommendation:**
Add an explicit caller context guard to ensure the state modification is authorized. Depending on the architecture, if this contract is a standalone validator module called by the account, it should enforce `require(msg.sender == userOp.sender, "Unauthorized")`.

---

### [CG-02] Permission Structure Lacks Caller Authentication Fields

**Severity:** MEDIUM
**Location:** `src/ClankerGateSafe.sol` : `execTransactionWithProof()`

**Description:**
The developer documentation for `execTransactionWithProof` states: *"This function now requires the caller to be explicitly authorized OR the permission to include a caller field. For security, proof alone is NOT enough."* 
However, the `Permission` struct (defined in `ClankerGateCore.sol`) completely lacks a caller field. The struct only includes: `target`, `selector`, `rules`, `validAfter`, `validUntil`, `chainId`, `singleUse`.

**Security Impact:**
Because the permission struct lacks a specific caller assignment, if a Safe authorizes multiple callers (e.g., Alice and Bob), a permission generated off-chain specifically intended for Bob could be intercepted and utilized by Alice (provided Alice is also generally authorized on the Safe). This circumvents granular operational flows, potentially allowing Alice to front-run Bob's intended permissions.

**Recommendation:**
If caller-specific permissions are an intended design feature according to the documentation, add an `address authorizedCaller` field to the `Permission` struct. Then, enforce a check inside `_validateAndExecute` (e.g., `if (permission.authorizedCaller != address(0) && msg.sender != permission.authorizedCaller) revert();`). Alternatively, update the documentation to explicitly accept that permissions are inherently shared among all authorized callers.

---

### [CG-03] Decoupled State Epochs: Policy Nonce Ignored in Permission Hashing

**Severity:** HIGH
**Location:** `src/ClankerGateCore.sol` : `hashPermissionWithAccount()`

**Description:**
The contracts maintain a monotonically increasing `nonce` variable (e.g., `nonces[account]`, `accountConfigs[account].nonce`) that increments whenever an account updates its `policyRoot`. This conceptually creates a new policy "epoch". 
However, the mathematical hash used to track `singleUse` replays (`ClankerGateCore.hashPermissionWithAccount`) completely omits this `nonce` from its encoding payload.

**Security Impact:**
Because the nonce is omitted, if an account owner updates their `policyRoot` to add a new function but keep their existing permissions, any `singleUse` permission executed in Epoch N remains marked as `true` in `usedPermissionHashes`. In Epoch N+1, the *same* `singleUse` permission structure will immediately revert as "Already Used". This breaks the module boundary between policy epochs, crippling the utility of `singleUse` across policy updates unless users artificially jitter timestamps to generate unique hashes.

**Recommendation:**
Include the account's current `nonce` inside the domain separator or the explicit parameter encoding of `_hashPermissionWithAccount`. This mathematically binds usage tracking to the current policy generation epoch.

---

### [CG-04] Incomplete State Wiping on ERC-7579 Module Uninstall

**Severity:** MEDIUM
**Location:** `src/ClankerGate7579.sol` : `onUninstall()`

**Description:**
In `ClankerGate7579.sol`, the `onUninstall` function invokes `delete accountConfigs[msg.sender]` to wipe the module installation state. However, the nested mapping `usedPermissionHashes` is not, and cannot easily be, deleted in Solidity.

**Security Impact:**
Because `singleUse` permission hashes omit any epoch or nonce data (as outlined in CG-03), if an account re-installs the module with standard policy configurations, historically consumed `singleUse` provisions will persist as already executed. The module's claim of a clean state installation is compromised by historical data leaks from the previous installation phase.

**Recommendation:**
Resolving CG-03 by integrating the `nonce` mapping into the permission hashing logic intrinsically resolves this issue as well, because an `onInstall` cleanly resets the nonce to `1`, thereby pivoting the access space away from old mapping collision values.

---

### [CG-05] Interface Standard Violations in ERC-4337 and ERC-7579 Validators

**Severity:** CRITICAL
**Location:** `src/ClankerGate4337.sol:validateUserOp()`, `src/ClankerGate7579.sol:validateUserOp()`

**Description:**
Both `ClankerGate4337` and `ClankerGate7579` define their `validateUserOp` implementation by appending a third parameter, `bytes calldata guardData`.
However, the standard ERC-4337 `.validateUserOp` signature expects `(UserOperation, bytes32, uint256)`, and the standard ERC-7579 signature expects `(PackedUserOperation, bytes32)`.

**Security Impact:**
Because the function signatures do not match the expected standards, typical smart accounts (for 4337) and standard ecosystem infrastructure (like Bundlers) will fail to interact with the module. The EVM ABI decoder will either interpret trailing properties incorrectly (leading to an out-of-bounds array access revert) or immediately revert due to mismatched calldata lengths. The modules are fundamentally incompatible natively with standard clients.

**Recommendation:**
Remove the `bytes calldata guardData` parameter from the function signatures. Instead, decode the `guardData` manually directly from the trailing bytes of the `signature` field inside the `UserOperation`, which is the standardized way for passing module-specific data through generalized validation endpoints.

---

### [CG-06] Broken Promises: PackedUserOperation v0.7 Hard-Revert

**Severity:** HIGH
**Location:** `src/ClankerGate7579.sol` : `_decodeCallData()`

**Description:**
The internal `_decodeCallData` method dictates through comments that it supports both standard legacy UserOp formats and v0.7 `PackedUserOperation` variants. However, if the decode process fails to resolve against the 10-parameter legacy schema, it immediately executes `revert InvalidUserOpFormat();` without making any attempt to mathematically extract the `PackedUserOperation`.

**Security Impact:**
Any modern ERC-4337 v0.7 compliant smart account attempting to utilize this module will experience a hard revert. This guarantees integration failures for contemporary infrastructure despite explicit documentation asserting support.

**Recommendation:**
Implement standard extraction logic for `PackedUserOperation` if legacy parsing fails. For example, use static offsets (since `PackedUserOperation` offsets are rigidly defined) to slice the relevant boundaries and extract `callData`.

---

### [CG-07] EOA Signer Expectation Assumed For Signature Validator Contracts

**Severity:** HIGH
**Location:** `src/ClankerGate7579.sol` : `_getExpectedSigner() / validateUserOp()`

**Description:**
The contract provides a `signatureValidator` configuration aimed at using external contracts to perform signature validation. However, the validation loop uses raw execution: `userOpHash.recover(signature) != signatureValidator`. 

**Security Impact:**
Smart contracts cannot physically generate ECDSA signatures. If a smart contract is used as an external signature validator (such as a multi-sig or passkey integrated EIP-1271 construct), `userOpHash.recover(signature)` will recover an arbitrary 160-bit EOA address. Checking if this derived EOA address precisely equals the validator's smart contract address will mathematically always fail. Integrating a custom signature validator immediately bricks the module for that account setup.

**Recommendation:**
Refactor the signature validation to check if `signatureValidator.code.length > 0`. If it does, execute a standard `EIP1271.isValidSignature` external call against the contract instead of attempting raw ECDSA recovery matching.

---

### [CG-08] Unbounded Array Loop in OP_IN Validation (Footgun/Bundler Griefing)

**Severity:** MEDIUM
**Location:** `src/ClankerGateCore.sol` : `inArray()`

**Description:**
While `ClankerGateCore` strictly bounds `permission.rules.length` to `MAX_RULES` (10) as a gas griefing protection, it completely neglects to bound the `bytes32[] values` array nested inside each `ParamRule` when used with `OP_IN`. The `inArray` function iterates over this array unbounded.

**Security Impact:**
If a policy requires checking a massive array for an `OP_IN` rule, the gas consumed during ERC-4337 `validateUserOp` simulation might differ slightly from actual execution due to state caching or varying inputs, potentially causing the UserOp to hit verification gas limits and be dropped by bundlers. This represents a self-inflicted Denial of Service or an attack vector against layer 2 data availability costs by forcing bundlers to process massive calldata payloads that subsequently drop.

**Recommendation:**
Implement a `MAX_IN_VALUES` constant (e.g., 20) and enforce `if (rule.values.length > MAX_IN_VALUES) revert TooManyValues();` inside the `validateCallDataExtended` function when processing an `OP_IN` operation.

---

### [CG-09] Persistent State Consumption on Execution Revert (Single-Use Griefing)

**Severity:** MEDIUM
**Location:** `src/ClankerGate4337.sol`, `src/ClankerGate7579.sol` : `validateUserOp()`

**Description:**
In the ERC-4337 and ERC-7579 architecture, `validateUserOp` alters state before the execution layer processes the transaction. Both `ClankerGate` validator modules natively set `usedPermissionHashes[userOp.sender][permissionHash] = true` inside `validateUserOp`. If the subsequent execution fails (which happens in a separate sub-call by the EntryPoint), this state change persists.

**Security Impact:**
An attacker who monitors the mempool can see a UserOp with a single-use permission (e.g., a DEX swap) and front-run the operation to manipulate the pool. The victim's UserOp validation will succeed (the bundler gets paid, and the `permissionHash` is marked as `true` in the module). However, the execution layer attempts the swap and reverts due to slippage tolerance. The `singleUse` permission is now permanently burned and dead. The user suffers a total Denial of Service for that specific off-chain policy intent and must generate and sign a new payload.

**Recommendation:**
Document explicitly that `singleUse` permissions are permanently consumed upon *validation*, not successful execution. To secure guaranteed execution without griefing, single-use state modifications should optimally be managed inside a post-validation hook (ERC-7579 Hook implementations) rather than the pre-execution validation module, allowing state rollback if the primary execution fails.

---

### [CG-10] Unrestricted Native ETH Transfers via Unchecked `value` Execution

**Severity:** CRITICAL
**Location:** `src/ClankerGateSafe.sol:execTransactionWithProof()`, `src/ClankerGateCore.sol:decodeExecuteCall()`

**Description:**
The ClankerGate validation architecture strictly verifies the `target`, `selector`, and specific `calldata` parameter subsets using the `Permission` struct and `ParamRule` rules. However, the architecture entirely forgets to validate or bound the native ETH `value` transferred during an external call.

**Security Impact:**
An authorized session key holder (or relayer on an account) receives a strict permission to call a function on a trusted protocol. The policy uses `ParamRule`s to ensure the user can only act upon limited USDC bounds.
However, because the validation modules completely ignore the `value` parameter, the attacker can simply set the `value` parameter to the entire ETH balance of the Smart Account. The external call executes natively, draining all of the Smart Account's native ETH directly to the target (assuming the target has a `payable` fallback or the approved function is `payable`). This massive bypass of the intended application security policy leads directly to the unauthorized loss of native Ethereum assets.

**Recommendation:**
1. Add a `uint256 maxValue` field to the core `Permission` struct.
2. In `ClankerGateSafe.sol`, enforce `if (value > permission.maxValue) revert ValueTooHigh();`.
3. In `ClankerGateCore.sol`, update `decodeExecuteCall` to extract and explicitly validate the `value` field from `callData[36:68]` against the permission rules.

---

### [CG-11] Return Data Bomb against `try/catch` Fallbacks via `staticcall`

**Severity:** MEDIUM
**Location:** `src/ClankerGate4337.sol:_getOwner()`, `src/ClankerGate7579.sol:_getExpectedSigner()`

**Description:**
The validator modules query `.owner()` on potentially untrusted caller accounts via a native `try/catch` block.

**Security Impact:**
If an attacker creates a malicious `UserOperation` where `userOp.sender` points to a malicious contract, the bundler simulates the operation. When the validator invokes `userOp.sender.owner()`, the malicious contract executes a `return` returning a multi-megabyte payload.
Because Solidity's `try/catch` mechanism automatically allocates contiguous memory to hold the return data *before* attempting ABI decoding, the simulation causes a massive memory expansion, exhausting the RPC node's computational memory or forcefully crashing the execution. This represents a Denial of Service griefing vulnerability against ecosystem infrastructure (Bundlers).

**Recommendation:**
Enforce low-level `staticcall` patterns with restricted returned memory limits via assembly when interrogating untrusted caller endpoints to extract owner mappings. Alternatively, check `account.code.length` prior to invocation.

---

### [CG-12] Hardcoded Calldata Layout Bypass (Vector 169)

**Severity:** CRITICAL
**Location:** `src/ClankerGateCore.sol:decodeExecuteCall()`, `src/ClankerGateCore.sol:decodeExecuteCallMemory()`

**Description:**
When decoding `execute(address,uint256,bytes)` wrappers to inspect the underlying call flow, `ClankerGateCore` explicitly assumes tightly packed ABI encoding by hardcoding absolute offsets. Specifically, it reads the `dataLength` from offset `100` instead of reading it from the dynamically-resolved `dataOffset` pointer.

**Security Impact:**
An attacker can craft a non-canonical, ABI-encoded `UserOperation` wherein `dataOffset` (the pointer indicating where dynamic data actually starts) points to a different location (e.g., offset 200). The validator module extracts `dataLength` from the hardcoded offset 100, checking the constraints perfectly based on that length. However, when the target `execute()` function is ultimately executed by the EVM on the Smart Account, the EVM respects the dynamic pointer at 200, bypassing the length restrictions derived from offset 100. This complete divergence between simulation (what is validated) and execution (what is executed) allows attackers to seamlessly bypass all `ParamRule` rules.

**Recommendation:**
Refactor the parsing logic in `decodeExecuteCall()` and `decodeExecuteCallMemory()` to correctly resolve the dynamic length based on the `dataOffset` pointer:
```solidity
    uint256 dataOffset = uint256(bytes32(callData[68:100]));
    uint256 lengthPointerOffset = 4 + dataOffset;
    uint256 dataLength = uint256(bytes32(callData[lengthPointerOffset:lengthPointerOffset+32]));
```

---

### [CG-13] O(N) Byte-by-Byte Calldata Copy Causes User Self-DoS on Large Payloads

**Severity:** LOW
**Location:** `src/ClankerGate7579.sol:validateUserOp()`

**Description:**
In `ClankerGate7579.sol`, when unwrapping an `execute()` call using Memory wrappers, the contract manually copies the payload element-by-element inside a `for` loop (`innerCallData[i] = callData[innerOffset + i]`).

**Security Impact:**
Because this iteration occurs within the validation bounds (simulation phase), users supplying legitimately large calldata payloads (e.g. rollups, complex batched operations) will cause the bundler to hit its `verificationGasLimit` during the O(N) loop. This forces an Out-Of-Gas revert during simulation, effectively constituting a Denial of Service against the user's *own* valid payloads. It avoids classifying as an amplification attack since the bundler imposes strict validation gas caps.

**Recommendation:**
Rely on `mcopy` (Shanghai upgrade) or the identity precompile to duplicate memory locations dynamically instead of manual block iteration.

---


### [CG-15] Incorrect Bit Shift in `_packValidationData` Corrupts ERC-4337 Timestamps

**Severity:** HIGH
**Location:** `src/ClankerGate4337.sol:_packValidationData()` (L182), `src/ClankerGate7579.sol:_packValidationData()` (L368)

**Description:**
The ERC-4337 packed validation format places `validUntil` at bits 160–207 and `validAfter` at bits 208–255. The implementation shifts `validAfter` left by `192` instead of `208`, causing `validAfter` to overlap with the upper half of `validUntil`'s bit range, corrupting both timestamp values when the EntryPoint decodes them.

**Vulnerable Code:**
```solidity
return (uint256(validUntil) << 160) | (uint256(validAfter) << 192) | (sigFailed ? 1 : 0);
//                                                         ^^^— should be 208
```

**Impact:** EntryPoint reads corrupt timestamps; valid UserOps may be rejected or invalid ones accepted based on time.

**Recommendation:**
```solidity
return (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
```

---


### [CG-18] Domain Separator Uses `permission.target` Instead of `address(this)` — Cross-Contract Replay

**Severity:** HIGH
**Location:** `src/ClankerGateCore.sol:hashPermission()` (L340–346)

**Description:**
The EIP-712 domain separator in `hashPermission()` uses `permission.target` (the call destination) as the `verifyingContract` instead of `address(this)` (the ClankerGate validator). Merkle permission hashes are therefore identical across all ClankerGate validator instances on the same chain — a proof valid for one validator works against any other.

**Vulnerable Code:**
```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    DOMAIN_SEPARATOR_TYPEHASH,
    keccak256("ClankerGate"),
    keccak256("1"),
    permission.chainId,
    permission.target  // ← wrong: should be address(this)
));
```

**Recommendation:**
```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    DOMAIN_SEPARATOR_TYPEHASH,
    keccak256("ClankerGate"),
    keccak256("1"),
    block.chainid,
    address(this)    // ← bind to this validator instance
));
```

---

### [CG-19] Policy Nonce Absent from Permission Hash — singleUse State Desync on Policy Rotation

**Severity:** MEDIUM
**Location:** `src/ClankerGateCore.sol:hashPermission()` (L330–338), `hashPermissionWithAccount()` (L355–356)

**Description:**
`usedPermissionHashes` tracks consumed `singleUse` permissions via `hashPermissionWithAccount`, which does not include the policy generation nonce. If an account rotates policy and re-adds a previously consumed permission, the mapping incorrectly blocks the re-granted permission because the hash is identical to the historic used entry.

**Recommendation:**
Include the current policy nonce in `hashPermissionWithAccount`:
```solidity
function hashPermissionWithAccount(
    address account,
    uint256 policyNonce,  // ← add nonce
    Permission memory permission
) internal pure returns (bytes32) {
    return keccak256(abi.encode(account, policyNonce, hashPermission(permission)));
}
```

---


### [CG-20b] Delegatecall Whitelist Not Cleared on Policy Rotation

**Severity:** LOW
**Location:** `src/ClankerGateSafe.sol:delegatecallWhitelist` (L62)

**Description:**
`delegatecallWhitelist[safe][target]` entries persist indefinitely and are never bulk-cleared when a Safe rotates its policy root. A stricter new policy root that revokes a previously whitelisted delegatecall target has no mechanism to automatically clear `delegatecallWhitelist` — the Safe owner must manually call `setDelegatecallWhitelist(safe, target, false)` for each revoked target. Missed entries remain permanently exploitable.

**Recommendation:**
Add a versioned whitelist tied to the policy nonce, or add a `clearDelegatecallWhitelist` bulk-clear function callable only by the Safe.

---

### [CG-23] Prefer Custom Errors Over `require`

**Severity:** LOW / GAS
**Location:** `src/ClankerGateSafe.sol` (L112, L125, L135, L146), `src/ClankerGate4337.sol` (L74)

**Description:**
The core library cleanly uses custom errors, but the outer entrypoint contracts still use legacy `require` statements. Custom errors are cheaper to deploy, cheaper at runtime on revert, and easier for indexers to decode.

**Recommendation:**
Replace `require` statements with custom errors.

---

### [CG-24] Loop Optimization: `++i` vs `i++` and Explicit Zero Initialization

**Severity:** GAS / INFO
**Location:** All loop headers in `ClankerGateCore.sol` and `ClankerGate7579.sol`

**Description:**
All loops use `for (uint256 i = 0; i < len; i++)`. Explicitly declaring `i = 0` costs extra gas over `uint256 i;`, and post-increment (`i++`) costs more than pre-increment (`++i`) due to temporary variable allocation.

**Recommendation:**
Refactor loops to `for (uint256 i; i < len; ++i)`.

---

### [CG-25] Floating Pragmas in Production Contracts

**Severity:** INFO
**Location:** All `.sol` files (L2)

**Description:**
The contracts use floating pragmas (`pragma solidity ^0.8.20;`). Production contracts should be deployed with strict pragmas to ensure the exact compiler version used in testing is used for deployment.

**Recommendation:**
Lock pragma versions (e.g. `pragma solidity 0.8.20;`).

---

### [CG-26] Missing `@custom:security-contact`

**Severity:** INFO
**Location:** All `.sol` files

**Description:**
The NatSpec documentation does not define a security contact. Whitehats need a canonical way to disclose vulnerabilities confidentially.

**Recommendation:**
Add a `@custom:security-contact` tag to the contract docstrings.

### [CG-21] Unsigned Comparison Type-Confusion in `OP_GT`/`OP_LT` for Signed Parameters

**Severity:** MEDIUM
**Location:** `src/ClankerGateCore.sol:compareRule()` (L280–284)

**Description:**
`OP_GT`, `OP_LT`, `OP_GTE`, and `OP_LTE` compare `bytes32` values as **unsigned integers**. If a policy creator applies these operators to ABI-encoded `int256` parameters (e.g., a `slippage` limit or signed deadline), the comparison silently uses wrong semantics. Negative `int256` values encode as large unsigned numbers (e.g., `-1 = 0xFFFF...FFFF`), so `OP_GT(threshold=0)` on a signed parameter would always pass for negative values — precisely the values the policy intended to block.

`OP_SGT` and `OP_SLT` exist for signed comparison but there is no enforcement mechanism ensuring they are selected for signed-type parameters.

**Recommendation:**
Add documentation clearly stating that `OP_GT`/`OP_LT`/`OP_GTE`/`OP_LTE` are for unsigned values and `OP_SGT`/`OP_SLT` must be used for signed parameters. Consider adding a type tag field to `ParamRule` that is validated against the ABI type of the target parameter at policy construction time.

---

### [CG-22] `setPolicyRoot` Allows Arbitrary `IAccount(account).owner()` External Call

**Severity:** LOW
**Location:** `src/ClankerGate4337.sol:setPolicyRoot()` (L74)

**Description:**
`setPolicyRoot(address account, bytes32 root)` authorizes the caller by checking `msg.sender == IAccount(account).owner()`. Since `account` is fully caller-controlled, any attacker can supply a contract they deployed whose `owner()` returns their own address. This lets an attacker:
1. Write arbitrary entries into `policyRoots` for addresses they control
2. Increment `nonces` for those addresses freely
3. Emit arbitrary `PolicyRootSet` events, polluting indexer/event logs

No legitimate user's policy is affected since modifying `policyRoots[attackerContract]` does not impact real accounts.

**Recommendation:**
Restrict `setPolicyRoot` to only allow `account` values that are `msg.sender` itself, or validate that real accounts must be pre-registered. Alternatively, accept this as a known limitation since the worst case is event log noise.
