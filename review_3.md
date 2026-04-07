# 🔒 Contract-Level Audit — ClankerGate Implementations

**Contracts:** `ClankerGate4337`, `ClankerGate7579`, `ClankerGateSafe`  
**Date:** 2026-02-25  

> [!NOTE]
> This report covers **contract-specific** findings only. Issues inherited from `ClankerGateCore` (C-01 through L-04) still apply to all three contracts — see [audit_report.md](file:///home/halaprix/.gemini/antigravity/brain/37cc4b69-b64a-4d44-b590-b24acd56be44/audit_report.md).

---

## Summary Per Contract

| Finding | Severity | 4337 | 7579 | Safe |
|---------|----------|:----:|:----:|:----:|
| Events emitted before reverts (wasted gas) | 🟡 | ✅ | ✅ | ✅ |
| `singleUse` collision across accounts | 🔴 | ✅ | ✅ | ✅ |
| No `delegatecall` protection | 🟠 | — | — | ✅ |
| `execTransactionWithProof` has no caller check | 🔴 | — | — | ✅ |
| Non-standard ERC-7579 interface | 🟠 | — | ✅ | — |
| UserOp decoded manually from `bytes` | 🟠 | — | ✅ | — |
| Missing `owner()` fallback error handling | 🟡 | ✅ | ✅ | — |
| `setPolicyRoot` has no access control | 🟠 | ✅ | — | — |
| `validateCallData` returns `(false,0)` silently | 🟡 | ✅ | ✅ | — |
| Missing reentrancy guard | 🟡 | — | — | ✅ |
| `onInstall` allows re-installation overwrite | 🟠 | — | ✅ | — |

---

## 🔴 Critical Findings

### CROSS-01: `singleUse` Permission Hash Collision Across Accounts

**Affects:** All three contracts

All contracts share a single `usedPermissionHashes` mapping:
```solidity
mapping(bytes32 => bool) public usedPermissionHashes;
```

The permission hash is computed from `(target, selector, rules, validAfter, validUntil, chainId, singleUse)` — **there is no account/Safe address in the hash**. This means:

- **Account A** uses a `singleUse` permission → hash marked as used
- **Account B** has the **same** permission in their tree → it's now **blocked** even though Account B never used it

**Impact:** Cross-account denial of service. Any account can poison `singleUse` permissions for ALL other accounts that share the same permission set.

**Fix:** Include the account address in the hash:
```diff
- bytes32 permissionHash = ClankerGateCore.hashPermission(permission);
+ bytes32 permissionHash = keccak256(abi.encode(msg.sender, ClankerGateCore.hashPermission(permission)));
```

---

### SAFE-01: `execTransactionWithProof` Has No Caller Authorization

**Affects:** `ClankerGateSafe`

`execTransactionWithProof()` is intended as an "alternative pattern" where the proof itself authorizes the transaction. However, the Permission struct **does not contain the caller's address**, so:

1. Anyone can call `execTransactionWithProof()`
2. The Merkle proof only validates *what* transaction is allowed, not *who* can execute it
3. There is **no `msg.sender` check** at all

An attacker who observes a valid proof in the mempool (or obtains it off-chain) can front-run the legitimate caller and execute the same transaction, or can simply call this function directly since the proof is reusable (unless `singleUse`) and not bound to the caller.

**Impact:** Any EOA can execute arbitrary transactions through the Safe as long as they have a valid proof. Combined with `singleUse = false`, this is permanently exploitable.

**Fix:** Either:
1. Remove this function entirely, or
2. Add caller constraint to `Permission` struct, or
3. Require `isAuthorizedCaller` check here too

---

## 🟠 High Findings

### SAFE-02: No `delegatecall` Protection

**Affects:** `ClankerGateSafe`

`execTransaction()` and `execTransactionWithProof()` accept an `operation` parameter where `1 = DELEGATECALL`. There is **no validation** preventing `delegatecall` usage.

A `delegatecall` executes in the **context of the Safe**, meaning an attacker with a valid proof could:
- Modify the Safe's storage
- Drain all funds via `selfdestruct` (pre-Dencun) or storage manipulation
- Change owners, remove modules, etc.

```solidity
// This is passed directly to Safe without any validation:
success = ISafe(safe).execTransactionFromModule(to, value, data, operation);
```

**Fix:**
```solidity
require(operation == 0, "DELEGATECALL not allowed");
// Or whitelist specific targets for delegatecall
```

---

### 7579-01: `onInstall` Allows Silent Overwrite of Existing Config

**Affects:** `ClankerGate7579`

`onInstall()` does not check if the module is already installed:
```solidity
function onInstall(bytes calldata initData) external {
    // No check for config.installed == false
    config.owner = initOwner;
    config.policyRoot = initPolicyRoot;
    // ...
    config.installed = true;
}
```

If the account (or a malicious module with control of the account) calls `onInstall()` again, it silently overwrites the owner, policy root, and resets the nonce. This could be used to hijack an existing configuration.

**Fix:**
```solidity
require(!config.installed, "Already installed");
```

---

### 7579-02: UserOp Decoded Manually from Raw `bytes`

**Affects:** `ClankerGate7579`

The function signature is:
```solidity
function validateUserOp(
    bytes calldata userOp,  // Encoded UserOperation
    bytes32 userOpHash,
    bytes calldata guardData
) external returns (uint256 validationData)
```

The ERC-7579 standard expects validator modules to receive a **structured** `PackedUserOperation`, not raw `bytes`. The manual `abi.decode` of 10 fields is fragile and incompatible with:
- ERC-4337 v0.7 (`PackedUserOperation` format)
- Most account implementations that call validators with typed structs

This means the module likely **won't work** with any standard ERC-7579 account.

**Fix:** Use the standard interface:
```solidity
function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
) external returns (uint256 validationData)
```

---

### 4337-01: `setPolicyRoot` Has Insufficient Access Control

**Affects:** `ClankerGate4337`

```solidity
function setPolicyRoot(bytes32 root) external {
    policyRoots[msg.sender] = root;
    nonces[msg.sender]++;
    // ...
}
```

Anyone can call `setPolicyRoot` for their own address. This is fine **if** the contract only validates UserOps for smart accounts. But if the EntryPoint or another contract delegates validation to `ClankerGate4337` on behalf of an account, the `msg.sender` will be the EntryPoint, not the account. The root is then stored under the EntryPoint's address, not the account's.

Meanwhile, `validateUserOp` reads the root from `policyRoots[userOp.sender]`, which is the **account's** address. There's a disconnect — the account must call `setPolicyRoot` directly (not through the EntryPoint), which may not always be possible depending on account architecture.

**Fix:** Document the expected calling pattern, or allow the account owner to set roots:
```solidity
function setPolicyRoot(address account, bytes32 root) external {
    require(msg.sender == account || msg.sender == IAccount(account).owner(), "Unauthorized");
    policyRoots[account] = root;
}
```

---

## 🟡 Medium Findings

### CROSS-02: Events Emitted Before Reverts (Wasted Gas)

**Affects:** All three contracts

Throughout all contracts, events are emitted immediately before reverting:
```solidity
emit ValidationFailed(userOp.sender, ERR_INVALID_PROOF, 0);
revert InvalidProof();
```

Since a `revert` rolls back **all state changes including event logs**, these `emit` statements consume gas but produce no observable output. They are dead code.

**Fix:** Remove all `emit` calls that precede a `revert`, OR change the logic to `return 1` instead of reverting (following ERC-4337's convention where validators return `1` for invalid instead of reverting).

---

### CROSS-03: `validateCallData` Silent Failure for Selector Mismatch

**Affects:** `ClankerGate4337`, `ClankerGate7579`

When `validateCallData` returns `(false, 0)`, it means either:
- calldata is < 4 bytes, or
- the selector doesn't match

But the contracts check:
```solidity
(bool valid, uint256 ruleIndex) = ClankerGateCore.validateCallData(...);
if (!valid) {
    emit ValidationFailed(userOp.sender, ERR_RULE_VIOLATION, ruleIndex);
    return 1;  // or revert
}
```

`ruleIndex = 0` doesn't distinguish between "selector mismatch" and "first rule failed". The error code used is `ERR_RULE_VIOLATION` when the actual error might be `ERR_SELECTOR_MISMATCH`.

**Fix:** Return distinct error codes from `validateCallData`:
```solidity
uint8 constant INVALID_LENGTH = 1;
uint8 constant SELECTOR_MISMATCH = 2;
uint8 constant RULE_FAILED = 3;
```

---

### CROSS-04: Missing `owner()` Fallback Error Handling

**Affects:** `ClankerGate4337`, `ClankerGate7579`

Both contracts call `owner()` on the account to retrieve the expected signer:
```solidity
// 4337
address owner = IAccount(userOp.sender).owner();

// 7579
return IERC7579Account(account).owner();
```

If the account doesn't implement `owner()` (e.g., multi-sig, social recovery), this will **revert** with an unhelpful low-level error, bricking validation for that account.

**Fix:** Use `try/catch` or `staticcall` with return data validation.

---

### SAFE-03: Missing Reentrancy Guard

**Affects:** `ClankerGateSafe`

`execTransaction()` calls `ISafe(safe).execTransactionFromModule(...)`, which executes arbitrary external calls. If the target calls back into `ClankerGateSafe`, it could potentially:
- Re-enter `execTransaction` with the same permission (if not `singleUse`)
- Manipulate `isAuthorizedCaller` state mid-execution

With `singleUse = false`, the same permission can be used unlimited times, making reentrancy viable.

**Fix:** Add `ReentrancyGuard` or a custom lock:
```solidity
uint256 private _locked = 1;
modifier nonReentrant() {
    require(_locked == 1, "Reentrant");
    _locked = 2;
    _;
    _locked = 1;
}
```

---

### SAFE-04: `ISafe.isOwner()` External Call Trust Assumption

**Affects:** `ClankerGateSafe`

`setPolicyRoot`, `authorizeCaller`, and `deauthorizeCaller` all call `ISafe(safe).isOwner(msg.sender)` on a user-supplied `safe` address. If `safe` is a malicious contract, it can:
- Return `true` for any `msg.sender`, tricking the module into storing a policy root
- Later use this stored state to execute transactions through legitimate Safes

The attack: deploy a fake "safe" contract that returns `true` from `isOwner()`, set up authorization, then the attacker has entries in `authorizations` and `isAuthorizedCaller` for their malicious contract. While this doesn't directly affect real Safes, it pollutes the state.

**Fix:** Consider having Safe itself call the module functions (so `msg.sender == safe` is the primary check), or verify the Safe has this module enabled.

---

## Per-Contract Action Items

### `ClankerGate4337` — 5 items
| # | Severity | Finding | Fix Effort |
|---|----------|---------|------------|
| 1 | 🔴 | CROSS-01: singleUse hash collision | Low |
| 2 | 🟠 | 4337-01: setPolicyRoot access control | Low |
| 3 | 🟡 | CROSS-02: Events before reverts | Low |
| 4 | 🟡 | CROSS-03: Silent selector mismatch | Low |
| 5 | 🟡 | CROSS-04: `owner()` call may revert | Medium |

### `ClankerGate7579` — 6 items
| # | Severity | Finding | Fix Effort |
|---|----------|---------|------------|
| 1 | 🔴 | CROSS-01: singleUse hash collision | Low |
| 2 | 🟠 | 7579-01: onInstall allows overwrite | Low |
| 3 | 🟠 | 7579-02: Wrong UserOp format (won't work) | High |
| 4 | 🟡 | CROSS-02: Events before reverts | Low |
| 5 | 🟡 | CROSS-03: Silent selector mismatch | Low |
| 6 | 🟡 | CROSS-04: `owner()` call may revert | Medium |

### `ClankerGateSafe` — 7 items
| # | Severity | Finding | Fix Effort |
|---|----------|---------|------------|
| 1 | 🔴 | CROSS-01: singleUse hash collision | Low |
| 2 | 🔴 | SAFE-01: No caller check in `execTransactionWithProof` | Low |
| 3 | 🟠 | SAFE-02: No delegatecall protection | Low |
| 4 | 🟡 | CROSS-02: Events before reverts | Low |
| 5 | 🟡 | SAFE-03: Missing reentrancy guard | Medium |
| 6 | 🟡 | SAFE-04: `isOwner()` trust assumption | Medium |
| 7 | 🟡 | Uses string revert instead of custom error | Low |
