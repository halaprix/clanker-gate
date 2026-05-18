# ClankerGate Security Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use flywheel + subagent-driven-development to implement bead-by-bead.

**Goal:** Refactor ClankerGate contracts to elite security/gas standards without altering core logic or external interfaces.

**Architecture:** 10 independent beads, each one commit. Order respects dependency graph: struct packing → reentrancy → assembly → require syntax → domain separator → memory optimization → return bombs → msg.value → EIP docs.

**Tech Stack:** Solidity 0.8.35, Foundry, Solady (ReentrancyGuardTransient), OpenZeppelin (MerkleProof, ECDSA)

---

## Bead Dependency Graph

```
bd-01 (lock pragmas) ─────────────────────────────────────────────┐
                                                                    │
bd-02 (struct packing) ──► bd-03 (transient reentrancy)             │
                                 │                                  │
                                 ▼                                  │
                           bd-04 (assembly audit) ◄─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              bd-05 (require)  bd-06 (DOMAIN)  bd-08 (return bombs)
                    │            │
                    ▼            ▼
              bd-07 (validateUserOp memory)
                    │
                    ▼
              bd-09 (msg.value DELEGATECALL)
                    │
                    ▼
              bd-10 (EIP compliance docs)
```

---

### Bead 01: Lock Pragma to 0.8.35

**Files:** All 21 .sol files in src/, test/, script/

- [ ] Replace `pragma solidity ^0.8.35;` → `pragma solidity 0.8.35;` in all .sol files
- [ ] `forge build` — verify clean
- [ ] `forge test` — all 147 pass
- [ ] Commit: `chore: lock Solidity pragma to 0.8.35`

### Bead 02: Pack Structs for Gas

**Files:** `src/ClankerGateCore.sol`, `src/ClankerGateSafe.sol`, `src/ClankerGate7579.sol`

**Permission struct** (Core):
- Move `ParamRule[] rules` to END of struct (after all fixed fields)
- Reorder: `target(20) | selector(4) | validAfter(6)` → slot 0, `validUntil(6) | singleUse(1)` → slot 1, `chainId` → slot 2, `maxValue` → slot 3, `authorizedCaller(20)` → slot 4, `rules` pointer → slot 5
- Result: 6 fixed slots (same count, but better cache locality for fixed fields, `rules` access doesn't fragment)

**CallerAuth struct** (Safe):
- Change `whitelistVersion` from `uint256` → `uint248`
- Pack: `policyRoot(32)` → slot 0, `nonce(32)` → slot 1, `whitelistVersion(248) | enabled(1)` → slot 2
- Saves: 1 slot (4 → 3)

**AccountConfig struct** (7579):
- Pack: `policyRoot(32)` → slot 0, `nonce(32)` → slot 1, `owner(20) | installed(1)` → slot 2, `signatureValidator(20)` → slot 3
- Same slot count (4), but `installed` now with `owner` for better grouping

- [ ] Apply struct reordering
- [ ] Update all field accesses (especially whitelistVersion type change affects comparisons)
- [ ] `forge build` + `forge test` — verify 147 pass
- [ ] Commit: `gas: pack Permission/CallerAuth/AccountConfig structs`

### Bead 03: Transient Reentrancy Guard

**Files:** `src/ClankerGateSafe.sol`, `foundry.toml`, `.gitmodules` (if needed)

- [ ] Add Solady as git submodule: `forge install Vectorized/solady`
- [ ] Import `{ReentrancyGuardTransient} from "solady/src/utils/ReentrancyGuardTransient.sol"`
- [ ] Replace storage-based `nonReentrant` modifier with Solady's:
  ```solidity
  // Remove:
  uint256 private constant _NOT_ENTERED = 1;
  uint256 private constant _ENTERED = 2;  
  uint256 private _reentrancyStatus = _NOT_ENTERED;
  modifier nonReentrant() { ... }
  
  // Add:
  import {ReentrancyGuardTransient} from "solady/src/utils/ReentrancyGuardTransient.sol";
  // Use ReentrancyGuardTransient's nonReentrant modifier
  ```
- [ ] `forge build` + `forge test`
- [ ] Verify gas improvement on execTransaction
- [ ] Commit: `refactor: use Solady ReentrancyGuardTransient in ClankerGateSafe`

### Bead 04: Audit & Harden Assembly Blocks

**Files:** `src/ClankerGate4337.sol`, `src/ClankerGate7579.sol`, `src/ClankerGateCore.sol`

Issues found:
1. **`_getOwner` (4337)** and **`_assertCallerIsAccountOrOwner` (4337)** and **`_getExpectedSigner` (7579)**: Use `mload(0x40)` (free memory pointer) as scratch space for function selector + staticcall output. This is fragile — external calls could corrupt the free memory pointer.

   **Fix:** Use Solidity's reserved scratch space at `0x00-0x3f` instead:
   ```solidity
   assembly {
       mstore(0x00, 0x5c60da1b00000000000000000000000000000000000000000000000000000000)
       let success := staticcall(gas(), account, 0x00, 0x04, 0x00, 0x20)
       if success {
           owner := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
       }
   }
   ```

2. **`decodeExecuteCallMemory` (Core)**: Assembly reads `padding` from `mload(add(callData, 36))` which is bytes 4-36 in the data (selector + address). The address starts at byte 4, and the padding check reads bytes 4-16. This is correct. `targetBytes` from `mload(add(add(callData, 32), 16))` = data start + 16 = bytes 16-48 (address). Correct.

3. **`compareRule` signed comparison (Core)**: `actualSigned := actual` and `expectedSigned := expected` — this is a no-op cast at the assembly level (bytes32 → int256 preserves the bit pattern). Correct for Solidity.

- [ ] Apply scratch space fix to all 3 assembly blocks
- [ ] `forge build` + `forge test`
- [ ] Commit: `security: use memory scratch space in assembly, not free memory pointer`

### Bead 05: `require(condition, CustomError())` Syntax

**Files:** All 4 contracts

Convert 9 instances of `if (condition) revert CustomError()` → `require(condition, CustomError())`:

| File | Line | Current | New |
|------|------|---------|-----|
| Core | 292 | `if (values.length > MAX_IN_VALUES) revert TooManyValues(...)` | `require(values.length <= MAX_IN_VALUES, TooManyValues(...))` |
| Safe | 125 | `if (msg.sender != safe) revert MustBeCalledDirectlyBySafe()` | `require(msg.sender == safe, MustBeCalledDirectlyBySafe())` |
| Safe | 148 | same | same |
| Safe | 158 | same | same |
| Safe | 169 | same | same |
| 4337 | 211 | `if (msg.sender != sender) revert UnauthorizedCaller()` | `require(msg.sender == sender, UnauthorizedCaller())` |
| 4337 | 238 | `if (!success \|\| msg.sender != owner) revert UnauthorizedCaller()` | Split into two requires or keep as refactored assembly check |
| 4337 | 265 | `if (owner == address(0)) revert AccountHasNoOwner(...)` | `require(owner != address(0), AccountHasNoOwner(...))` |
| 7579 | 467 | same | same |

Note: `require(condition, CustomError())` is native in 0.8.26+. Error arguments must NOT use parentheses — `require(x, MyError(a))` not `require(x, MyError(a))` — actually in 0.8.26+ it IS `require(condition, CustomError(arg1, arg2))` without extra parens.

- [ ] Apply all 9 conversions
- [ ] `forge build` + `forge test`
- [ ] Commit: `refactor: use require(condition, CustomError()) syntax`

### Bead 06: Immutable DOMAIN_SEPARATOR

**Files:** `src/ClankerGateSafe.sol`, `src/ClankerGate4337.sol`, `src/ClankerGate7579.sol`, `src/ClankerGateCore.sol`

Current: `ClankerGateCore.hashPermission()` recomputes `domainSeparator` from `DOMAIN_SEPARATOR_TYPEHASH`, name, version, chainid, address(this) on every call.

Fix:
1. Add `bytes32 private immutable DOMAIN_SEPARATOR` to each contract
2. Compute in constructor: `DOMAIN_SEPARATOR = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, keccak256("ClankerGate"), keccak256("1"), block.chainid, address(this)))`
3. Add overloaded `hashPermission(Permission memory, bytes32 domainSeparator)` to Core library (or modify existing to accept pre-computed value)
4. Update call sites in Safe/4337/7579

- [ ] Add immutable DOMAIN_SEPARATOR to Safe, 4337, 7579
- [ ] Add domainSeparator parameter to Core.hashPermission
- [ ] Update all call sites
- [ ] `forge build` + `forge test` — especially hash computation tests
- [ ] Commit: `gas: cache DOMAIN_SEPARATOR as immutable`

### Bead 07: Minimize validateUserOp Memory — 4337

**Files:** `src/ClankerGate4337.sol`

Current: `validateUserOp` `abi.decode`s the full userOp (11 fields) into memory, allocating for all bytes/uint256 fields, even though only `sender` and `callData` are used.

Fix: Use assembly to extract only sender and callData from calldata:
```solidity
address sender;
bytes memory callData;
assembly {
    sender := calldataload(add(userOp.offset, 0))  // sender at offset 0
    // callData offset is at position 3*32=96 in the ABI encoding
    let callDataOffset := calldataload(add(userOp.offset, 96))
    let callDataLen := calldataload(add(userOp.offset, add(callDataOffset, 0)))
    callData := ... // allocate and copy from calldata
}
```

Actually, the UserOperation is ABI-encoded, so:
- Offset 0: sender (address, padded to 32 bytes)
- Offset 32: nonce (uint256)
- Offset 64: initCode offset (uint256 pointer)
- Offset 96: callData offset (uint256 pointer)
- ...

Since callData is a `bytes` dynamic type in the ABI, its encoding is: offset pointer (at position 96 in the tuple), then at that offset: length (32 bytes), then data.

The assembly fix:
```solidity
assembly {
    sender := calldataload(add(userOp.offset, 0))
    let cdOffset := calldataload(add(userOp.offset, 96))
    let cdLen := calldataload(add(userOp.offset, cdOffset))
    // Allocate memory for callData
    callData := mload(0x40)
    mstore(callData, cdLen)
    // Copy from calldata
    calldatacopy(add(callData, 32), add(userOp.offset, add(cdOffset, 32)), cdLen)
    mstore(0x40, add(add(callData, 32), cdLen)) // update free memory pointer
}
```

- [ ] Implement assembly-based callData extraction
- [ ] Remove full userOp abi.decode
- [ ] `forge build` + `forge test`
- [ ] Gas benchmark compare (before/after)
- [ ] Commit: `gas: minimize validateUserOp memory allocation in 4337`

### Bead 08: Return Data Bomb Protection

**Files:** `src/ClankerGate4337.sol`, `src/ClankerGate7579.sol`

Issue: Fallback in `_getOwner` (4337) and `_getExpectedSigner` (7579) uses high-level `account.staticcall(...)` which allocates memory for FULL return data. Malicious account could return massive payload.

Fix: Use low-level staticcall with bounded output (32 bytes) for the fallback too:
```solidity
// Replace:
(bool callSuccess, bytes memory returnData) = account.staticcall(
    abi.encodeWithSelector(IAccount(account).owner.selector)
);
if (callSuccess && returnData.length >= 32) {
    owner = abi.decode(returnData, (address));
}

// With:
assembly {
    mstore(0x00, 0x8da5cb5b00000000000000000000000000000000000000000000000000000000)
    let success := staticcall(gas(), account, 0x00, 0x04, 0x00, 0x20)
    if success {
        owner := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
    }
}
```

Note: After Bead 04, the primary assembly path uses scratch space 0x00 correctly. This bead fixes the FALLBACK path which currently uses high-level call.

- [ ] Replace high-level staticcall fallback with assembly in both contracts
- [ ] `forge build` + `forge test`
- [ ] Commit: `security: protect against return data bombs in owner() fallback`

### Bead 09: msg.value Double-Spending Guard for DELEGATECALL

**Files:** `src/ClankerGateSafe.sol`

Issue: When `operation == 1` (DELEGATECALL), the `value` parameter might be 0 but `msg.value` could be non-zero. The Safe's `execTransactionFromModule` preserves msg.value in DELEGATECALL context.

Fix: Add explicit `msg.value <= permission.maxValue` check for DELEGATECALL:
```solidity
// After existing value check (line 263-265):
if (value > permission.maxValue) {
    revert ValueExceedsPermission(value, permission.maxValue);
}
// Add DELEGATECALL-specific msg.value guard:
if (operation == 1 && msg.value > permission.maxValue) {
    revert ValueExceedsPermission(msg.value, permission.maxValue);
}
```

- [ ] Add msg.value check for DELEGATECALL
- [ ] Add test: DELEGATECALL with non-zero msg.value exceeding maxValue
- [ ] `forge build` + `forge test`
- [ ] Commit: `security: guard against msg.value double-spending in DELEGATECALL`

### Bead 10: EIP Compliance Documentation

**Files:** `SPEC.md` or new `EIP_COMPLIANCE.md`

- [ ] Document EIP-4337 compliance: validateUserOp return format, signature aggregation, entry point interaction
- [ ] Document EIP-7579 compliance: Module Type 1, onInstall/onUninstall lifecycle, isModuleInstalled
- [ ] Document EIP-1271 compliance: malleability resistance (magic value comparison to `isValidSignature.selector`)
- [ ] Verify no gaps against each EIP specification
- [ ] Commit: `docs: verify and document EIP-4337/7579/1271 compliance`

---

## Self-Review

1. **Spec coverage:** All 10 directives from Claude review mapped to beads.
2. **Placeholder scan:** No TBD/TODO — all code shown inline.
3. **Type consistency:** whitelistVersion type change (uint256→uint248) must update all comparisons in `setDelegatecallWhitelist`.
4. **Dependency chain:** Bead 02 (packing) must come before Bead 04 (assembly audit) because struct reordering could affect assembly offsets.

## Execution

**Approach:** Sequential (dependency chain requires order). Spawn subagent per bead.
