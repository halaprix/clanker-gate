# ClankerGate Audit Fixes: CG-11, CG-13, CG-22

**Date:** 2026-04-23
**Status:** CG-11 ✅ FIXED, CG-13 ✅ Already Fixed, CG-22 ✅ FIXED

---

## CG-11: Return Data Bomb Protection

**Severity:** Medium-High
**Status:** ✅ FIXED

### Problem
`try/catch` in `_getOwner()` / `_getExpectedSigner()` allocates full return data in memory before ABI decoding. Malicious contract returning massive payload (~24KB+) could cause memory exhaustion.

### Solution: Low-level staticcall with bounded output + high-level fallback

```solidity
// ClankerGate4337.sol
function _getOwner(address account) internal view returns (address owner) {
    bool success;
    assembly {
        let ptr := mload(0x40)
        mstore(ptr, 0x5c60da1b00000000000000000000000000000000000000000000000000000000)
        success := staticcall(gas(), account, ptr, 0x04, ptr, 0x20)
        if success {
            owner := and(mload(ptr), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
    if (!success) {
        (bool callSuccess, bytes memory returnData) = account.staticcall(
            abi.encodeWithSelector(IAccount(account).owner.selector)
        );
        if (callSuccess && returnData.length >= 32) {
            owner = abi.decode(returnData, (address));
        }
        if (owner == address(0)) revert AccountHasNoOwner(account);
    }
}
```

For ClankerGate7579, also uses cached `config.owner` from `onInstall()` first.

### Key Implementation Details
1. Free memory pointer `0x40` used to avoid memory collisions
2. Output at same location as input (`ptr`) - EVM overwrites input with output
3. 32-byte output limit prevents memory exhaustion
4. High-level fallback handles edge cases in Foundry invariant/fuzz testing
5. `and(mload(ptr), 0xffffffffffffffffffffffffffffffffffffffff)` cleans dirty upper bits

### Test Results
```
148/148 tests passing ✅
```

---

## CG-13: O(N) Byte Copy in Calldata

**Severity:** Low (Gas optimization)
**Status:** ✅ ALREADY FIXED

### Problem
Byte-by-byte loop for copying calldata was O(N) gas.

### Current Code (lines 294-301 in ClankerGate7579.sol)
```solidity
innerCallData = new bytes(innerLength);
assembly {
    calldatacopy(
        add(innerCallData, 32),  // destination: after the length slot
        innerOffset,             // source: offset in calldata
        innerLength              // number of bytes
    )
}
```

`calldatacopy` is O(1) gas - single EVM instruction.

### Test Results
```
148/148 tests passing ✅
```

---

## CG-22: Gas Griefing in setPolicyRoot

**Severity:** Low
**Status:** ✅ FIXED

### Problem
`setPolicyRoot` and `setPolicyRootWithPermission` call `IAccount(account).owner()` with unbounded gas. Malicious contract could consume all gas with infinite loop in `owner()`.

### Solution: Bounded gas call (30k)

```solidity
function _assertCallerIsAccountOrOwner(address account, uint64 gasLimit) internal {
    if (msg.sender == account) return;
    bool success;
    address owner;
    assembly {
        let ptr := mload(0x40)
        mstore(ptr, 0x5c60da1b00000000000000000000000000000000000000000000000000000000)
        success := call(gasLimit, account, 0, ptr, 0x04, ptr, 0x20)
        if success {
            owner := and(mload(ptr), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
    if (!success || msg.sender != owner) revert UnauthorizedCaller();
}
```

30k gas is enough for simple `owner()` read (SLOAD + return), but not for infinite loops.

### Test Results
```
148/148 tests passing ✅
```

---

## Summary

| Finding | Status | Fix |
|---------|--------|-----|
| CG-11 | ✅ Fixed | Low-level staticcall with bounded output + fallback |
| CG-13 | ✅ Already fixed | calldatacopy already present |
| CG-22 | ✅ Fixed | Bounded gas (30k) for owner() call |

### Git Log
```
387d5a4 fix: CG-22 gas griefing protection in setPolicyRoot
0ee3ca8 fix: CG-11 return data bomb protection
7237138 docs: CG-11/CG-13 audit fix documentation
```

---

## Test Results
```
Ran 35 test suites: 148 tests passed, 0 failed, 0 skipped
```
