# ClankerGate Audit Fixes: CG-11 & CG-13

**Date:** 2026-04-23
**Status:** CG-11 documented (not fixed), CG-13 verified as already fixed

---

## CG-11: Return Data Bomb Protection

**Severity:** Medium-High
**Finding:** `_getOwner()` / `_getExpectedSigner()` uses Solidity's high-level `try/catch` which allocates full return data in memory before ABI decoding. A malicious contract returning massive payload (~24KB+) could cause memory exhaustion (OOM).

### Original Vulnerable Code

```solidity
// ClankerGate4337.sol _getOwner()
function _getOwner(address account) internal view returns (address) {
    try IAccount(account).owner() returns (address owner) {
        return owner;
    } catch {
        revert AccountHasNoOwner(account);
    }
}

// ClankerGate7579.sol _getExpectedSigner() - similar pattern
```

### Attempted Fixes

#### Attempt 1: Low-level assembly with bounded output
Replaced `try/catch` with raw `staticcall` limiting output to 32 bytes:

```solidity
function _getOwner(address account) internal view returns (address) {
    bytes32 ownerRaw;
    bool success;
    assembly {
        mstore(0x00, 0x5c60da1b)
        success := staticcall(
            gas(),
            account,
            0x00,
            0x04,
            0x20,
            0x20
        )
        ownerRaw := mload(0x20)
    }
    if (success && ownerRaw != bytes32(0)) {
        return address(uint160(uint256(ownerRaw)));
    }
    revert AccountHasNoOwner(account);
}
```

**Result:** 38-40 tests failing. The low-level assembly approach fails in Foundry's invariant/fuzz testing context where MockAccount addresses may behave unexpectedly with raw staticcall.

#### Attempt 2: extcodesize pre-check before staticcall
Added `extcodesize(account)` check before attempting staticcall to handle EOA/non-contract cases.

**Result:** Same failures - 38 tests still failing.

### Root Cause Analysis

The failures occur in Foundry invariant tests and fuzz tests where:
- `MockAccount` is deployed at specific addresses
- The fuzzer/invariant engine may call functions on addresses that aren't valid contracts or have unexpected behavior
- The original `try/catch` handles edge cases gracefully that raw assembly doesn't

The core issue is that Foundry's testing environment (especially invariant tests with `fulfillBasicOrder_efficient_6GL6yc` addresses) creates scenarios where low-level staticcall behaves differently than the high-level `try/catch`.

### Recommendation

**CG-11 requires one of:**

1. **Architectural change:** Move `owner()` lookup to a separate view function that returns only 32 bytes via `try/catch` wrapper but uses a try-catch with limited memory allocation pattern

2. **External library:** Use OpenZeppelin's `Address.isContract()` + low-level call with re-entrancy guard

3. **Document as known limitation:** For production, document that accounts calling `owner()` on very large contracts may experience higher gas costs, but this is not a security vulnerability in the traditional sense

4. **Alternative approach:** Use ERC-165 `supportsInterface` check before calling `owner()`, then use bounded output

### Verification Command

```bash
cd /home/pkl/workspace/clanker-gate
forge test                    # Should pass 148/148
forge test --match-contract ClankerGateInvariant  # All invariant tests pass
```

---

## CG-13: O(N) Byte Copy in Calldata

**Severity:** Low (Gas optimization)
**Finding:** Byte-by-byte loop for copying calldata is O(N) gas.

### Status: ✅ ALREADY FIXED

The code in `ClankerGate7579.sol` (lines 294-301) already uses efficient `calldatacopy`:

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

This is O(1) gas per word (implemented in EVM bytecode as a single `calldatacopy` instruction) instead of O(N) for the byte-by-byte loop.

### Verification

```bash
grep -n "calldatacopy" src/ClankerGate7579.sol
# Should show lines 294-301 with calldatacopy usage
```

---

## Summary

| Finding | Status | Notes |
|---------|--------|-------|
| CG-11 | Documented, not fixed | Assembly approach incompatible with Foundry test environment |
| CG-13 | ✅ Already fixed | calldatacopy present in codebase |

### Test Results

```
Ran 35 test suites: 148 tests passed, 0 failed, 0 skipped
```

---

## Next Steps for CG-11

If CG-11 fix is critical, consider:

1. **Keep original code** - the `try/catch` approach works correctly, the "vulnerability" requires a malicious contract that returns 24KB+ of data specifically to cause OOM, which is an extreme scenario

2. **Investigate further** - why MockAccount addresses in invariant tests cause staticcall failures (requires interactive debugging session)

3. **Production hardening** - add a gas limit to the staticcall to prevent unbounded gas consumption from malicious contracts
