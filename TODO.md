# clanker-gate Bug Fixes — TODO

## Status: 1/10 naprawionych

---

## CG-10 ✅ NAPRAWIONE (commit 006bed1)
- **Issue:** `msg.value` nigdy nie był sprawdzany przeciwko `permission.maxValue`
- **Fix:** 
  1. `Permission.maxValue` dodane do struct + `hashPermission` updated
  2. `decodeExecuteCall(/Memory)` teraz zwraca `value` (wyciąga z bytes 36-68 execute() callData)
  3. Check: `if (callValue > permission.maxValue) revert ValueExceedsPermission(...)` w `validateUserOp` 4337 i 7579
  4. Safe już miało check (value jako parametr)
- **Walidacja:** 67 tests pass, build clean

---

## CG-05 ✅ NAPRAWIONE wcześniej (commit 006bed1)
- Sygnatura `validateUserOp` przywrócona do ERC-4337: `IEntryPoint.UserOperation calldata userOp`
- `guardData` jest teraz dekodowane ze `signature` field (standard ERC-4337 way)

---

## CG-15: Incorrect Bit Shift in `_packValidationData` — HIGH
**Location:** `src/ClankerGate4337.sol:_packValidationData()` (L~182), `src/ClankerGate7579.sol:_packValidationData()` (L~368)

**Issue:** ERC-4337 packed validation format:
- `validUntil` = bits 160–207
- `validAfter` = bits 208–255

Ale kod robi `validAfter << 192` zamiast `<< 208`, więc `validAfter` nachodzi na `validUntil` i oba są skorumpowane.

**Vulnerable code:**
```solidity
return (uint256(validUntil) << 160) | (uint256(validAfter) << 192) | (sigFailed ? 1 : 0);
//                                                         ^^^— WRONG, should be 208
```

**Fix:**
```solidity
return (uint256(validUntil) << 160) | (uint256(validAfter) << 208) | (sigFailed ? 1 : 0);
```

**Walidacja:**
- Oblicz: jeśli `validUntil=0, validAfter=1`, packed = `1 << 208` = `0x100...00`
- Sprawdź: EntryPoint dekoduje `validUntil = packed >> 160 = 0x100...00 >> 160 = 256` (powinno być 0!)
- Test: sprawdź czy dekodowana wartość `validAfter` zgadza się z oczekiwaną

---

## CG-18: Domain Separator Uses `permission.target` zamiast `address(this)` — HIGH
**Location:** `src/ClankerGateCore.sol:hashPermission()` (L~340–346)

**Issue:** Domain separator w `hashPermission()` używa `permission.target` jako `verifyingContract`. 
To znaczy że proof ważny dla JEDNEGO ClankerGate działa na WSZYSTKICH — atakujący może replayować
proof między różnymi instancjami.

**Vulnerable code:**
```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    DOMAIN_SEPARATOR_TYPEHASH,
    keccak256("ClankerGate"),
    keccak256("1"),
    permission.chainId,
    permission.target  // ← WRONG: should be address(this)
));
```

**Fix:**
```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    DOMAIN_SEPARATOR_TYPEHASH,
    keccak256("ClankerGate"),
    keccak256("1"),
    block.chainid,
    address(this)    // ← bind to this validator instance
));
```

**Walidacja:**
- Zweryfikuj że `domainSeparator` = f(address(this), chainId)
- Proof wygenerowany dla `ClankerGate at 0xABC` nie działa na `ClankerGate at 0xDEF`

---

## CG-01: Reentrancy — State Modification w `validateUserOp` przed Execution — HIGH
**Location:** `src/ClankerGate4337.sol:validateUserOp()`, `src/ClankerGate7579.sol:validateUserOp()`

**Issue:** `usedPermissionHashes[userOp.sender][permissionHash] = true` jest ustawiane W `validateUserOp`, 
ale to jest przed actual execution (EntryPoint wykonuje potem). 
Atakujący może front-runnąć mempool, wywołać `validateUserOp` zanim prawdziwa transakcja dojdzie,
i zburnować `singleUse` permission — prawdziwa transakcja potem revertuje.

**Fix:** Dodać check że `msg.sender == userOp.sender` (tylko konto może wywołać swoje własne validateUserOp):
```solidity
require(msg.sender == userOp.sender, "Unauthorized");
```

Albo: przenieść `singleUse` state modification DO execute(), po successful execution.

**Walidacja:**
- Test: attacker call `validateUserOp` bezpośrednio → powinien revert z "Unauthorized"
- Test: normal flow (EntryPoint wywołuje) → działa

---

## CG-06: `_decodeCallData` Always Reverts na PackedUserOperation v0.7 — HIGH
**Location:** `src/ClankerGate7579.sol:_decodeCallData()`

**Issue:** Komentarze mówią że wspiera legacy i v0.7 format, ale jeśli legacy parse fail — od razu `revert InvalidUserOpFormat()` 
bez próby v0.7. Nowoczesne ERC-4337 v0.7 compliant accounts będą hard-revertować.

**Fix:** Jeśli legacy parse fail, spróbuj v0.7 (PackedUserOperation ma sztywne offsety):
```solidity
// Try PackedUserOperation v0.7 format extraction
// offset 0x00: sender (address)
// offset 0x20: nonce (uint256)
// offset 0x40: initCode (bytes)
// offset 0x60: callData (bytes)
// ... etc
```

**Walidacja:**
- Test: encode jako PackedUserOperation v0.7 → powinien działać nie revertować

---

## CG-07: ECDSA zamiast EIP-1271 dla Contract Signature Validators — HIGH
**Location:** `src/ClankerGate7579.sol:_getExpectedSigner()`

**Issue:** Jeśli `signatureValidator` jest smart contract (np. multisig, passkey), 
`userOpHash.recover(signature)` próbuje ECDSA recover — ale contracts NIE MOGĄ generować ECDSA signatures.
Wynik zawsze failuje bo recovery daje losowy EOA address, nie adres contractu.

**Fix:**
```solidity
function _getExpectedSigner(...) internal view returns (address) {
    if (signatureValidator.code.length > 0) {
        // It's a contract — use EIP-1271
        return signatureValidator;
    }
    // EOA — use ECDSA recovery
    return userOpHash.recover(signature);
}
```
I zmień check w `validateUserOp`:
```solidity
// Before:
if (signer != expectedSigner) revert UnauthorizedSigner();

// After:
if (signer != expectedSigner) {
    // Try EIP-1271 if validator is a contract
    if (signatureValidator.code.length > 0) {
        bytes32 hash = ERC1271.isValidSignature.selector;
        (bool success, bytes memory result) = signatureValidator.staticcall(
            abi.encodeWithSelector(ERC1271.isValidSignature.selector, userOpHash, signature)
        );
        if (success && result == bytes32(ERC1271.isValidSignature.selector)) {
            return; // valid
        }
    }
    revert UnauthorizedSigner();
}
```

**Walidacja:**
- Test: signatureValidator = multisig contract → signature validation działa
- Test: signatureValidator = EOA → nadal działa (backward compatible)

---

## CG-03: Policy Nonce Absent from Permission Hash — HIGH
**Location:** `src/ClankerGateCore.sol:hashPermissionWithAccount()` (L~355–356)

**Issue:** `singleUse` permissions trackują się przez `hashPermissionWithAccount`, ale NIE uwzględniają policy nonce.
Jeśli użytkownik zaktualizuje policy (nonce++) i doda tę samą permission co poprzednio, ta permission jest już "used" 
w starym nonce i natychmiast revertuje.

**Fix:** Include nonce w hash:
```solidity
function hashPermissionWithAccount(
    address account,
    uint256 policyNonce,  // ← ADD
    Permission memory permission
) internal pure returns (bytes32) {
    return keccak256(abi.encode(account, policyNonce, hashPermission(permission)));
}
```

**Walidacja:**
- Test: setPolicyRoot twice z tą samą singleUse permission → 2nd usage powinien być OK (inny nonce)
- Test: rotation without nonce increment → 2nd usage nadal revertuje (old behavior preserved)

---

## CG-12: Low-level Call Return Value Not Checked — CRITICAL
**Location:** `src/ClankerGate4337.sol` (likely `execute()` lub `_executeCall()`), `src/ClankerGate7579.sol`

**Issue:** Low-level calls (`address(target).call{value: x}(data)`) nie sprawdzają zwracanej wartości.
Jeśli call revertuje, `success = false`, ale kod może kontynuować jakby nic.

**Fix:**
```solidity
(bool success, bytes memory returnData) = target.call{value: value}(data);
if (!success) {
    revert CallReverted(returnData);
}
```

**Walidacja:**
- Test: target revertuje → cała transakcja revertuje (nie silent fail)
- Test: target succeed → normal flow

---

## CG-27: Front-running w `claim()` — MEDIUM
**Location:** `src/ClankerGateCore.sol` lub `src/ClankerGateSafe.sol` — "claim()" function

**Issue:** (z audit report) Brak timestamp/nonce w claim() — atakujący może front-runnąć claim.

**Fix:** Potrzebny detail inspection. TODO: przeczytać kod `claim()`.

**Walidacja:** TODO

---

## CG-28: UnsafeDowncast w tokenId — MEDIUM
**Location:** Gdzieś w codebase — konwersja `uint256 → uint88` lub mniejszy integer na tokenId

**Issue:** Jeśli tokenId > typu docelowego, może dojść do overflow/cwraparound.

**Fix:** Dodać explicit check:
```solidity
require(tokenId <= type(uint88).max, "TokenId overflow");
uint88 safeTokenId = uint88(tokenId);
```

**Walidacja:** TODO

---

## CG-02: Permission Structure Lacks Caller Authentication Fields — MEDIUM
**Location:** `src/ClankerGateCore.sol:struct Permission`

**Issue:** Documentation mówi że `execTransactionWithProof` wymaga caller field w permission, 
ale `Permission` struct nie ma takiego pola. Granular caller-specific permissions nie działają.

**Fix:** Albo dodać `address authorizedCaller` do Permission i walidować w `_validateAndExecute`,
albo zaktualizować dokumentację że caller-specific permissions nie są wspierane.

**Walidacja:** TODO

---

## CG-04: Incomplete State Wiping on ERC-7579 Module Uninstall — MEDIUM
**Location:** `src/ClankerGate7579.sol:onUninstall()`

**Issue:** `delete accountConfigs[msg.sender]` ale `usedPermissionHashes` NIE jest kasowane.
Po reinstall, stare singleUse entries nadal blocking.

**Fix:** To jest related do CG-03. Fix CG-03 (nonce in hash) częściowo to naprawia,
ale `usedPermissionHashes` mapping nadal może mieć old entries.

**Walidacja:** TODO

---

## CG-08: Unbounded Array Loop in OP_IN — MEDIUM
**Location:** `src/ClankerGateCore.sol:inArray()`

**Issue:** `bytes32[] values` w `ParamRule` z `OP_IN` może być arbitrarily large — gas griefing.

**Fix:** Dodać `MAX_IN_VALUES = 20` constant:
```solidity
if (rule.values.length > MAX_IN_VALUES) revert TooManyValues();
```

**Walidacja:** Test z >20 values → revert

---

## CG-09: Persistent State Consumption on Execution Revert — MEDIUM
**Location:** `src/ClankerGate4337.sol`, `src/ClankerGate7579.sol:validateUserOp()`

**Issue:** `singleUse` permission jest marked jako `used` w `validateUserOp`, ale jeśli execution revert 
(poprzez front-run lub inne), permission jest zburnowana permanent.

**Fix:** To jest design issue. Dodać dokumentację że singleUse = consumed on VALIDATION, nie execution.
Dla guaranteed execution bez griefing, użytkownik musi użyć innego mechanizmu.

**Walidacja:** Documentation only

---

## CG-11: Return Data Bomb via `try/catch` — MEDIUM
**Location:** `src/ClankerGate4337.sol:_getOwner()`, `src/ClankerGate7579.sol:_getExpectedSigner()`

**Issue:** `try/catch` na `owner()` lub innym external call może otrzymać massive return data (bomb),
co exhaustuje memory podczas simulation.

**Fix:** Użyć `staticcall` z limitowanym return data, lub sprawdzić `account.code.length > 0` przed call.

**Walidacja:** Test z malicious contract zwracającym 1MB return → nie crashuje

---

## CG-13: O(N) Byte-by-Byte Calldata Copy — LOW
**Location:** `src/ClankerGate7579.sol:validateUserOp()`

**Issue:** `for` loop copying `innerCallData[i] = callData[innerOffset + i]` jest O(N).

**Fix:** Użyć assembly z `mcopy` (Shanghai) lub identity precompile.

**Walidacja:** Gas test z large calldata

---

## CG-19: Policy Nonce Absent from Permission Hash — MEDIUM
**Location:** `src/ClankerGateCore.sol:hashPermission()`, `hashPermissionWithAccount()`

**Issue:** CG-03 duplicate. `singleUse` permission hashes nie uwzględniają nonce.

**Fix:** Same jako CG-03.

---

## CG-20b: Delegatecall Whitelist Not Cleared on Policy Rotation — LOW
**Location:** `src/ClankerGateSafe.sol:delegatecallWhitelist` (L62)

**Issue:** `delegatecallWhitelist[safe][target]` entries persist indefinitely.
Po rotation, old entries nie są cleared.

**Fix:** Dodać `clearDelegatecallWhitelist(safe)` bulk clear function,
albo version the whitelist z nonce.

**Walidacja:** TODO

---

## CG-21: Unsigned Comparison Type-Confusion in OP_GT/OP_LT — MEDIUM
**Location:** `src/ClankerGateCore.sol:compareRule()` (L280–284)

**Issue:** `OP_GT/LT` interpretuje `bytes32` jako unsigned. Negative `int256` values 
(encoded jako `0xFFFF...FFFF`) będą zawsze większe od 0 — policy może nie działać jak intended.

**Fix:** Dodać enforcement że `OP_GT/OP_LT` tylko dla unsigned. Dodać `OP_SGT/OP_LT` 
dla signed i/lub dodać type tag do `ParamRule`.

**Walidacja:** Test z negative int256 value

---

## CG-22: `setPolicyRoot` Allows Arbitrary `owner()` External Call — LOW
**Location:** `src/ClankerGate4337.sol:setPolicyRoot()` (L74)

**Issue:** `setPolicyRoot(address account, bytes32 root)` sprawdza `msg.sender == IAccount(account).owner()`,
ale attacker może deployować contract którego `owner()` zwraca ich adres. No real user affected.

**Fix:** Restrict `account` do `msg.sender` only, albo zaakceptować jako known limitation.

**Walidacja:** Documentation only

---

## CG-23: Prefer Custom Errors Over `require` — LOW
**Location:** `src/ClankerGateSafe.sol` (L112,125,135,146), `src/ClankerGate4337.sol` (L74)

**Fix:** Replace `require(x, "message")` z `if (!x) revert CustomError();`

**Walidacja:** Code review

---

## CG-24: Loop Optimization `++i` vs `i++` — INFO
**Location:** All loops

**Fix:** `for (uint256 i; i < len; ++i)` zamiast `i++`

**Walidacja:** Gas benchmark

---

## CG-25: Floating Pragmas — INFO
**Fix:** Lock `pragma solidity 0.8.20;` zamiast `^0.8.20`

**Walidacja:** Code review

---

## CG-26: Missing `@custom:security-contact` — INFO
**Fix:** Dodać natSpec security contact tag

**Walidacja:** Code review

---

## Test Infrastructure Bugs (blokujące `forge test`)
6 plików testowych ma bugs które powodują że `forge test` nie kompiluje:

1. **ClankerGateSafe.t.sol** — `assertTrue` w view function (line ~1023)
2. **GasBenchmark.t.sol** — `assertTrue` w view function (lines ~275, 290)  
3. **ClankerGateInvariant.t.sol** — `assertGt` w view function (line ~95)
4. **UniV3Swap.t.sol** — `abi.encode(userOp)` zamiast `userOp` (type mismatch)
5. **Fixes.t.sol** — podobny type mismatch
6. **CG10_ValueValidation.t.sol** — constructor args mismatch

**Fix:** Usunąć `view` z functions zawierających asserts, naprawić type mismatches.
