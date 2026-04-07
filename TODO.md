# clanker-gate Bug Fixes — TODO

## Status: IN PROGRESS

### CG-10 (TODO — NIE NAPRAWIANE)
- **File:** `src/ClankerGateCore.sol`
- **Issue:** W `execute()` funkcji `msg.value` nigdy nie jest sprawdzane przeciwko `permission.maxValue`
- **Fix:** Przed wykonaniem low-level call, sprawdź czy `msg.value <= permission.maxValue`. Jeśli `permission.maxValue == 0` i `msg.value > 0` → revert
- **Test:** Napisz test w `test/CG10_ValueValidation.t.sol`

### CG-05 ✅ NAPRAWIONE
- Sygnatura `validateUserOp` przywrócona do ERC-4337 standard

### Pozostałe (not started)
- [ ] CG-15: `validAfter << 192` zamiast `<< 208` w `_packValidationData`
- [ ] CG-18: Domain separator używa `permission.target` zamiast `address(this)`
- [ ] CG-01: Reentrancy — stan zapisywany przed wykonaniem w `validateUserOp`
- [ ] CG-06: `_decodeCallData` zawsze revertuje na PackedUserOperation v0.7
- [ ] CG-07: `signatureValidator` contract wallets zawsze fail (ECDSA zamiast EIP-1271)
- [ ] CG-03: Policy nonce nie w permission hash
- [ ] CG-27: Front-running w `claim()`
- [ ] CG-28: UnsafeDowncast w tokenId
- [ ] CG-12: Low-level call bez sprawdzenia zwracanej wartości
