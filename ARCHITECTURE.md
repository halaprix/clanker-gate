# ClankerGate v1 - Architectural Master Plan

**Status:** Ready for Implementation  
**Date:** February 2026

---

## 1. Executive Summary

ClankerGate is a stateful validator module for Smart Accounts (ERC-4337/ERC-7579) that enables defining granular transaction policies without handing over the full private key to an external executor.

| | Without ClankerGate | With ClankerGate |
|---|---|---|
| **Security** | Executor receives full private key — one breach = lost account | Executor operates only within policy bounds defined by the owner |
| **Auditability** | No trace of what executor actually did | Every operation verified on-chain, result immutably in block |
| **Flexibility** | Separate adapter per protocol (UniV3Guard, AaveGuard...) | Single contract handles any protocol — just needs ABI |
| **Gas Cost** | ABI decoding on-chain: 20k–50k gas / rule | calldataload offset: ~800 gas / rule — >80% savings |

### Primary Use Cases
- **DeFi automation** — swap bot operates within strict amount limits without access to entire wallet
- **Paymaster delegation** — system pays for gas only on approved operations
- **Multisig lite** — multiple executors with different policies on the same account
- **Cross-chain bridges** — limiting tokens and destination networks

---

## 2. Key Architectural Decision

> **Byte offsets exist solely as an internal execution format. Developers never work with offsets directly.**

| Layer | Approach | Justification |
|--------|-----------|---------------|
| **On-chain** | Offset-based validation — raw calldataload | Minimal gas, zero ABI parsing attack surface, permanent without upgrades |
| **Off-chain SDK** | ABI-aware Policy DSL → compiled to offsets | Excellent DX — developer writes `params.amountIn`, not offset 128 |
| **Future Changes** | Off-chain only — new compiler / DSL versions | On-chain contract never requires upgrade or migration |

---

## 3. System Architecture

### 3.1 Data Flow

```
OFF-CHAIN                                    ON-CHAIN
─────────────────────────────────           ─────────────────────────
1. Developer defines policy via DSL    
   policy.allow().to(ROUTER).")
   .wherefn("exactInput("params.amountIn").lte(1 ETH)      
                                                
5. EntryPoint.validateUserOp()
2. Policy Compiler                            
   (ABI → selectors → offsets → Permission)  
                                              6. ClankerGate.validateUserOp()
3. Merkle Tree Builder                        
   (Permission structs → root + proof)       7. Merkle proof verification
                                             
4. UserOp Builder attaches proof to signature 8. calldataload at offsets → rule comparison
                                             
→ One transaction setPolicyRoot(root)       9. Owner ECDSA verification → ✓ / ✗
  saves root on-chain                        
```

### 3.2 Components and Responsibilities

#### Component 1 — ClankerGate.sol (on-chain)

Stateful validation engine. Stores mappings: `policyRoots`, `nonces`, `usedPermissionHashes`, `isAuthorizedCaller`, `delegatecallWhitelist`.

| Validation Step | Details + Gas Cost |
|----------------|------------------------|
| 1. Merkle Proof | Whether given policy is in tree approved by owner. ~5,000 gas |
| 2. Calldata Rules | `calldataload(offset)` → comparison with rules (EQ, GT, LT, GTE, LTE). ~800 gas / rule |
| 3. ECDSA Signature | Whether account owner signed this specific UserOperation. ~3,000 gas |
| Owner Check | `IAccount(userOp.sender).owner()` — verification that signer is actual owner |

**Contract DOES NOT:** parse ABI, know protocol structures, perform dynamic decoding, require upgrades.

```solidity
struct ParamRule { uint256 offset; uint8 op; bytes32 value; }
struct Permission { address target; bytes4 selector; ParamRule[] rules; }
// signature = abi.encode(bytes32[] proof, Permission permission, bytes userSignature)
```

#### Component 2 — Policy Compiler (off-chain, primary DX)

Transforms human-readable policy description into contract-executable format. ClankerGate remains unchanged regardless of compiler version.

```typescript
// INPUT (Developer writes)
policy.allow()
   .to(UNI_V3_ROUTER)
   .fn("exactInput")
   .where("params.amountIn").lte(1 ETH)
   .where("params.recipient").eq(user)

// OUTPUT (Permission struct)
{
  selector: 0xc04b8d59,
  target: 0x...,
  rules: [
    { offset: 128, op: LTE, value: 1e18 },
    { offset: 64,  op: EQ,  value: user }
  ]
}
```

Compiler: parses ABI → resolves selector → resolves struct layout → computes calldata offsets → generates Permission struct.

#### Component 3 — clanker-gate-client SDK (TypeScript)

| SDK Module | Responsibility |
|-----------|------------------|
| ABI Registry | Maps named function fields (`params.recipient`) to specific byte offsets. One registry per project. |
| Policy Compiler | ABI → offsets. Handles nested structures, dynamic types, ABIv2 padding. |
| Permission.from() | Fluent builder — creates Permission from field names, zero magic numbers. |
| ClankerPolicyBuilder | Aggregates multiple policies into single Merkle tree, generates root and proof. |
| UserOp Builder | Automatically attaches matching proof to signature field — developer never touches proof manually. |
| Off-chain Simulator | Tests UserOp before sending. Returns readable errors: "amountIn exceeds limit of 1 ETH". |
| Codegen CLI | Exports Solidity snippets to tests — eliminates TS ↔ Solidity desync. |

**Stack:** viem + merkletreejs. No ethers.js dependency.

### 3.3 Trust Model

| Component | Trusted? | Justification |
|-----------|----------|--------------|
| ClankerGate.sol | Yes — trustless | Deterministic on-chain logic, Merkle root immutable |
| Policy Compiler | No — non-trusted | Bad output → validation fails (safe fail). Cannot escalate privileges. |
| Merkle Root | Yes | Set by account owner via `setPolicyRoot()` — out of executor's reach |
| Global Root (optional) | Depends on operator | Requires trust in publishing entity. Architect decision — see section 6. |

**Failure modes:**
- `root == 0` → all transactions blocked (fail-safe)
- proof invalid → transaction rejected
- rule mismatch → transaction rejected
- No partial execution risk — validation is atomic

---

## 4. Gas Characteristics

| Operation | This System | ABI Decode On-chain | Hardcoded Guard |
|----------|------------|---------------------|-----------------|
| Base validation | ~20,000 gas | ~20,000 gas | ~15,000 gas |
| Per rule | ~800 gas | ~20,000–50,000 gas | N/A (hardcoded) |
| Merkle proof | ~5,000 gas | N/A | N/A |
| **Typical (5 rules)** | **~29,000 gas** | **~120,000–270,000 gas** | **~15,000 gas** |
| Flexibility | Any protocol | Any protocol | One protocol |
| Upgrade for new DEX | Not required | Not required | New deployment |

> **NOTE:** `abi.decode(userOp.signature, ...)` allocates memory proportionally to rule count. With 10 rules + Merkle depth 20 → 1,000–3,000 gas overhead. Benchmark before deciding on packed encoding (see section 6 — Decision 2).

---

## 5. Risk Registry

| Risk | Severity | Status | Action |
|--------|--------|--------|-------|
| **Offset calculation error** — incorrect absolute offset inside `execute()` wrapper. Could pass malformed transaction. | CRITICAL | Phase 0 | Correct formula: `funcDataOffset = 4 + abiRelativeOffset + 4`. Cover with Foundry fuzz tests before audit. |
| **Missing account owner verification** — ECDSA verified, but no check if `signer == owner`. | HIGH | Phase 0 | Add `IAccount(userOp.sender).owner()` before mainnet. Interface depends on SmartAccount implementation. |
| **SDK offset calculation errors** — risk of funds locked (transactions revert). | HIGH | Phase 0–1 | SDK tests comparing computed offsets with actual calldata from Foundry/Anvil. Mandatory E2E test before testnet. |
| **Missing granular debug events** — validation returns binary 0/1. | MEDIUM | Phase 1 | Add event `ValidationFailed(address account, uint8 reason, uint256 ruleIndex)`. Zero cost in production. |
| **External contract ABI changes** (e.g., new UniV3 Router). | LOW | Constant | System based on target address whitelisting. New router = new policy = new root. No risk to existing accounts. |
| **Merkle root loss** — inability to execute transactions. | LOW | Constant | Recoverable via Smart Account social recovery. Document procedure for users. |

---

## 6. Implementation Plan

### PHASE 0 — Hardening and Critical Fixes (Week 1–2)
Before anything goes to external testing or audit.

- [x] Solidity: Implement `ClankerGate.sol` with correct offset formula from day one
- [x] Solidity: Add `IAccount(userOp.sender).owner()` — owner verification
- [x] Foundry: Unit tests for edge cases — zero root, empty rule list, offset outside calldata bounds
- [x] Foundry: Fuzz testing calldata (`forge fuzz`) for `_validateCallData`
- [x] SDK: ABI Registry for UniV3 `exactInput` + `exactInputSingle` (minimal v1 scope)
- [x] SDK: Tests comparing computed offsets with actual calldata from Anvil

### PHASE 1 — Testnet and Full SDK (Week 3–4)

- [ ] Deploy `ClankerGate.sol` on Sepolia with SimpleAccount as test SmartAccount
- [ ] Bundler integration (Pimlico or Alchemy AA — EIP-4337 v0.7, do not mix with v0.6)
- [ ] SDK: complete Policy Compiler, `Permission.from()`, `ClankerPolicyBuilder`, Off-chain Simulator
- [ ] Add event `ValidationFailed(address, uint8 reason, uint256 ruleIndex)` + verification via `simulateValidation`
- [ ] Mandatory E2E test: UniV3 swap within policy bounds → passes / above limit → rejected

### PHASE 2 — Security Audit (Week 5–8)

- [ ] Formal Solidity audit (Spearbit or Sherlock recommended)
- [ ] Foundry fuzz testing — full validation path coverage
- [ ] Invariant verification: guard never passes if `root == 0`
- [ ] Gas benchmark: measure `abi.decode` vs packed encoding → decision before mainnet

### PHASE 3 — Mainnet (Post-Audit)

- [ ] Deploy on Ethereum Mainnet and/or L2 (Base, Optimism)
- [ ] Register with ERC-4337 EntryPoint as trusted validator
- [ ] On-chain monitoring: alert on `ValidationFailed` spike with `reason == ROOT_NOT_SET`
- [ ] Integration with permissionless.js, zeroDev SDK
- [ ] Complete `clanker-gate-client` SDK documentation + interactive Policy Builder

> **KEY:** On-chain contract requires no upgrades. All future extensions (new protocols, new operators, new policy formats) delivered via new off-chain SDK versions. No migration, no proxy.

---

## 7. Open Decisions for Architect

The following decisions must be made by the architect before or during Phase 0.

| # | Decision | Options | Impact |
|---|---------|-------|-------|
| 1 | **ABI Registry v1 Scope** | A) UniV3 only (2 functions) B) UniV3 + Curve + Balancer from start | A) faster Week 1, smaller audit scope B) larger scope, longer Phase 0 |
| 2 | **abi.decode vs packed encoding** | A) abi.decode — readable code, ~2k gas overhead B) Manual parser — complexity, ~0 gas overhead | Benchmark in Phase 2. Decision impacts audit complexity. |
| 3 | **Global root vs per-account only** | A) Per-account root only B) Optional global root for open executors | B) requires additional registry contract and trust model for operator |
| 4 | **Post-deployment monitoring** | A) Tenderly B) Dune Analytics C) Custom subgraph | Needed before Phase 3. Impacts Phase 3 schedule. |

---

## 8. Technology Stack

| Layer | Technology | Notes |
|--------|-------------|-------|
| Smart Contract | Solidity ^0.8.20 | Optimizer enabled, assembly for calldataload |
| On-chain Libraries | OpenZeppelin MerkleProof + ECDSA | Audited — do not reimplement cryptography |
| Test Framework | Foundry (forge test + fuzz) | Fuzz testing critical for calldata edge cases |
| TS Client | viem + merkletreejs | No ethers.js dependency |
| Bundler | Pimlico / Alchemy AA | EIP-4337 v0.7 — do not mix with v0.6 |
| EntryPoint | ERC-4337 EntryPoint v0.7 | Verify version before L2 deploy |
| Account Integrations | Safe, Biconomy, ZeroDev (ERC-7579) | `installModule()` — no modification to base account |

---

## Why This Architecture is Optimal

The on-chain contract is simple, deterministic, and never requires upgrade. All complexity lives off-chain where it can be updated without migration risk and cost. Developers operate in business language, not bytes. Gas cost is ~80% lower than ABI-decode alternatives while maintaining full genericity. The system will handle protocols that don't yet exist — without any contract changes.
