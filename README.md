```
________            __             ______      __     
  / ____/ /___ _____  / /_____  _____/ ____/___ _/ /____ 
 / /   / / __ `/ __ \/ //_/ _ \/ ___/ / __/ __ `/ __/ _ \
/ /___/ / /_/ / / / / ,< /  __/ /  / /_/ / /_/ / /_/  __/
\____/_/\__,_/_/ /_/_/|_|\___/_/   \____/\__,_/\__/\___/ 
```

**Stateful Transaction Validator for Smart Accounts**

> ⚠️ **UNAUDITED — USE AT YOUR OWN RISK.** This code has **not** undergone a professional security audit. It controls access to on-chain funds; bugs can lead to **irreversible loss of assets**. Do not use it to guard accounts holding value you cannot afford to lose. See the full [Disclaimer](#disclaimer) below.

ClankerGate is a validation module that enables defining granular transaction policies without giving external executors full private key access. It acts as a "guard" for various types of Smart Accounts, verifying on-chain whether operations fall within defined boundaries.

## Implementations

| Contract | Standard | Description |
|----------|----------|-------------|
| **ClankerGateCore** | Library | Shared validation logic (Merkle proof, calldata rules, OP_IN) |
| **ClankerGate4337** | ERC-4337 | For Account Abstraction (UserOperation validation) |
| **ClankerGateSafe** | Gnosis Safe | Safe Module with execTransaction |
| **ClankerGate7579** | ERC-7579 | Modular accounts (ZeroDev, Biconomy, Rhinestone) |

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  OFF-CHAIN                                                      │
│                                                                 │
│  1. Developer defines policy via TypeScript SDK:                │
│     policy.allow().to(ROUTER).fn("exactInputSingle")                 │
│            .where("params.amountIn").lte(1 ETH)                 │
│                                                                 │
│  2. Policy Compiler: ABI → selectors → offsets → Permission     │
│                                                                 │
│  3. Merkle Tree Builder: Permission → root + proof              │
│                                                                 │
│  4. Single transaction setPolicyRoot(root) on-chain             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  ON-CHAIN                                                       │
│                                                                 │
│  validateUserOp() / execTransaction():                          │
│    1. Merkle Proof - verify policy is in tree                   │
│    2. Calldata Rules - calldataload(offset) vs rules            │
│    3. ECDSA Signature - verify owner signed                     │
│    4. Time validation - validAfter / validUntil                 │
│    5. Chain validation - chainId check                          │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features

| Feature | Description |
|---------|-------------|
| **Gas-efficient** | ~800 gas / rule (vs 20k-50k for ABI decode) |
| **Stateful** | Stores policyRoots, nonces, usedPermissionHashes, and caller authorizations |
| **Upgrade-proof** | On-chain contract never needs upgrade |
| **Protocol-agnostic** | Any protocol - just provide ABI |
| **Type-safe SDK** | viem + TypeScript with full typing |
| **Multi-standard** | ERC-4337, Gnosis Safe, ERC-7579 |

## Project Structure

```
clanker-gate/
├── src/                              # Solidity smart contracts
│   ├── ClankerGateCore.sol          # Shared logic (library)
│   ├── ClankerGate4337.sol          # ERC-4337 validator
│   ├── ClankerGateSafe.sol          # Gnosis Safe module
│   ├── ClankerGate7579.sol          # ERC-7579 validator module
│   └── interfaces/
│       ├── IERC4337.sol             # ERC-4337 interfaces
│       └── IERC7579.sol             # ERC-7579 interfaces
├── test/                             # Foundry tests
│   ├── ClankerGateCore.t.sol        # 26 tests (core logic + OP_IN)
│   ├── ClankerGate4337.t.sol        # 21 tests (ERC-4337 + OP_IN)
│   ├── ClankerGateSafe.t.sol        # 39 tests (Safe module + OP_IN)
│   └── ClankerGate7579.t.sol        # 22 tests (ERC-7579)
├── test/                             # Additional tests
│   ├── GasBenchmark.t.sol            # 11 tests (gas benchmarks)
│   ├── e2e/UniV3Swap.t.sol          # 4 tests (E2E integration)
│   └── invariant/ClankerGateInvariant.t.sol # 8 tests
├── sdk/                              # TypeScript SDK
│   └── src/
│       ├── types/                    # TypeScript types
│       ├── domain/                   # Clean Architecture entities
│       ├── abi-registry/             # ABI registry (Uniswap V3)
│       ├── policy-compiler/          # Policy compiler
│       ├── builder/                  # Merkle tree builder
│       ├── simulator/                # Off-chain validation
│       ├── clients/                  # Clients for each contract
│       │   ├── ClankerGate4337Client.ts
│       │   ├── ClankerGateSafeClient.ts
│       │   └── ClankerGate7579Client.ts
│       └── __tests__/                # 156 SDK tests
├── ARCHITECTURE.md                   # Detailed architecture docs
```

## Quick Start

### Smart Contract (Foundry)

```bash
# Build
forge build

# Test
forge test --summary

# Test specific contract
forge test --match-path "test/ClankerGate4337.t.sol"
forge test --match-path "test/ClankerGate7579.t.sol"
```

### SDK (TypeScript)

```bash
cd sdk

# Install
pnpm install

# Build
pnpm build

# Test
pnpm test
```

## SDK Usage

### Basic Policy

```typescript
import { ClankerGate, UNISWAP_V3_ROUTER_ABI, OP } from '@clanker/gate-client';

// Fluent API
const permission = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
  .allow()
  .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45') // Uniswap V3 Router
  .fn('exactInputSingle')
  .where('params.amountIn')
  .lte(BigInt('1000000000000000000')) // Max 1 ETH
  .build();

// Shorthand
import { permission } from '@clanker/gate-client';

const perm = permission(
  UNISWAP_V3_ROUTER_ABI,
  '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
  'exactInputSingle',
  [
    { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') }
  ]
);
```

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq(value)` | Equal | `.eq(BigInt(100))` |
| `gt(value)` | Greater than | `.gt(BigInt(100))` |
| `lt(value)` | Less than | `.lt(BigInt(100))` |
| `gte(value)` | Greater than or equal | `.gte(BigInt(100))` |
| `lte(value)` | Less than or equal | `.lte(BigInt(100))` |
| `in(values[])` | Value in set | `.in([addr1, addr2, addr3])` |

### Fixed-offset safety

On-chain rules compare 32-byte words at fixed calldata offsets. The SDK therefore
only compiles rules for statically located scalar parameters and fields inside
fully static tuples. It rejects `bytes`, `string`, arrays, and fields behind a
dynamic tuple pointer: comparing those with a fixed offset would inspect an ABI
pointer or a canonical sample layout rather than the value Solidity eventually
decodes.

Manually constructed `Permission` values must follow the same restriction.

For the ERC-4337 and ERC-7579 validators, `singleUse` means one successful
validation attempt, not one successful downstream execution. EntryPoint
execution failure does not roll back state written during validation. Use the
Safe module when validation and execution must be atomic, or add an
account-specific post-execution hook.

### OP_IN - Multiple Allowed Values

```typescript
import { OP } from '@clanker/gate-client';

// Allow 3 specific recipient addresses
const permission = ClankerGate.policy(TOKEN_ABI)
  .allow()
  .to(tokenAddress)
  .fn('transfer')
  .where('to')
  .in([
    BigInt('0x1234...'),  // address 1
    BigInt('0x5678...'),  // address 2
    BigInt('0xabcd...'),  // address 3
  ])
  .build();
```

### Merkle Tree and Proof

```typescript
const builder = ClankerGate.merkleTree();

// Add multiple policies
builder.addPermission(permission1);
builder.addPermission(permission2);
builder.addPermission(permission3);

// Build tree
const { root, leaves } = builder.build();

// Generate proof for specific policy
const proof = builder.getProof(permission1);

console.log({
  root: proof.root,        // Save on-chain via setPolicyRoot()
  proof: proof.proof,      // Include in guardData
  leaf: proof.leaf         // Policy hash
});
```

### Off-chain Simulator

```typescript
import { simulator } from '@clanker/gate-client';

// Test policy without deployment
const result = simulator.validate(permission, calldata);

if (result.valid) {
  console.log('Policy allows this operation');
} else {
  console.log('Rule violation:', result.violation);
}
```

## Integration

### ERC-4337 (ClankerGate4337)

```typescript
import { createClankerGate4337Client } from '@clanker/gate-client';

const client = createClankerGate4337Client({
  address: '0x...',
  publicClient,
  walletClient,
});

// Set policy
await client.setPolicyRoot({ account, root });

// Get current root
const root = await client.getPolicyRoot(accountAddress);
```

```solidity
// In Smart Account
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    bytes calldata guardData  // (proof, permission, signature)
) external returns (uint256) {
    return clankerGate.validateUserOp(userOp, userOpHash, guardData);
}
```

### Gnosis Safe (ClankerGateSafe)

```typescript
import { createClankerGateSafeClient } from '@clanker/gate-client';

const client = createClankerGateSafeClient({
  address: '0x...',
  publicClient,
  walletClient,
});

// Authorize executor
await client.authorizeCaller({ safe, caller, account });

// Execute transaction with proof
await client.execTransaction({
  safe,
  to: targetAddress,
  value: 0n,
  data: callData,
  operation: 0,
  proof,
  permission,
  account,
});
```

```solidity
// In Safe - enable module
safe.enableModule(address(clankerGateSafe));

// Executor executes transaction
clankerGateSafe.execTransaction(
    safe,
    to,
    value,
    data,
    operation,
    proof,
    permission
);
```

### ERC-7579 (ClankerGate7579)

```typescript
import { createClankerGate7579Client } from '@clanker/gate-client';

const client = createClankerGate7579Client({
  address: '0x...',
  publicClient,
  walletClient,
});

// Encode installation data
const initData = client.encodeOnInstall(
  ownerAddress,
  initialRoot,
  signatureValidator  // address(0) = use account.owner()
);

// In account contract:
// account.installModule(MODULE_TYPE_VALIDATOR, gateAddress, initData);
```

```solidity
// initData format
abi.encode(
    initOwner,           // Address that can update policy
    initPolicyRoot,      // Initial Merkle root (0 = disabled)
    signatureValidator   // Contract for signature validation (0 = account.owner())
)
```

## ParamRule Struct

```solidity
struct ParamRule {
    uint256 offset;      // Offset in calldata (after selector)
    uint8 op;            // Operator (0=EQ, 1=GT, 2=LT, 3=GTE, 4=LTE, 5=IN, 6=SGT, 7=SLT)
    bytes32 value;       // Value for EQ/GT/LT/GTE/LTE/SGT/SLT
    bytes32[] values;    // Array of values for OP_IN
}
```

## Permission Struct

```solidity
struct Permission {
    address target;      // Target contract (0 = any)
    bytes4 selector;     // Function selector
    ParamRule[] rules;   // Validation rules
    uint48 validAfter;   // Timestamp when valid (0 = always)
    uint48 validUntil;   // Timestamp until valid (0 = always)
    uint256 chainId;     // Chain ID (0 = all chains)
}
```

## Security

### Risks Addressed by ClankerGate

| Risk | Mitigation |
|------|------------|
| Executor gets full key | Executor operates within policy bounds |
| No operation trace | On-chain verification, immutable result |
| One adapter per protocol | Single contract for all |
| High gas cost | ~800 gas/rule vs 20k-50k |
| Cross-chain replay | chainId in Permission struct |
| Time-based attacks | validAfter / validUntil validation |

### Failure Modes

| Condition | Result |
|-----------|--------|
| `root == 0` | All transactions blocked (fail-safe) |
| Invalid proof | Transaction rejected |
| Rule violation | Transaction rejected with `RuleViolation` or `ValueNotInSet` |
| Invalid signer | Transaction rejected with `UnauthorizedSigner` |
| Permission expired | Transaction rejected with `PermissionExpired` |
| ChainId mismatch | Transaction rejected with `ChainIdMismatch` |

## Tech Stack

| Layer | Technology |
|-------|------------|
| Smart Contract | Solidity ^0.8.20 |
| Libraries | OpenZeppelin (MerkleProof, ECDSA, MessageHashUtils) |
| Test Framework | Foundry |
| TS Client | viem + merkletreejs |
| Test Runner | Vitest |
| Architecture | Clean Architecture (domain/use-cases/infrastructure) |

## Tests

```bash
# Foundry (Solidity)
forge test --summary
# 148 tests passing

# SDK (TypeScript)
cd sdk && pnpm test
# 156 tests passing

# Total: 282 tests
```

### Test Coverage

| Component | Tests | Description |
|-----------|-------|-------------|
| ClankerGateCore | 26 | Core logic, OP_IN, Merkle proof |
| ClankerGate4337 | 21 | ERC-4337 validation, OP_IN integration |
| ClankerGateSafe | 39 | Safe module, caller auth, OP_IN |
| ClankerGate7579 | 22 | ERC-7579 module, install/uninstall |
| GasBenchmark | 11 | Gas benchmarks |
| UniV3Swap (E2E) | 4 | End-to-end integration tests |
| Invariant | 8 | Invariant testing |
| SDK Domain | 40 | Entities, value objects, errors |
| SDK Simulator | 21 | Off-chain validation |
| SDK Integration | 10 | End-to-end flows |

## Documentation

- `ARCHITECTURE.md` - Detailed architecture and design decisions
- SDK TSDoc - API documentation in code

## Disclaimer

**This software is experimental and has not been audited.**

- **No security audit.** Neither the smart contracts nor the SDK have been reviewed by a professional security auditor. Known and unknown vulnerabilities may exist, including ones that allow **total loss of funds** in guarded accounts.
- **No warranty.** The software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement (see the MIT License below).
- **Use at your own risk and responsibility.** You are solely responsible for evaluating the code, testing it against your own threat model, and for any consequences of deploying or interacting with it — including lost, stolen, or frozen assets, failed transactions, and gas costs.
- **No liability.** In no event shall the authors, contributors, or copyright holders be liable for any claim, damages, or other liability arising from the use of this software.
- **Not financial, legal, or security advice.** Nothing in this repository constitutes advice of any kind. Deploying smart contracts and delegating transaction authority may be subject to laws and regulations in your jurisdiction — compliance is your responsibility.
- **Immutability warning.** Smart contracts, once deployed, may be impossible to patch. A policy that compiles and validates today may still not express what you intended — always verify permissions against real calldata before trusting them with value.

If you intend to use ClankerGate in production, commission an independent security audit first.

## License

MIT — see the warranty and liability disclaimers above, which restate the license's terms:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
