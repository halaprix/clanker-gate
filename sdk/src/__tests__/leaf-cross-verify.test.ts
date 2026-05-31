/**
 * Cross-verification: SDK hashPermissionLeaf == on-chain computePermissionHash
 *
 * The authoritative vector was captured from the on-chain ClankerGate4337 contract
 * using the following Foundry command (temporary test/LeafVectorGen.t.sol, now deleted):
 *
 *   forge test --match-contract LeafVectorGen -vv
 *
 * The test deployed a fresh ClankerGate4337, built a Permission with:
 *   - OP_IN rule with non-empty values array (2 token addresses)
 *   - nonzero maxValue (500000000000000000)
 *   - nonzero authorizedCaller
 *   - nonzero validAfter / validUntil
 *   - nonzero permission.chainId (1 = Ethereum mainnet policy field)
 *   - singleUse = true
 * and called gate.computePermissionHash(account, permission, nonce=0).
 *
 * To regenerate:
 *   forge test --match-contract LeafVectorGen -vv
 * (temporarily re-add test/LeafVectorGen.t.sol from git history or the audit notes)
 */
import { describe, it, expect } from 'vitest';
import { hashPermissionLeaf } from '../builder/index.js';
import { OP } from '../types/index.js';
import type { Permission } from '../types/index.js';

// --- Captured vector (from LeafVectorGen.t.sol run) ---
const GATE_ADDRESS = '0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f' as const;
const CHAIN_ID = 31337n; // Foundry anvil default
const EXPECTED_LEAF = '0xf5f655dac0d97f8514e1adee64925181b6b6b60377e315111ef146b4627862df' as const;

// --- The exact same permission used to generate the vector ---
const ACCOUNT = '0x1111111111111111111111111111111111111111' as const;
const NONCE = 0n;

const PERMISSION: Permission = {
  target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
  selector: '0xc04b8d59', // exactInput
  rules: [
    {
      offset: 0,
      op: OP.IN,
      value: '0x0000000000000000000000000000000000000000000000000000000000000000',
      values: [
        // bytes32(uint256(uint160(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)))
        '0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
        // bytes32(uint256(uint160(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)))
        '0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
      ],
    },
  ],
  validAfter: 1000000,
  validUntil: 9999999,
  chainId: 1,              // permission policy field (not gate chainId)
  singleUse: true,
  maxValue: 500000000000000000n,
  authorizedCaller: '0x1234567890123456789012345678901234567890',
};

describe('leaf-cross-verify: SDK hashPermissionLeaf == on-chain computePermissionHash', () => {
  it('SDK leaf matches on-chain leaf for non-trivial permission with OP_IN values', () => {
    const sdkLeaf = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(sdkLeaf).toBe(EXPECTED_LEAF);
  });

  it('leaf changes when account differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: PERMISSION,
      account: '0x2222222222222222222222222222222222222222',
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when nonce differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: 0n,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: 1n,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when gateAddress differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: '0x9999999999999999999999999999999999999999',
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when singleUse differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: { ...PERMISSION, singleUse: false },
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when maxValue differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: { ...PERMISSION, maxValue: 1n },
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when authorizedCaller differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: { ...PERMISSION, authorizedCaller: '0x0000000000000000000000000000000000000000' },
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });

  it('leaf changes when OP_IN values list differs', () => {
    const leaf1 = hashPermissionLeaf({
      permission: PERMISSION,
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    const leaf2 = hashPermissionLeaf({
      permission: {
        ...PERMISSION,
        rules: [{ ...PERMISSION.rules[0], values: [PERMISSION.rules[0].values![0]] }],
      },
      account: ACCOUNT,
      nonce: NONCE,
      gateAddress: GATE_ADDRESS,
      chainId: CHAIN_ID,
    });

    expect(leaf1).not.toBe(leaf2);
  });
});
