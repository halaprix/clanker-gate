import { describe, it, expect } from 'vitest';
import { hashPermissionStruct, hashPermissionLeaf, computeDomainSeparator } from '../builder/index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { compilePolicy } from '../policy-compiler/index.js';
import { OP } from '../types/index.js';
import { encodeAbiParameters, parseAbiParameters, keccak256, toBytes, zeroAddress } from 'viem';
import type { MerkleTreeConfig } from '../builder/index.js';

const TEST_CONFIG: MerkleTreeConfig = {
  account: '0x1111111111111111111111111111111111111111',
  gateAddress: '0x2222222222222222222222222222222222222222',
  chainId: 1n,
  nonce: 0n,
};

describe('SDK ↔ Solidity cross-verification', () => {
  it('should produce deterministic hashes for new Permission struct', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [
        { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') },
        { paramPath: 'params.tokenIn', op: OP.EQ, value: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
      ],
    });

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    const sdkHash = hashPermissionStruct(permission, domainSeparator);

    // Hash should be deterministic and non-zero
    expect(sdkHash).toMatch(/^0x[a-f0-9]{64}$/);
    expect(sdkHash).not.toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
  });

  it('should match manual abi.encode derivation of the canonical formula', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [
        { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt(1000) },
      ],
    });

    // Manually reproduce the canonical on-chain formula step-by-step.
    // Step 1: domain separator
    const DOMAIN_TYPEHASH = keccak256(
      toBytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
    );
    const nameHash = keccak256(toBytes('ClankerGate'));
    const versionHash = keccak256(toBytes('1'));
    const domainSeparator = keccak256(
      encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'uint256' }, { type: 'address' }],
        [DOMAIN_TYPEHASH, nameHash, versionHash, TEST_CONFIG.chainId, TEST_CONFIG.gateAddress]
      )
    );

    // Step 2: rule hashes (offset, op, value, values)
    const ruleHashes = permission.rules.map((rule) =>
      keccak256(
        encodeAbiParameters(
          [{ type: 'uint256' }, { type: 'uint8' }, { type: 'bytes32' }, { type: 'bytes32[]' }],
          [BigInt(rule.offset), rule.op, rule.value, rule.values ?? []]
        )
      )
    );

    // Step 3: encodedPermission (9 fields, chainId BEFORE singleUse)
    const encodedPermission = keccak256(
      encodeAbiParameters(
        [
          { type: 'address' },
          { type: 'bytes4' },
          { type: 'bytes32[]' },
          { type: 'uint48' },
          { type: 'uint48' },
          { type: 'uint256' },
          { type: 'bool' },
          { type: 'uint256' },
          { type: 'address' },
        ],
        [
          permission.target,
          permission.selector,
          ruleHashes,
          permission.validAfter ?? 0,
          permission.validUntil ?? 0,
          BigInt(permission.chainId ?? 0),
          permission.singleUse ?? false,
          permission.maxValue ?? 0n,
          permission.authorizedCaller ?? zeroAddress,
        ]
      )
    );

    // Step 4: permHash
    const permHash = keccak256(
      encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes32' }],
        [domainSeparator, encodedPermission]
      )
    );

    const sdkHash = hashPermissionStruct(permission, computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId));

    expect(sdkHash).toBe(permHash);
  });

  it('should produce deterministic hashes for empty rules', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    const hash1 = hashPermissionStruct(permission, domainSeparator);
    const hash2 = hashPermissionStruct(permission, domainSeparator);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('should produce different hashes for different rule order', () => {
    const permission1 = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [
        { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt(1000) },
        { paramPath: 'params.tokenIn', op: OP.EQ, value: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
      ],
    });

    const permission2 = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [
        { paramPath: 'params.tokenIn', op: OP.EQ, value: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
        { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt(1000) },
      ],
    });

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    expect(hashPermissionStruct(permission1, domainSeparator)).not.toBe(hashPermissionStruct(permission2, domainSeparator));
  });

  it('should produce different hashes for different validUntil', () => {
    const permission1 = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const permission2 = {
      ...permission1,
      validUntil: 1735689600,
    };

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    expect(hashPermissionStruct(permission1, domainSeparator)).not.toBe(hashPermissionStruct(permission2, domainSeparator));
  });

  it('should produce different hashes for different chainId', () => {
    const permission1 = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const permission2 = {
      ...permission1,
      chainId: 1, // Ethereum mainnet
    };

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    expect(hashPermissionStruct(permission1, domainSeparator)).not.toBe(hashPermissionStruct(permission2, domainSeparator));
  });

  it('should produce different hashes for singleUse flag', () => {
    const permission1 = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const permission2 = {
      ...permission1,
      singleUse: true,
    };

    const domainSeparator = computeDomainSeparator(TEST_CONFIG.gateAddress, TEST_CONFIG.chainId);
    expect(hashPermissionStruct(permission1, domainSeparator)).not.toBe(hashPermissionStruct(permission2, domainSeparator));
  });

  it('hashPermissionLeaf should change with account and nonce', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const leaf1 = hashPermissionLeaf({ permission, ...TEST_CONFIG, nonce: 0n });
    const leaf2 = hashPermissionLeaf({ permission, ...TEST_CONFIG, nonce: 1n });
    const leaf3 = hashPermissionLeaf({
      permission,
      ...TEST_CONFIG,
      account: '0x3333333333333333333333333333333333333333',
      nonce: 0n,
    });

    expect(leaf1).not.toBe(leaf2);
    expect(leaf1).not.toBe(leaf3);
    expect(leaf1).toMatch(/^0x[a-f0-9]{64}$/);
  });
});
