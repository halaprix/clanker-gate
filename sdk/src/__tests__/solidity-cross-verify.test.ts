import { describe, it, expect } from 'vitest';
import { hashPermission } from '../builder/index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { compilePolicy } from '../policy-compiler/index.js';
import { OP } from '../types/index.js';
import { encodeAbiParameters, parseAbiParameters, keccak256 } from 'viem';

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

    const sdkHash = hashPermission(permission);
    
    // Hash should be deterministic and non-zero
    expect(sdkHash).toMatch(/^0x[a-f0-9]{64}$/);
    expect(sdkHash).not.toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
  });

  it('should match abi.encode format for permission struct with lifecycle fields', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [
        { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt(1000) },
      ],
    });

    const rulesEncoded = permission.rules.map((rule) => [
      BigInt(rule.offset),
      rule.op,
      rule.value,
      rule.values ?? [],
    ] as const);

    const encoded = encodeAbiParameters(
      parseAbiParameters('address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256, bool'),
      [
        permission.target,
        permission.selector,
        rulesEncoded,
        permission.validAfter,
        permission.validUntil,
        BigInt(permission.chainId),
        permission.singleUse ?? false,
      ]
    );

    const sdkHash = keccak256(encoded);
    const builderHash = hashPermission(permission);

    expect(sdkHash).toBe(builderHash);
  });

  it('should produce deterministic hashes for empty rules', () => {
    const permission = compilePolicy({
      abi: UNISWAP_V3_ROUTER_ABI,
      target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      functionName: 'exactInputSingle',
      rules: [],
    });

    const hash1 = hashPermission(permission);
    const hash2 = hashPermission(permission);

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

    expect(hashPermission(permission1)).not.toBe(hashPermission(permission2));
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

    expect(hashPermission(permission1)).not.toBe(hashPermission(permission2));
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

    expect(hashPermission(permission1)).not.toBe(hashPermission(permission2));
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

    expect(hashPermission(permission1)).not.toBe(hashPermission(permission2));
  });
});
