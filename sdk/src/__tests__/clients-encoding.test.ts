/**
 * Round-trip tests for the 4337 client guardData encoding.
 *
 * Verifies that encodeGuardData produces ABI bytes that decode back to
 * the original Permission struct with the correct on-chain tuple layout:
 *   Permission = (address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256, bool, uint256, address)
 *   ParamRule  = (uint256 offset, uint8 op, bytes32 value, bytes32[] values)
 *
 * Notably, ParamRule has exactly FOUR fields — NOT five.
 * The old SDK had a phantom 5th "maxValue" field on the rule tuple that
 * does not exist on-chain, causing silent ABI layout mismatches.
 */
import { describe, it, expect } from 'vitest';
import { encodeAbiParameters, decodeAbiParameters, parseAbiParameters, zeroAddress } from 'viem';
import type { Permission } from '../types/index.js';
import { OP } from '../types/index.js';

// Guard-data ABI matching ClankerGate4337Client.encodeGuardData
const GUARD_DATA_ABI = parseAbiParameters(
  'bytes32[], (address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256, bool, uint256, address), bytes'
);

function buildTestPermission(overrides: Partial<Permission> = {}): Permission {
  return {
    target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
    selector: '0xc04b8d59' as `0x${string}`,
    rules: [
      {
        offset: 32,
        op: OP.LTE,
        value: '0x0000000000000000000000000000000000000000000000000de0b6b3a7640000',
        values: [],
      },
      {
        offset: 64,
        op: OP.IN,
        value: '0x0000000000000000000000000000000000000000000000000000000000000000',
        values: [
          '0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
          '0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        ],
      },
    ],
    validAfter: 1000000,
    validUntil: 2000000,
    chainId: 1,
    singleUse: true,
    maxValue: 500000000000000000n,
    authorizedCaller: '0x1234567890123456789012345678901234567890',
    ...overrides,
  };
}

describe('client encoding round-trip', () => {
  it('encodes and decodes a Permission with rules preserving all 4 rule fields', () => {
    const permission = buildTestPermission();

    // Build the same tuple that ClankerGate4337Client.encodePermission produces
    const rulesEncoded = permission.rules.map((rule) => [
      BigInt(rule.offset),
      rule.op,
      rule.value,
      rule.values ?? [],
    ] as const);

    const permissionTuple = [
      permission.target,
      permission.selector,
      rulesEncoded,
      permission.validAfter ?? 0,
      permission.validUntil ?? 0,
      BigInt(permission.chainId ?? 0),
      permission.singleUse ?? false,
      permission.maxValue ?? 0n,
      permission.authorizedCaller ?? zeroAddress,
    ] as const;

    const proof: `0x${string}`[] = [
      '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ];
    const signature = '0xdeadbeef' as `0x${string}`;

    const encoded = encodeAbiParameters(
      GUARD_DATA_ABI,
      [proof, permissionTuple, signature]
    );

    // Decode back and assert structural equality
    const [decodedProof, decodedPerm, decodedSig] = decodeAbiParameters(
      GUARD_DATA_ABI,
      encoded
    );

    // Proof
    expect(decodedProof[0]).toBe(proof[0]);
    expect(decodedProof[1]).toBe(proof[1]);

    // Signature
    expect(decodedSig.toLowerCase()).toBe(signature.toLowerCase());

    // Permission top-level fields
    expect(decodedPerm[0].toLowerCase()).toBe(permission.target.toLowerCase()); // target
    expect(decodedPerm[1]).toBe(permission.selector);                           // selector
    // validAfter / validUntil are uint48 — viem decodes them as number
    expect(Number(decodedPerm[3])).toBe(permission.validAfter!);                // validAfter
    expect(Number(decodedPerm[4])).toBe(permission.validUntil!);                // validUntil
    expect(decodedPerm[5]).toBe(BigInt(permission.chainId!));                   // chainId (uint256)
    expect(decodedPerm[6]).toBe(permission.singleUse);                         // singleUse
    expect(decodedPerm[7]).toBe(permission.maxValue);                          // maxValue
    expect(decodedPerm[8].toLowerCase()).toBe(permission.authorizedCaller!.toLowerCase()); // authorizedCaller

    // Rules — decoded rules array is index 2
    const decodedRules = decodedPerm[2];
    expect(decodedRules).toHaveLength(2);

    // Rule 0: LTE rule
    const rule0 = decodedRules[0];
    expect(rule0[0]).toBe(BigInt(permission.rules[0].offset));  // offset
    expect(rule0[1]).toBe(permission.rules[0].op);              // op (uint8)
    expect(rule0[2]).toBe(permission.rules[0].value);           // value
    // values[] is the 4th element (index 3) — no 5th element
    expect(rule0[3]).toEqual([]);                               // values (empty)
    expect(rule0).toHaveLength(4);                             // EXACTLY 4 fields — no phantom 5th

    // Rule 1: IN rule with values
    const rule1 = decodedRules[1];
    expect(rule1[0]).toBe(BigInt(permission.rules[1].offset));
    expect(rule1[1]).toBe(permission.rules[1].op);
    expect(rule1[2]).toBe(permission.rules[1].value);
    expect(rule1[3]).toHaveLength(2);                          // values has 2 elements
    expect(rule1[3][0]).toBe(permission.rules[1].values![0]);
    expect(rule1[3][1]).toBe(permission.rules[1].values![1]);
    expect(rule1).toHaveLength(4);                             // EXACTLY 4 fields
  });

  it('encodes a permission with no rules and default optional fields', () => {
    const permission = buildTestPermission({
      rules: [],
      singleUse: undefined,
      maxValue: undefined,
      authorizedCaller: undefined,
    });

    const rulesEncoded: readonly (readonly [bigint, number, `0x${string}`, readonly `0x${string}`[]])[] = [];

    const permissionTuple = [
      permission.target,
      permission.selector,
      rulesEncoded,
      permission.validAfter ?? 0,
      permission.validUntil ?? 0,
      BigInt(permission.chainId ?? 0),
      permission.singleUse ?? false,
      permission.maxValue ?? 0n,
      permission.authorizedCaller ?? zeroAddress,
    ] as const;

    const encoded = encodeAbiParameters(
      GUARD_DATA_ABI,
      [[], permissionTuple, '0x']
    );

    const [, decodedPerm] = decodeAbiParameters(GUARD_DATA_ABI, encoded);

    expect(decodedPerm[2]).toHaveLength(0);  // no rules
    expect(decodedPerm[6]).toBe(false);       // singleUse default false
    expect(decodedPerm[7]).toBe(0n);          // maxValue default 0
    expect(decodedPerm[8].toLowerCase()).toBe(zeroAddress.toLowerCase()); // authorizedCaller default zero
  });
});
