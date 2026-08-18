/**
 * Round-trip tests for the client encoding helpers:
 *   1. packUserOpSignature — encodes proof + Permission + ownerSig into the
 *      bytes that go in userOp.signature for validateUserOp(userOp, hash).
 *   2. Legacy positional tuple round-trip to verify field order.
 *
 * On-chain Permission struct field order (ClankerGateCore.sol):
 *   target, selector, validAfter, validUntil, singleUse, chainId,
 *   maxValue, authorizedCaller, rules[]
 *
 * ParamRule has exactly FOUR fields: offset, op, value, values[]
 */
import { describe, it, expect } from 'vitest';
import { decodeAbiParameters, parseAbiParameters, zeroAddress } from 'viem';
import type { Permission } from '../types/index.js';
import { OP } from '../types/index.js';
import { packUserOpSignature, decodePackedSignature, PACKED_SIG_ABI } from '../clients/guardData.js';

// ---------------------------------------------------------------------------
// Shared positional ABI string matching the NEW on-chain field order:
//   (address target, bytes4 selector, uint48 validAfter, uint48 validUntil,
//    bool singleUse, uint256 chainId, uint256 maxValue, address authorizedCaller,
//    (uint256 offset, uint8 op, bytes32 value, bytes32[] values)[] rules)
// ---------------------------------------------------------------------------
const GUARD_DATA_ABI_POSITIONAL = parseAbiParameters(
  'bytes32[], (address, bytes4, uint48, uint48, bool, uint256, uint256, address, (uint256, uint8, bytes32, bytes32[])[]), bytes'
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

// ---------------------------------------------------------------------------
// packUserOpSignature round-trip tests
// ---------------------------------------------------------------------------

describe('packUserOpSignature round-trip', () => {
  it('encodes and decodes proof + Permission + ownerSig preserving all fields', () => {
    const permission = buildTestPermission();
    const proof: `0x${string}`[] = [
      '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ];
    const ownerSignature = '0xdeadbeef01020304' as `0x${string}`;

    const packed = packUserOpSignature({ proof, permission, ownerSignature });

    // Decode with viem using the named-field ABI
    const [decodedProof, decodedPerm, decodedSig] = decodeAbiParameters(PACKED_SIG_ABI, packed);

    // Proof
    expect(decodedProof).toHaveLength(2);
    expect(decodedProof[0]).toBe(proof[0]);
    expect(decodedProof[1]).toBe(proof[1]);

    // Signature
    expect(decodedSig.toLowerCase()).toBe(ownerSignature.toLowerCase());

    // Permission scalar fields
    expect(decodedPerm.target.toLowerCase()).toBe(permission.target.toLowerCase());
    expect(decodedPerm.selector).toBe(permission.selector);
    expect(Number(decodedPerm.validAfter)).toBe(permission.validAfter);
    expect(Number(decodedPerm.validUntil)).toBe(permission.validUntil);
    expect(decodedPerm.singleUse).toBe(permission.singleUse);
    expect(decodedPerm.chainId).toBe(BigInt(permission.chainId));
    expect(decodedPerm.maxValue).toBe(permission.maxValue);
    expect(decodedPerm.authorizedCaller.toLowerCase()).toBe(permission.authorizedCaller!.toLowerCase());

    // Rules — exactly 4 fields per rule
    expect(decodedPerm.rules).toHaveLength(2);

    const rule0 = decodedPerm.rules[0];
    expect(rule0.offset).toBe(BigInt(permission.rules[0].offset));
    expect(rule0.op).toBe(permission.rules[0].op);
    expect(rule0.value).toBe(permission.rules[0].value);
    expect(rule0.values).toEqual([]);

    const rule1 = decodedPerm.rules[1];
    expect(rule1.offset).toBe(BigInt(permission.rules[1].offset));
    expect(rule1.op).toBe(permission.rules[1].op);
    expect(rule1.value).toBe(permission.rules[1].value);
    expect(rule1.values).toHaveLength(2);
    expect(rule1.values[0]).toBe(permission.rules[1].values![0]);
    expect(rule1.values[1]).toBe(permission.rules[1].values![1]);
  });

  it('decodePackedSignature inverts packUserOpSignature', () => {
    const permission = buildTestPermission({ rules: [], singleUse: false, maxValue: 0n, authorizedCaller: undefined });
    const proof: `0x${string}`[] = [];
    const ownerSignature = '0xcafe' as `0x${string}`;

    const packed = packUserOpSignature({ proof, permission, ownerSignature });
    const { proof: dProof, ownerSignature: dSig } = decodePackedSignature(packed);

    expect(dProof).toHaveLength(0);
    expect(dSig.toLowerCase()).toBe(ownerSignature.toLowerCase());
  });

  it('encodes a permission with no rules and default optional fields', () => {
    const permission = buildTestPermission({
      rules: [],
      singleUse: undefined,
      maxValue: undefined,
      authorizedCaller: undefined,
    });
    const packed = packUserOpSignature({ proof: [], permission, ownerSignature: '0x' });
    const [, decodedPerm] = decodeAbiParameters(PACKED_SIG_ABI, packed);

    expect(decodedPerm.rules).toHaveLength(0);
    expect(decodedPerm.singleUse).toBe(false);
    expect(decodedPerm.maxValue).toBe(0n);
    expect(decodedPerm.authorizedCaller.toLowerCase()).toBe(zeroAddress.toLowerCase());
  });
});

// ---------------------------------------------------------------------------
// Field order verification — positional ABI matches named ABI
// ---------------------------------------------------------------------------

describe('client encoding field order', () => {
  it('codec output decodes positionally with all 4 rule fields in correct field order', () => {
    const permission = buildTestPermission();

    const proof: `0x${string}`[] = [
      '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ];
    const signature = '0xdeadbeef' as `0x${string}`;

    // Encode through the PRODUCTION path (packUserOpSignature → permission-codec),
    // then decode with an independently hand-written positional ABI. This pins
    // the codec's field order, not a locally re-declared one.
    const encoded = packUserOpSignature({ proof, permission, ownerSignature: signature });

    const [decodedProof, decodedPerm, decodedSig] = decodeAbiParameters(
      GUARD_DATA_ABI_POSITIONAL,
      encoded
    );

    // Proof
    expect(decodedProof[0]).toBe(proof[0]);
    expect(decodedProof[1]).toBe(proof[1]);

    // Signature
    expect(decodedSig.toLowerCase()).toBe(signature.toLowerCase());

    // Permission fields in NEW order: [0]=target, [1]=selector, [2]=validAfter,
    //   [3]=validUntil, [4]=singleUse, [5]=chainId, [6]=maxValue,
    //   [7]=authorizedCaller, [8]=rules[]
    expect(decodedPerm[0].toLowerCase()).toBe(permission.target.toLowerCase());
    expect(decodedPerm[1]).toBe(permission.selector);
    expect(Number(decodedPerm[2])).toBe(permission.validAfter!);
    expect(Number(decodedPerm[3])).toBe(permission.validUntil!);
    expect(decodedPerm[4]).toBe(permission.singleUse);
    expect(decodedPerm[5]).toBe(BigInt(permission.chainId!));
    expect(decodedPerm[6]).toBe(permission.maxValue);
    expect(decodedPerm[7].toLowerCase()).toBe(permission.authorizedCaller!.toLowerCase());

    // Rules at index 8
    const decodedRules = decodedPerm[8];
    expect(decodedRules).toHaveLength(2);

    const rule0 = decodedRules[0];
    expect(rule0[0]).toBe(BigInt(permission.rules[0].offset));
    expect(rule0[1]).toBe(permission.rules[0].op);
    expect(rule0[2]).toBe(permission.rules[0].value);
    expect(rule0[3]).toEqual([]);
    expect(rule0).toHaveLength(4);  // EXACTLY 4 fields — no phantom 5th

    const rule1 = decodedRules[1];
    expect(rule1[0]).toBe(BigInt(permission.rules[1].offset));
    expect(rule1[1]).toBe(permission.rules[1].op);
    expect(rule1[2]).toBe(permission.rules[1].value);
    expect(rule1[3]).toHaveLength(2);
    expect(rule1[3][0]).toBe(permission.rules[1].values![0]);
    expect(rule1[3][1]).toBe(permission.rules[1].values![1]);
    expect(rule1).toHaveLength(4);  // EXACTLY 4 fields
  });

  it('applies codec defaults for optional fields (positional decode)', () => {
    const permission = buildTestPermission({
      rules: [],
      singleUse: undefined,
      maxValue: undefined,
      authorizedCaller: undefined,
    });

    const encoded = packUserOpSignature({ proof: [], permission, ownerSignature: '0x' });

    const [, decodedPerm] = decodeAbiParameters(GUARD_DATA_ABI_POSITIONAL, encoded);

    expect(decodedPerm[8]).toHaveLength(0);  // rules at index 8, none
    expect(decodedPerm[4]).toBe(false);      // singleUse at index 4
    expect(decodedPerm[6]).toBe(0n);         // maxValue at index 6
    expect(decodedPerm[7].toLowerCase()).toBe(zeroAddress.toLowerCase()); // authorizedCaller at index 7
  });
});
