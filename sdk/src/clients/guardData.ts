/**
 * guardData — helper for packing the ERC-4337 / ERC-7579 userOp.signature
 *
 * On-chain, both ClankerGate4337 and ClankerGate7579 decode the signature
 * field of a PackedUserOperation as:
 *
 *   abi.decode(userOp.signature, (bytes32[], Permission, bytes))
 *
 * where Permission is:
 *   (address target, bytes4 selector, uint48 validAfter, uint48 validUntil,
 *    bool singleUse, uint256 chainId, uint256 maxValue, address authorizedCaller,
 *    ParamRule[] rules)
 *
 * and ParamRule has exactly FOUR fields:
 *   (uint256 offset, uint8 op, bytes32 value, bytes32[] values)
 */
import {
  type Hex,
  type Hash,
  encodeAbiParameters,
  parseAbiParameters,
  decodeAbiParameters,
} from 'viem';
import type { Permission } from '../types/index.js';
import { PERMISSION_STRUCT_ABI_STRING, toOnChainStruct } from './permission-codec.js';

// ---------------------------------------------------------------------------
// ABI string for the full packed signature payload
// ---------------------------------------------------------------------------

/**
 * ABI parameters string for packUserOpSignature / encodeGuardData output.
 * The Permission layout is owned by permission-codec.ts.
 */
export const PACKED_SIG_ABI_STRING =
  `bytes32[], ${PERMISSION_STRUCT_ABI_STRING}, bytes`;

export const PACKED_SIG_ABI = parseAbiParameters(PACKED_SIG_ABI_STRING);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface PackUserOpSignatureParams {
  /** Merkle proof for the permission */
  proof: readonly Hash[];
  /** The Permission granting this operation */
  permission: Permission;
  /** Owner's ECDSA signature over the userOpHash */
  ownerSignature: Hex;
}

/**
 * Encode proof + permission + ownerSignature into the bytes that must be
 * placed in `userOp.signature` before calling `validateUserOp(userOp, hash)`.
 *
 * @returns ABI-encoded `abi.encode(bytes32[] proof, Permission permission, bytes ownerSig)`
 */
export function packUserOpSignature({
  proof,
  permission,
  ownerSignature,
}: PackUserOpSignatureParams): Hex {
  const permTuple = toOnChainStruct(permission);
  return encodeAbiParameters(PACKED_SIG_ABI, [proof, permTuple, ownerSignature]);
}

/** Alias kept for backwards compatibility */
export const encodeGuardData = packUserOpSignature;

/**
 * Decode a packed userOp signature back to its proof and ownerSignature.
 * Useful for testing and debugging.
 */
export function decodePackedSignature(encoded: Hex): {
  proof: readonly Hash[];
  ownerSignature: Hex;
} {
  // decodeAbiParameters with a runtime-built ABI returns unknown[] —
  // we cast the elements we know the types of.
  const decoded = decodeAbiParameters(PACKED_SIG_ABI, encoded) as unknown as [
    readonly Hash[],
    unknown,
    Hex,
  ];
  return { proof: decoded[0], ownerSignature: decoded[2] };
}
