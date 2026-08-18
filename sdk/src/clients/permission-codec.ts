/**
 * permission-codec — the single owner of the on-chain Permission ABI layout.
 *
 * On-chain struct field order (ClankerGateCore.sol):
 *   target, selector, validAfter, validUntil, singleUse, chainId,
 *   maxValue, authorizedCaller, rules[]
 * ParamRule has exactly FOUR fields: (offset, op, value, values[]).
 *
 * NOTE: this ABI order deliberately differs from the hash-preimage order in
 * builder/leaf.ts (there chainId comes BEFORE singleUse, and rule hashes sit
 * third). Both orders are consensus-critical and locked by on-chain vectors —
 * never "align" one to the other.
 */
import { type Address, type Hash, type Hex, zeroAddress } from 'viem';
import type { ParamRule, Permission } from '../types/index.js';

export const RULE_STRUCT_ABI_STRING =
  '(uint256 offset, uint8 op, bytes32 value, bytes32[] values)';

export const PERMISSION_STRUCT_ABI_STRING =
  `(address target, bytes4 selector, uint48 validAfter, uint48 validUntil, bool singleUse, uint256 chainId, uint256 maxValue, address authorizedCaller, ${RULE_STRUCT_ABI_STRING}[] rules)`;

export interface OnChainRule {
  offset: bigint;
  op: number;
  value: Hash;
  values: readonly Hash[];
}

export interface OnChainPermission {
  target: Address;
  selector: Hex;
  validAfter: number;
  validUntil: number;
  singleUse: boolean;
  chainId: bigint;
  maxValue: bigint;
  authorizedCaller: Address;
  rules: readonly OnChainRule[];
}

/** Convert SDK ParamRules to the on-chain 4-field rule tuples. */
export function toRuleTuples(rules: readonly ParamRule[]): OnChainRule[] {
  return rules.map((r) => ({
    offset: BigInt(r.offset),
    op: r.op,
    value: r.value,
    values: r.values ?? [],
  }));
}

/**
 * Convert a Permission SDK object to the named-field struct shape expected by
 * writeContract / encodeFunctionData / encodeAbiParameters, applying the
 * canonical defaults for optional fields.
 */
export function toOnChainStruct(permission: Permission): OnChainPermission {
  return {
    target: permission.target,
    selector: permission.selector,
    validAfter: permission.validAfter ?? 0,
    validUntil: permission.validUntil ?? 0,
    singleUse: permission.singleUse ?? false,
    chainId: BigInt(permission.chainId ?? 0),
    maxValue: permission.maxValue ?? 0n,
    authorizedCaller: permission.authorizedCaller ?? zeroAddress,
    rules: toRuleTuples(permission.rules),
  };
}

/**
 * Positional args for the on-chain `computePermissionInnerHash` view
 * (target, selector, rules, validAfter, validUntil, chainId, singleUse, maxValue).
 */
export function toInnerHashArgs(permission: Permission) {
  return [
    permission.target,
    permission.selector,
    toRuleTuples(permission.rules),
    permission.validAfter ?? 0,
    permission.validUntil ?? 0,
    BigInt(permission.chainId ?? 0),
    permission.singleUse ?? false,
    permission.maxValue ?? 0n,
  ] as const;
}
