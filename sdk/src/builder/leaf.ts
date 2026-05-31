import { keccak256, encodeAbiParameters, toBytes, zeroAddress } from 'viem';
import type { Address, Hex } from 'viem';
import type { Permission, Hex32, ParamRule } from '../types/index.js';

// DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
const DOMAIN_TYPEHASH = keccak256(
  toBytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
) as Hex32;

/**
 * Computes the EIP-712 domain separator for a ClankerGate deployment.
 *
 * Matches on-chain:
 *   keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ClankerGate"), keccak256("1"), chainId, gateAddress))
 *
 * @param gateAddress - Address of the deployed gate contract
 * @param chainId     - Chain ID of the gate's deployment network (block.chainid)
 * @returns 32-byte domain separator
 */
export function computeDomainSeparator(gateAddress: Address, chainId: bigint): Hex32 {
  const nameHash = keccak256(toBytes('ClankerGate')) as Hex32;
  const versionHash = keccak256(toBytes('1')) as Hex32;

  const encoded = encodeAbiParameters(
    [
      { type: 'bytes32' },
      { type: 'bytes32' },
      { type: 'bytes32' },
      { type: 'uint256' },
      { type: 'address' },
    ],
    [DOMAIN_TYPEHASH, nameHash, versionHash, chainId, gateAddress]
  );

  return keccak256(encoded) as Hex32;
}

/**
 * Hashes a single ParamRule.
 *
 * Matches on-chain:
 *   keccak256(abi.encode(offset, op, value, values))
 */
function hashRule(rule: ParamRule): Hex32 {
  const encoded = encodeAbiParameters(
    [
      { type: 'uint256' },
      { type: 'uint8' },
      { type: 'bytes32' },
      { type: 'bytes32[]' },
    ],
    [BigInt(rule.offset), rule.op, rule.value, rule.values ?? []]
  );
  return keccak256(encoded) as Hex32;
}

/**
 * Hashes a Permission struct using the provided domain separator.
 *
 * Matches on-chain (two-step):
 *   encodedPermission = keccak256(abi.encode(target, selector, ruleHashes, validAfter, validUntil, chainId, singleUse, maxValue, authorizedCaller))
 *   permHash          = keccak256(abi.encode(domainSeparator, encodedPermission))
 *
 * Field order matters: chainId appears BEFORE singleUse.
 * Defaults: maxValue=0n, authorizedCaller=zeroAddress, singleUse=false.
 *
 * @param permission      - The permission to hash
 * @param domainSeparator - Pre-computed domain separator from computeDomainSeparator()
 * @returns 32-byte permission hash (permHash)
 */
export function hashPermissionStruct(permission: Permission, domainSeparator: Hex32): Hex32 {
  const ruleHashes: Hex32[] = permission.rules.map(hashRule);

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
  ) as Hex32;

  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }],
      [domainSeparator, encodedPermission]
    )
  ) as Hex32;
}

/**
 * Computes the canonical Merkle leaf for an account-scoped permission.
 *
 * Reproduces on-chain ClankerGateCore.hashPermissionWithAccount exactly:
 *   leaf = keccak256(abi.encode(account, hashPermission(permission), nonce))
 *
 * where hashPermission() = keccak256(abi.encode(domainSeparator, encodedPermission))
 * and   domainSeparator  = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ClankerGate"), keccak256("1"), chainId, gateAddress))
 *
 * @param params.permission   - The permission to hash
 * @param params.account      - The account address the permission is scoped to
 * @param params.nonce        - The policy epoch nonce for the account
 * @param params.gateAddress  - Address of the deployed gate contract
 * @param params.chainId      - Chain ID of the gate's deployment network
 * @returns 32-byte leaf hash
 *
 * @example
 * ```typescript
 * const leaf = hashPermissionLeaf({
 *   permission,
 *   account: '0x1234...',
 *   nonce: 0n,
 *   gateAddress: '0xGate...',
 *   chainId: 1n,
 * });
 * ```
 */
export function hashPermissionLeaf({
  permission,
  account,
  nonce,
  gateAddress,
  chainId,
}: {
  permission: Permission;
  account: Address;
  nonce: bigint;
  gateAddress: Address;
  chainId: bigint;
}): Hex32 {
  const domainSeparator = computeDomainSeparator(gateAddress, chainId);
  const permHash = hashPermissionStruct(permission, domainSeparator);

  return keccak256(
    encodeAbiParameters(
      [{ type: 'address' }, { type: 'bytes32' }, { type: 'uint256' }],
      [account, permHash, nonce]
    )
  ) as Hex32;
}
