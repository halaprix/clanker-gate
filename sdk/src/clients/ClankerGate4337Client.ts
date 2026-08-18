import {
  type Address,
  type Hash,
  type Hex,
  type Account,
  type WalletClient,
  type PublicClient,
  type Chain,
  type Abi,
} from 'viem';
import { ClankerGate4337ABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';
import { toOnChainStruct } from './permission-codec.js';
import {
  createGateClientBase,
  type GateClientConfig,
  type PackedUserOperation,
  type ValidateUserOpGuardParams,
} from './base.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };
export type { PackedUserOperation };

export type ClankerGate4337ClientConfig = GateClientConfig;

export interface SetPolicyRootParams {
  account: Address | Account;
  root: Hash;
}

export type ValidateUserOpParams = ValidateUserOpGuardParams;

export interface SetPolicyRootWithPermissionParams {
  /** The account whose policy root is being updated */
  account: Address | Account;
  /** Merkle-leaf permission that authorises the root update */
  permission: Permission;
}

export interface SetPolicyAdminParams {
  account: Address | Account;
  /** The account whose admin is being set */
  targetAccount: Address;
  /** The new admin address (zero address to clear) */
  admin: Address;
}

export function createClankerGate4337Client(config: ClankerGate4337ClientConfig) {
  const base = createGateClientBase(config, ClankerGate4337ABI as Abi);

  return {
    address: base.address,

    getPolicyRoot(account: Address): Promise<Hash> {
      return base.read<Hash>('policyRoots', [account]);
    },

    getNonce(account: Address): Promise<bigint> {
      return base.read<bigint>('nonces', [account]);
    },

    getPolicyAdmin(account: Address): Promise<Address> {
      return base.read<Address>('policyAdmin', [account]);
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      return base.setPolicyRoot(params.account, params.root, params.account);
    },

    /**
     * Set the policy root using a signed permission (no nonce arg — nonce is
     * now looked up on-chain inside the contract).
     */
    setPolicyRootWithPermission(params: SetPolicyRootWithPermissionParams) {
      return base.write(
        'setPolicyRootWithPermission',
        [params.account, toOnChainStruct(params.permission)],
        params.account
      );
    },

    /**
     * Set the policy admin for a given account.
     * Only the account itself (or current admin) can call this.
     */
    setPolicyAdmin(params: SetPolicyAdminParams) {
      return base.write('setPolicyAdmin', [params.targetAccount, params.admin], params.account);
    },

    /**
     * Validate a user operation.
     *
     * Packs proof + permission + ownerSignature into `userOp.signature` and
     * then calls the 2-arg `validateUserOp(userOp, userOpHash)`.
     *
     * @returns validationData uint256 (0 = success, 1 = failure, or packed sigFail|validUntil|validAfter)
     */
    validateUserOp(params: ValidateUserOpParams): Promise<bigint> {
      return base.validateUserOp(params);
    },

    computePermissionHash: base.computePermissionHash,
    computePermissionInnerHash: base.computePermissionInnerHash,
    encodeSetPolicyRoot: base.encodeSetPolicyRoot,
  };
}

export type ClankerGate4337Client = ReturnType<typeof createClankerGate4337Client>;
