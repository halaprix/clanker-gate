import {
  type Address,
  type Hash,
  type Hex,
  type Account,
  type WalletClient,
  type PublicClient,
  type Chain,
  encodeFunctionData,
} from 'viem';
import { ClankerGate4337ABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';
import { packUserOpSignature } from './guardData.js';
import { toInnerHashArgs, toOnChainStruct } from './permission-codec.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };

export interface ClankerGate4337ClientConfig {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  chain?: Chain | null;
}

export interface SetPolicyRootParams {
  account: Address | Account;
  root: Hash;
}

/**
 * PackedUserOperation as defined in ERC-4337 v0.7.
 *
 * The gas fields are packed into two bytes32 values:
 *   accountGasLimits = callGasLimit (hi 128 bits) | verificationGasLimit (lo 128 bits)
 *   gasFees          = maxPriorityFeePerGas (hi) | maxFeePerGas (lo)
 */
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  /** callGasLimit (hi 128 bits) | verificationGasLimit (lo 128 bits) */
  accountGasLimits: Hash;
  preVerificationGas: bigint;
  /** maxPriorityFeePerGas (hi 128 bits) | maxFeePerGas (lo 128 bits) */
  gasFees: Hash;
  paymasterAndData: Hex;
  /** MUST contain abi.encode(bytes32[] proof, Permission permission, bytes ownerSig) */
  signature: Hex;
}

export interface ValidateUserOpParams {
  userOp: PackedUserOperation;
  userOpHash: Hash;
  guardData: {
    proof: readonly Hash[];
    permission: Permission;
    ownerSignature: Hex;
  };
}

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
  const { address, publicClient, walletClient, chain } = config;

  return {
    address,

    async getPolicyRoot(account: Address): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'policyRoots',
        args: [account],
      }) as Promise<Hash>;
    },

    async getNonce(account: Address): Promise<bigint> {
      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'nonces',
        args: [account],
      }) as Promise<bigint>;
    },

    async getPolicyAdmin(account: Address): Promise<Address> {
      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'policyAdmin',
        args: [account],
      }) as Promise<Address>;
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'setPolicyRoot',
        args: [params.account, params.root],
        account: params.account,
        chain,
      });
    },

    /**
     * Set the policy root using a signed permission (no nonce arg — nonce is
     * now looked up on-chain inside the contract).
     */
    setPolicyRootWithPermission(params: SetPolicyRootWithPermissionParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'setPolicyRootWithPermission',
        args: [params.account, toOnChainStruct(params.permission)],
        account: params.account,
        chain,
      });
    },

    /**
     * Set the policy admin for a given account.
     * Only the account itself (or current admin) can call this.
     */
    setPolicyAdmin(params: SetPolicyAdminParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'setPolicyAdmin',
        args: [params.targetAccount, params.admin],
        account: params.account,
        chain,
      });
    },

    /**
     * Validate a user operation.
     *
     * Packs proof + permission + ownerSignature into `userOp.signature` and
     * then calls the 2-arg `validateUserOp(userOp, userOpHash)`.
     *
     * @returns validationData uint256 (0 = success, 1 = failure, or packed sigFail|validUntil|validAfter)
     */
    async validateUserOp(params: ValidateUserOpParams): Promise<bigint> {
      const { userOp, userOpHash, guardData } = params;

      // Pack the guard data into userOp.signature
      const packedSignature = packUserOpSignature({
        proof: guardData.proof,
        permission: guardData.permission,
        ownerSignature: guardData.ownerSignature,
      });

      const packedOp: PackedUserOperation = { ...userOp, signature: packedSignature };

      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'validateUserOp',
        args: [
          [
            packedOp.sender,
            packedOp.nonce,
            packedOp.initCode,
            packedOp.callData,
            packedOp.accountGasLimits,
            packedOp.preVerificationGas,
            packedOp.gasFees,
            packedOp.paymasterAndData,
            packedOp.signature,
          ],
          userOpHash,
        ],
      }) as Promise<bigint>;
    },

    /**
     * Compute the account-scoped permission hash (canonical leaf used in the Merkle tree).
     */
    async computePermissionHash(account: Address, permission: Permission, nonce: bigint): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'computePermissionHash',
        args: [account, toOnChainStruct(permission), nonce],
      }) as Promise<Hash>;
    },

    /**
     * Compute the inner (field-based) permission hash without an account scope.
     * Renamed from `computePermissionHash` (field-based overload) on this branch.
     */
    async computePermissionInnerHash(permission: Permission): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'computePermissionInnerHash',
        args: toInnerHashArgs(permission),
      }) as Promise<Hash>;
    },

    encodeSetPolicyRoot(account: Address, root: Hash): Hex {
      return encodeFunctionData({
        abi: ClankerGate4337ABI,
        functionName: 'setPolicyRoot',
        args: [account, root],
      });
    },
  };
}

export type ClankerGate4337Client = ReturnType<typeof createClankerGate4337Client>;
