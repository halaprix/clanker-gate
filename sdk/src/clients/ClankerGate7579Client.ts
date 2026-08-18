import {
  type Address,
  type Hash,
  type Hex,
  type Account,
  type WalletClient,
  type PublicClient,
  type Chain,
  encodeFunctionData,
  encodeAbiParameters,
  parseAbiParameters,
} from 'viem';
import { ClankerGate7579ABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';
import { packUserOpSignature } from './guardData.js';
import { toInnerHashArgs, toOnChainStruct } from './permission-codec.js';
import type { PackedUserOperation } from './ClankerGate4337Client.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };
export type { PackedUserOperation };

export interface ClankerGate7579ClientConfig {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  chain?: Chain | null;
}

/**
 * The six-field config returned by getAccountConfig.
 * Field order from ABI: owner, policyRoot, nonce, signatureValidator, installed, policyAdmin
 */
export interface AccountConfig {
  owner: Address;
  policyRoot: Hash;
  nonce: bigint;
  signatureValidator: Address;
  installed: boolean;
  policyAdmin: Address;
}

export interface OnInstallParams {
  account: Address | Account;
  owner: Address;
  policyRoot: Hash;
  signatureValidator: Address;
}

export interface SetPolicyRootParams {
  account: Address | Account;
  targetAccount: Address;
  root: Hash;
}

export interface SetOwnerParams {
  account: Address | Account;
  targetAccount: Address;
  newOwner: Address;
}

export interface SetPolicyAdminParams {
  account: Address | Account;
  targetAccount: Address;
  admin: Address;
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

export function createClankerGate7579Client(config: ClankerGate7579ClientConfig) {
  const { address, publicClient, walletClient, chain } = config;

  return {
    address,

    /**
     * Returns the full six-field AccountConfig for a given account.
     * Field order: owner, policyRoot, nonce, signatureValidator, installed, policyAdmin
     */
    async getAccountConfig(account: Address): Promise<AccountConfig> {
      const result = await publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'getAccountConfig',
        args: [account],
      }) as [Address, Hash, bigint, Address, boolean, Address];

      return {
        owner: result[0],
        policyRoot: result[1],
        nonce: result[2],
        signatureValidator: result[3],
        installed: result[4],
        policyAdmin: result[5],
      };
    },

    async isModuleInstalled(account: Address): Promise<boolean> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'isModuleInstalled',
        args: [account],
      }) as Promise<boolean>;
    },

    /**
     * Query whether this validator satisfies a given ERC-7579 module type ID.
     * Replaces the old `moduleType()` function.
     *
     * @param moduleTypeId  1 = validator, 2 = executor, 3 = fallback, 4 = hook
     */
    async isModuleType(moduleTypeId: bigint): Promise<boolean> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'isModuleType',
        args: [moduleTypeId],
      }) as Promise<boolean>;
    },

    /**
     * Validate a signature using ERC-1271 with sender context.
     * Added in the new contract interface.
     */
    async isValidSignatureWithSender(sender: Address, hash: Hash, signature: Hex): Promise<Hex> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'isValidSignatureWithSender',
        args: [sender, hash, signature],
      }) as Promise<Hex>;
    },

    onInstall(params: OnInstallParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      const initData = encodeAbiParameters(
        parseAbiParameters('address, bytes32, address'),
        [params.owner, params.policyRoot, params.signatureValidator]
      );

      return walletClient.writeContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'onInstall',
        args: [initData],
        account: params.account,
        chain,
      });
    },

    onUninstall(params: { account: Address | Account }) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'onUninstall',
        args: ['0x'],
        account: params.account,
        chain,
      });
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'setPolicyRoot',
        args: [params.targetAccount, params.root],
        account: params.account,
        chain,
      });
    },

    setOwner(params: SetOwnerParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'setOwner',
        args: [params.targetAccount, params.newOwner],
        account: params.account,
        chain,
      });
    },

    /**
     * Set the policy admin for an account.
     */
    setPolicyAdmin(params: SetPolicyAdminParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGate7579ABI,
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
     * calls the 2-arg `validateUserOp(userOp, userOpHash)`.
     */
    async validateUserOp(params: ValidateUserOpParams): Promise<bigint> {
      const { userOp, userOpHash, guardData } = params;

      const packedSignature = packUserOpSignature({
        proof: guardData.proof,
        permission: guardData.permission,
        ownerSignature: guardData.ownerSignature,
      });

      const packedOp: PackedUserOperation = { ...userOp, signature: packedSignature };

      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
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
     * Compute the account-scoped permission hash (canonical Merkle leaf).
     */
    async computePermissionHash(account: Address, permission: Permission, nonce: bigint): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'computePermissionHash',
        args: [account, toOnChainStruct(permission), nonce],
      }) as Promise<Hash>;
    },

    /**
     * Compute the inner (field-based) permission hash — renamed from the old
     * field-based `computePermissionHash` overload to `computePermissionInnerHash`.
     */
    async computePermissionInnerHash(permission: Permission): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'computePermissionInnerHash',
        args: toInnerHashArgs(permission),
      }) as Promise<Hash>;
    },

    encodeOnInstall(owner: Address, policyRoot: Hash, signatureValidator: Address): Hex {
      const initData = encodeAbiParameters(
        parseAbiParameters('address, bytes32, address'),
        [owner, policyRoot, signatureValidator]
      );

      return encodeFunctionData({
        abi: ClankerGate7579ABI,
        functionName: 'onInstall',
        args: [initData],
      });
    },

    encodeOnUninstall(): Hex {
      return encodeFunctionData({
        abi: ClankerGate7579ABI,
        functionName: 'onUninstall',
        args: ['0x'],
      });
    },

    encodeSetPolicyRoot(targetAccount: Address, root: Hash): Hex {
      return encodeFunctionData({
        abi: ClankerGate7579ABI,
        functionName: 'setPolicyRoot',
        args: [targetAccount, root],
      });
    },
  };
}

export type ClankerGate7579Client = ReturnType<typeof createClankerGate7579Client>;
