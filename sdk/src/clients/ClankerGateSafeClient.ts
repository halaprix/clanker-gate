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
import { ClankerGateSafeABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };

export interface ClankerGateSafeClientConfig {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  chain?: Chain | null;
}

export interface SetPolicyRootParams {
  safe: Address;
  root: Hash;
  account: Address | Account;
}

export interface AuthorizeCallerParams {
  safe: Address;
  caller: Address;
  account: Address | Account;
}

export interface ExecTransactionParams {
  safe: Address;
  to: Address;
  value: bigint;
  data: Hex;
  operation: 0 | 1;
  proof: readonly Hash[];
  permission: Permission;
  account: Address | Account;
}

export interface PolicyRootSetEvent {
  safe: Address;
  root: Hash;
  nonce: bigint;
}

export interface CallerAuthorizedEvent {
  safe: Address;
  caller: Address;
}

export interface ExecutionSucceededEvent {
  safe: Address;
  caller: Address;
  target: Address;
  selector: Hex;
}

export function createClankerGateSafeClient(config: ClankerGateSafeClientConfig) {
  const { address, publicClient, walletClient, chain } = config;

  return {
    address,

    async getAuthorization(safe: Address): Promise<{ policyRoot: Hash; nonce: bigint; whitelistVersion: bigint; enabled: boolean }> {
      const result = await publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'authorizations',
        args: [safe],
      });
      return result as { policyRoot: Hash; nonce: bigint; whitelistVersion: bigint; enabled: boolean };
    },

    async getNonce(safe: Address): Promise<bigint> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'nonces',
        args: [safe],
      }) as Promise<bigint>;
    },

    async delegatecallWhitelistVersion(safe: Address, target: Address): Promise<bigint> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'delegatecallWhitelistVersion',
        args: [safe, target],
      }) as Promise<bigint>;
    },

    async isAuthorizedCaller(safe: Address, caller: Address): Promise<boolean> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'isAuthorizedCaller',
        args: [safe, caller],
      }) as Promise<boolean>;
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'setPolicyRoot',
        args: [params.safe, params.root],
        account: params.account,
        chain,
      });
    },

    authorizeCaller(params: AuthorizeCallerParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'authorizeCaller',
        args: [params.safe, params.caller],
        account: params.account,
        chain,
      });
    },

    deauthorizeCaller(params: AuthorizeCallerParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'deauthorizeCaller',
        args: [params.safe, params.caller],
        account: params.account,
        chain,
      });
    },

    setDelegatecallWhitelist(params: { safe: Address; target: Address; allowed: boolean; account: Address | Account }) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'setDelegatecallWhitelist',
        args: [params.safe, params.target, params.allowed],
        account: params.account,
        chain,
      });
    },

    execTransaction(params: ExecTransactionParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'execTransaction',
        args: [
          params.safe,
          params.to,
          params.value,
          params.data,
          params.operation,
          params.proof,
          encodePermissionStruct(params.permission),
        ],
        account: params.account,
        chain,
      });
    },

    execTransactionWithProof(params: ExecTransactionParams) {
      if (!walletClient) {
        throw new Error('Wallet client required for write operations');
      }

      return walletClient.writeContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'execTransactionWithProof',
        args: [
          params.safe,
          params.to,
          params.value,
          params.data,
          params.operation,
          params.proof,
          encodePermissionStruct(params.permission),
        ],
        account: params.account,
        chain,
      });
    },

    async computePermissionHash(permission: Permission): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'computePermissionHash',
        args: [
          permission.target,
          permission.selector,
          permission.rules.map((r) => ({
            offset: BigInt(r.offset),
            op: r.op,
            value: r.value,
          })),
          permission.validAfter,
          permission.validUntil,
          BigInt(permission.chainId),
        ],
      }) as Promise<Hash>;
    },

    encodeSetPolicyRoot(safe: Address, root: Hash): Hex {
      return encodeFunctionData({
        abi: ClankerGateSafeABI,
        functionName: 'setPolicyRoot',
        args: [safe, root],
      });
    },

    encodeAuthorizeCaller(safe: Address, caller: Address): Hex {
      return encodeFunctionData({
        abi: ClankerGateSafeABI,
        functionName: 'authorizeCaller',
        args: [safe, caller],
      });
    },

    encodeExecTransaction(params: Omit<ExecTransactionParams, 'account'>): Hex {
      return encodeFunctionData({
        abi: ClankerGateSafeABI,
        functionName: 'execTransaction',
        args: [
          params.safe,
          params.to,
          params.value,
          params.data,
          params.operation,
          params.proof,
          encodePermissionStruct(params.permission),
        ],
      });
    },
  };
}

function encodePermissionStruct(permission: Permission): {
  target: Address;
  selector: Hex;
  rules: readonly { offset: bigint; op: number; value: Hash; values: readonly Hash[] }[];
  validAfter: number;
  validUntil: number;
  chainId: bigint;
  singleUse: boolean;
  maxValue: bigint;
  authorizedCaller: Address;
} {
  return {
    target: permission.target,
    selector: permission.selector,
    rules: permission.rules.map((r) => ({
      offset: BigInt(r.offset),
      op: r.op,
      value: r.value,
      values: r.values ?? [],
    })),
    validAfter: permission.validAfter,
    validUntil: permission.validUntil,
    chainId: BigInt(permission.chainId),
    singleUse: permission.singleUse ?? false,
    maxValue: permission.maxValue ?? 0n,
    authorizedCaller: permission.authorizedCaller ?? '0x0000000000000000000000000000000000000000',
  };
}

export type ClankerGateSafeClient = ReturnType<typeof createClankerGateSafeClient>;
