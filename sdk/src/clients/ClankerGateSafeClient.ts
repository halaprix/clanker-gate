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

    /**
     * Execute a transaction through the Safe module.
     *
     * execTransaction is non-payable — no ETH is forwarded to the module call
     * itself (the `value` arg is a uint256 passed as a parameter to the Safe).
     */
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

    /**
     * Execute a transaction through the Safe module (with proof variant).
     * Non-payable — no ETH forwarded to the module call.
     */
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

    /**
     * Compute the account-scoped permission hash (canonical Merkle leaf).
     *
     * Uses the `computePermissionHash(address account, Permission permission, uint256 nonce)`
     * overload. The old field-based overload has been renamed to `computePermissionInnerHash`.
     */
    async computePermissionHash(safe: Address, permission: Permission, nonce: bigint): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'computePermissionHash',
        args: [safe, encodePermissionStruct(permission), nonce],
      }) as Promise<Hash>;
    },

    /**
     * Compute the inner (field-based) permission hash without a Safe scope.
     * Renamed from the old field-based `computePermissionHash` overload.
     */
    async computePermissionInnerHash(permission: Permission): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGateSafeABI,
        functionName: 'computePermissionInnerHash',
        args: [
          permission.target,
          permission.selector,
          permission.rules.map((r) => ({
            offset: BigInt(r.offset),
            op: r.op,
            value: r.value,
            values: r.values ?? [],
          })),
          permission.validAfter ?? 0,
          permission.validUntil ?? 0,
          BigInt(permission.chainId ?? 0),
          permission.singleUse ?? false,
          permission.maxValue ?? 0n,
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function encodePermissionStruct(permission: Permission): {
  target: Address;
  selector: Hex;
  validAfter: number;
  validUntil: number;
  singleUse: boolean;
  chainId: bigint;
  maxValue: bigint;
  authorizedCaller: Address;
  rules: readonly { offset: bigint; op: number; value: Hash; values: readonly Hash[] }[];
} {
  return {
    target: permission.target,
    selector: permission.selector,
    validAfter: permission.validAfter ?? 0,
    validUntil: permission.validUntil ?? 0,
    singleUse: permission.singleUse ?? false,
    chainId: BigInt(permission.chainId ?? 0),
    maxValue: permission.maxValue ?? 0n,
    authorizedCaller: permission.authorizedCaller ?? '0x0000000000000000000000000000000000000000',
    rules: permission.rules.map((r) => ({
      offset: BigInt(r.offset),
      op: r.op,
      value: r.value,
      values: r.values ?? [],
    })),
  };
}

export type ClankerGateSafeClient = ReturnType<typeof createClankerGateSafeClient>;
