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

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };

export interface ClankerGate7579ClientConfig {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  chain?: Chain | null;
}

export interface AccountConfig {
  owner: Address;
  policyRoot: Hash;
  nonce: bigint;
  signatureValidator: Address;
  installed: boolean;
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

export interface ComputePermissionHashParams {
  target: Address;
  selector: Hex;
  rules: readonly {
    offset: bigint;
    op: number;
    value: Hash;
    values: readonly Hash[];
  }[];
  validAfter: number;
  validUntil: number;
  chainId: bigint;
}

export function createClankerGate7579Client(config: ClankerGate7579ClientConfig) {
  const { address, publicClient, walletClient, chain } = config;

  return {
    address,

    async getAccountConfig(account: Address): Promise<AccountConfig> {
      const result = await publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'accountConfigs',
        args: [account],
      }) as [Address, Hash, bigint, Address, boolean];

      return {
        owner: result[0],
        policyRoot: result[1],
        nonce: result[2],
        signatureValidator: result[3],
        installed: result[4],
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

    async moduleType(): Promise<bigint> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'moduleType',
      }) as Promise<bigint>;
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

    async computePermissionHash(params: ComputePermissionHashParams): Promise<Hash> {
      return publicClient.readContract({
        address,
        abi: ClankerGate7579ABI,
        functionName: 'computePermissionHash',
        args: [
          params.target,
          params.selector,
          params.rules,
          params.validAfter,
          params.validUntil,
          params.chainId,
        ],
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
