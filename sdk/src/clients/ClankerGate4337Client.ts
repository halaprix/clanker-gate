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
import { ClankerGate4337ABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';

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

export interface ValidateUserOpParams {
  userOp: {
    sender: Address;
    nonce: bigint;
    initCode: Hex;
    callData: Hex;
    callGasLimit: bigint;
    verificationGasLimit: bigint;
    preVerificationGas: bigint;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
    paymasterAndData: Hex;
    signature: Hex;
  };
  userOpHash: Hash;
  guardData: {
    proof: readonly Hash[];
    permission: Permission;
    signature: Hex;
  };
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

    async validateUserOp(params: ValidateUserOpParams): Promise<bigint> {
      const { userOp, userOpHash, guardData } = params;

      const encodedPermission = encodePermission(guardData.permission);

      return publicClient.readContract({
        address,
        abi: ClankerGate4337ABI,
        functionName: 'validateUserOp',
        args: [
          [
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData,
            userOp.signature,
          ],
          userOpHash,
          encodeGuardData(guardData.proof, encodedPermission, guardData.signature),
        ],
      }) as Promise<bigint>;
    },

    encodeSetPolicyRoot(root: Hash): Hex {
      return encodeFunctionData({
        abi: ClankerGate4337ABI,
        functionName: 'setPolicyRoot',
        args: [root],
      });
    },
  };
}

function encodePermission(permission: Permission): readonly [Address, Hex, readonly (readonly [bigint, number, Hex, readonly Hex[], bigint])[], number, number, bigint, boolean, bigint, Address] {
  const rulesEncoded = permission.rules.map((rule): readonly [bigint, number, Hex, readonly Hex[], bigint] => [
    BigInt(rule.offset),
    rule.op,
    rule.value,
    rule.values ?? ([] as readonly Hex[]),
    rule.maxValue !== undefined ? BigInt(rule.maxValue) : 0n,
  ]);

  return [
    permission.target,
    permission.selector,
    rulesEncoded,
    permission.validAfter,
    permission.validUntil,
    BigInt(permission.chainId),
    permission.singleUse ?? false,
    permission.maxValue ?? 0n,
    permission.authorizedCaller ?? '0x0000000000000000000000000000000000000000',
  ];
}

function encodeGuardData(proof: readonly Hash[], permission: ReturnType<typeof encodePermission>, signature: Hex): Hex {
  return encodeAbiParameters(
    parseAbiParameters('bytes32[], (address, bytes4, (uint256, uint8, bytes32, bytes32[], uint256)[], uint48, uint48, uint256, bool, uint256, address), bytes'),
    [proof, permission, signature]
  );
}

export type ClankerGate4337Client = ReturnType<typeof createClankerGate4337Client>;
