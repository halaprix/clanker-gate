/**
 * base — shared implementation behind the three gate clients.
 *
 * Owns everything that is identical across ClankerGate4337 / 7579 / Safe:
 * the config shape, the wallet-client guard, the read/write wrappers, the
 * permission-hash views, setPolicyRoot, and userOp validation packing.
 * Each standard's client file keeps only its genuine surface.
 */
import {
  type Abi,
  type Address,
  type Hash,
  type Hex,
  type Account,
  type WalletClient,
  type PublicClient,
  type Chain,
  encodeFunctionData,
} from 'viem';
import type { Permission } from '../types/index.js';
import { toInnerHashArgs, toOnChainStruct } from './permission-codec.js';
import { packUserOpSignature } from './guardData.js';

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

export interface GateClientConfig {
  address: Address;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  chain?: Chain | null;
}

export interface ValidateUserOpGuardParams {
  userOp: PackedUserOperation;
  userOpHash: Hash;
  guardData: {
    proof: readonly Hash[];
    permission: Permission;
    ownerSignature: Hex;
  };
}

export function createGateClientBase(config: GateClientConfig, abi: Abi) {
  const { address, publicClient, walletClient, chain } = config;

  function read<T>(functionName: string, args: readonly unknown[] = []): Promise<T> {
    return publicClient.readContract({ address, abi, functionName, args }) as Promise<T>;
  }

  function write(functionName: string, args: readonly unknown[], account: Address | Account) {
    if (!walletClient) {
      throw new Error('Wallet client required for write operations');
    }
    return walletClient.writeContract({ address, abi, functionName, args, account, chain });
  }

  return {
    address,
    read,
    write,

    /** Compute the account-scoped permission hash (canonical Merkle leaf). */
    computePermissionHash(account: Address, permission: Permission, nonce: bigint): Promise<Hash> {
      return read<Hash>('computePermissionHash', [account, toOnChainStruct(permission), nonce]);
    },

    /** Compute the inner (field-based) permission hash without an account scope. */
    computePermissionInnerHash(permission: Permission): Promise<Hash> {
      return read<Hash>('computePermissionInnerHash', toInnerHashArgs(permission));
    },

    /** target = the account/safe whose root is set; account = the tx signer. */
    setPolicyRoot(target: Address | Account, root: Hash, account: Address | Account) {
      return write('setPolicyRoot', [target, root], account);
    },

    encodeSetPolicyRoot(target: Address, root: Hash): Hex {
      return encodeFunctionData({ abi, functionName: 'setPolicyRoot', args: [target, root] });
    },

    /**
     * Pack proof + permission + ownerSignature into `userOp.signature` and
     * call the 2-arg `validateUserOp(userOp, userOpHash)` view (4337 / 7579).
     */
    validateUserOp(params: ValidateUserOpGuardParams): Promise<bigint> {
      const { userOp, userOpHash, guardData } = params;
      const signature = packUserOpSignature(guardData);
      const packedOp = { ...userOp, signature };
      return read<bigint>('validateUserOp', [
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
      ]);
    },
  };
}

export type GateClientBase = ReturnType<typeof createGateClientBase>;
