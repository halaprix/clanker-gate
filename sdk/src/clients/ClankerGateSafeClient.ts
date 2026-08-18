import {
  type Address,
  type Hash,
  type Hex,
  type Account,
  type WalletClient,
  type PublicClient,
  type Chain,
  type Abi,
  encodeFunctionData,
} from 'viem';
import { ClankerGateSafeABI } from '../contracts/index.js';
import type { Permission } from '../types/index.js';
import { toOnChainStruct } from './permission-codec.js';
import { createGateClientBase, type GateClientConfig } from './base.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };

export type ClankerGateSafeClientConfig = GateClientConfig;

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

function execTransactionArgs(params: Omit<ExecTransactionParams, 'account'>) {
  return [
    params.safe,
    params.to,
    params.value,
    params.data,
    params.operation,
    params.proof,
    toOnChainStruct(params.permission),
  ] as const;
}

export function createClankerGateSafeClient(config: ClankerGateSafeClientConfig) {
  const base = createGateClientBase(config, ClankerGateSafeABI as Abi);

  return {
    address: base.address,

    getAuthorization(safe: Address): Promise<{ policyRoot: Hash; nonce: bigint; whitelistVersion: bigint; enabled: boolean }> {
      return base.read('authorizations', [safe]);
    },

    getNonce(safe: Address): Promise<bigint> {
      return base.read<bigint>('nonces', [safe]);
    },

    delegatecallWhitelistVersion(safe: Address, target: Address): Promise<bigint> {
      return base.read<bigint>('delegatecallWhitelistVersion', [safe, target]);
    },

    isAuthorizedCaller(safe: Address, caller: Address): Promise<boolean> {
      return base.read<boolean>('isAuthorizedCaller', [safe, caller]);
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      return base.setPolicyRoot(params.safe, params.root, params.account);
    },

    authorizeCaller(params: AuthorizeCallerParams) {
      return base.write('authorizeCaller', [params.safe, params.caller], params.account);
    },

    deauthorizeCaller(params: AuthorizeCallerParams) {
      return base.write('deauthorizeCaller', [params.safe, params.caller], params.account);
    },

    setDelegatecallWhitelist(params: { safe: Address; target: Address; allowed: boolean; account: Address | Account }) {
      return base.write(
        'setDelegatecallWhitelist',
        [params.safe, params.target, params.allowed],
        params.account
      );
    },

    /**
     * Execute a transaction through the Safe module.
     *
     * execTransaction is non-payable — no ETH is forwarded to the module call
     * itself (the `value` arg is a uint256 passed as a parameter to the Safe).
     */
    execTransaction(params: ExecTransactionParams) {
      return base.write('execTransaction', execTransactionArgs(params), params.account);
    },

    /**
     * Execute a transaction through the Safe module (with proof variant).
     * Non-payable — no ETH forwarded to the module call.
     */
    execTransactionWithProof(params: ExecTransactionParams) {
      return base.write('execTransactionWithProof', execTransactionArgs(params), params.account);
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
        args: execTransactionArgs(params),
      });
    },

    computePermissionHash: base.computePermissionHash,
    computePermissionInnerHash: base.computePermissionInnerHash,
    encodeSetPolicyRoot: base.encodeSetPolicyRoot,
  };
}

export type ClankerGateSafeClient = ReturnType<typeof createClankerGateSafeClient>;
