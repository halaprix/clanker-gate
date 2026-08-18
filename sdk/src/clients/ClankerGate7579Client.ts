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
  encodeAbiParameters,
  parseAbiParameters,
} from 'viem';
import { ClankerGate7579ABI } from '../contracts/index.js';
import {
  createGateClientBase,
  type GateClientConfig,
  type PackedUserOperation,
  type ValidateUserOpGuardParams,
} from './base.js';

export type { Address, Hash, Hex, Account, WalletClient, PublicClient, Chain };
export type { PackedUserOperation };

export type ClankerGate7579ClientConfig = GateClientConfig;

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

export type ValidateUserOpParams = ValidateUserOpGuardParams;

function encodeInstallData(owner: Address, policyRoot: Hash, signatureValidator: Address): Hex {
  return encodeAbiParameters(
    parseAbiParameters('address, bytes32, address'),
    [owner, policyRoot, signatureValidator]
  );
}

export function createClankerGate7579Client(config: ClankerGate7579ClientConfig) {
  const base = createGateClientBase(config, ClankerGate7579ABI as Abi);

  return {
    address: base.address,

    /**
     * Returns the full six-field AccountConfig for a given account.
     * Field order: owner, policyRoot, nonce, signatureValidator, installed, policyAdmin
     */
    async getAccountConfig(account: Address): Promise<AccountConfig> {
      const result = await base.read<[Address, Hash, bigint, Address, boolean, Address]>(
        'getAccountConfig',
        [account]
      );

      return {
        owner: result[0],
        policyRoot: result[1],
        nonce: result[2],
        signatureValidator: result[3],
        installed: result[4],
        policyAdmin: result[5],
      };
    },

    isModuleInstalled(account: Address): Promise<boolean> {
      return base.read<boolean>('isModuleInstalled', [account]);
    },

    /**
     * Query whether this validator satisfies a given ERC-7579 module type ID.
     * Replaces the old `moduleType()` function.
     *
     * @param moduleTypeId  1 = validator, 2 = executor, 3 = fallback, 4 = hook
     */
    isModuleType(moduleTypeId: bigint): Promise<boolean> {
      return base.read<boolean>('isModuleType', [moduleTypeId]);
    },

    /**
     * Validate a signature using ERC-1271 with sender context.
     * Added in the new contract interface.
     */
    isValidSignatureWithSender(sender: Address, hash: Hash, signature: Hex): Promise<Hex> {
      return base.read<Hex>('isValidSignatureWithSender', [sender, hash, signature]);
    },

    onInstall(params: OnInstallParams) {
      const initData = encodeInstallData(params.owner, params.policyRoot, params.signatureValidator);
      return base.write('onInstall', [initData], params.account);
    },

    onUninstall(params: { account: Address | Account }) {
      return base.write('onUninstall', ['0x'], params.account);
    },

    setPolicyRoot(params: SetPolicyRootParams) {
      return base.setPolicyRoot(params.targetAccount, params.root, params.account);
    },

    setOwner(params: SetOwnerParams) {
      return base.write('setOwner', [params.targetAccount, params.newOwner], params.account);
    },

    /**
     * Set the policy admin for an account.
     */
    setPolicyAdmin(params: SetPolicyAdminParams) {
      return base.write('setPolicyAdmin', [params.targetAccount, params.admin], params.account);
    },

    /**
     * Validate a user operation.
     *
     * Packs proof + permission + ownerSignature into `userOp.signature` and
     * calls the 2-arg `validateUserOp(userOp, userOpHash)`.
     */
    validateUserOp(params: ValidateUserOpParams): Promise<bigint> {
      return base.validateUserOp(params);
    },

    encodeOnInstall(owner: Address, policyRoot: Hash, signatureValidator: Address): Hex {
      return encodeFunctionData({
        abi: ClankerGate7579ABI,
        functionName: 'onInstall',
        args: [encodeInstallData(owner, policyRoot, signatureValidator)],
      });
    },

    encodeOnUninstall(): Hex {
      return encodeFunctionData({
        abi: ClankerGate7579ABI,
        functionName: 'onUninstall',
        args: ['0x'],
      });
    },

    computePermissionHash: base.computePermissionHash,
    computePermissionInnerHash: base.computePermissionInnerHash,
    encodeSetPolicyRoot: base.encodeSetPolicyRoot,
  };
}

export type ClankerGate7579Client = ReturnType<typeof createClankerGate7579Client>;
