/**
 * @clanker/gate-client
 * 
 * TypeScript SDK for ClankerGate - a policy-based transaction validator
 * for ERC-4337 Smart Accounts and Gnosis Safe modules.
 * 
 * @packageDocumentation
 * 
 * ClankerGate enables fine-grained control over what operations can be
 * performed by external executors without giving them full private key access.
 * 
 * @example Basic Usage - Policy Creation
 * ```typescript
 * import { ClankerGate, UNISWAP_V3_ROUTER_ABI, OP } from '@clanker/gate-client';
 * 
 * // Create a policy using the fluent API
 * const permission = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
 *   .allow()
 *   .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
 *   .fn('exactInput')
 *   .where('params.amountIn')
 *   .lte(BigInt('1000000000000000000')) // Max 1 ETH
 *   .build();
 * 
 * // Build Merkle tree and generate proof
 * const builder = ClankerGate.merkleTree();
 * builder.addPermission(permission);
 * const { root } = builder.build();
 * const proof = builder.getProof(permission);
 * ```
 * 
 * @example ERC-4337 Integration
 * ```typescript
 * import { createClankerGate4337Client, permission } from '@clanker/gate-client';
 * 
 * const client = createClankerGate4337Client({
 *   address: '0x...',
 *   publicClient,
 *   walletClient,
 * });
 * 
 * // Set policy root
 * await client.setPolicyRoot({ account, root });
 * ```
 * 
 * @example Gnosis Safe Integration
 * ```typescript
 * import { createClankerGateSafeClient, permission } from '@clanker/gate-client';
 * 
 * const client = createClankerGateSafeClient({
 *   address: '0x...',
 *   publicClient,
 *   walletClient,
 * });
 * 
 * // Authorize caller
 * await client.authorizeCaller({ safe, caller, account });
 * 
 * // Execute transaction with proof
 * await client.execTransaction({
 *   safe, to, value, data, operation: 0, proof, permission, account
 * });
 * ```
 */

import type { Permission, PolicyConfig, ABIEntry, OpType } from './types/index.js';
import { compilePolicy, createPolicyBuilder } from './policy-compiler/index.js';
import { createMerkleTreeBuilder, hashPermission, verifyMerkleProof, hashPermissionLeaf } from './builder/index.js';
import { createABIRegistry, defaultRegistry } from './abi-registry/index.js';
import { createSimulator, simulator } from './simulator/index.js';

export * from './types/index.js';
export * from './abi-registry/index.js';
export * from './policy-compiler/index.js';
export { resolveOffset, computeSelector, toHex32, validateCalldataLength, getSelectorFromCalldata, isDynamicType, getTupleStaticSize } from './policy-compiler/offset-calculator.js';
export * from './builder/index.js';
export * from './simulator/index.js';
export * from './abi-converter/index.js';
export * from './contracts/index.js';
export * from './clients/index.js';
export {
  Operator,
  type OperatorType,
  OperatorSymbol,
  isOperator,
  compare,
  Selector as DomainSelector,
  InvalidSelectorError,
  Offset,
  InvalidOffsetError as OffsetError,
  ValidationResult as DomainValidationResult,
  ValidationError as DomainValidationError,
  ValidationErrorCode as DomainValidationErrorCode,
  ParamRule as DomainParamRule,
  type ParamRuleProps,
  Permission as DomainPermission,
  type PermissionProps,
  CalldataTooShortError,
  SelectorMismatchError,
  CalldataOutOfRangeError,
  RuleViolationError,
  RootNotSetError,
  InvalidProofError,
  UnauthorizedSignerError,
} from './domain/index.js';
export type {
  MerkleProof,
  HashPermissionPort,
  MerkleTreePort,
  CalldataValidatorPort,
  SignatureValidatorPort,
  ABIResolverPort,
} from './domain/index.js';

/**
 * Main API object for ClankerGate SDK.
 * 
 * Provides convenient methods for:
 * - Creating policies via fluent builder
 * - Compiling policy configurations
 * - Building Merkle trees for on-chain verification
 * - Managing ABIs in a registry
 * 
 * @example
 * ```typescript
 * // Create policy
 * const permission = ClankerGate.policy(abi)
 *   .allow()
 *   .to(targetAddress)
 *   .fn('transfer')
 *   .where('amount')
 *   .lte(maxAmount)
 *   .build();
 * 
 * // Build Merkle tree
 * const tree = ClankerGate.merkleTree();
 * tree.addPermission(permission);
 * const { root } = tree.build();
 * 
 * // Get ABI from registry
 * const abi = ClankerGate.registry.get('UniswapV3Router');
 * ```
 */
export const ClankerGate = {
  /**
   * Creates a fluent policy builder for the given ABI.
   * @param abi - Contract ABI
   * @returns Policy builder with chainable methods
   */
  policy: (abi: readonly ABIEntry[]) => createPolicyBuilder(abi),
  
  /**
   * Compiles a policy configuration into a Permission.
   * @param config - Policy configuration
   * @returns Compiled permission
   */
  compile: (config: PolicyConfig) => compilePolicy(config),
  
  /**
   * Creates a new Merkle tree builder.
   * @returns Empty Merkle tree builder
   */
  merkleTree: () => createMerkleTreeBuilder(),
  
  /**
   * Hashes a permission for use in Merkle tree (legacy, no account/nonce scope).
   */
  hashPermission,

  /**
   * Computes the canonical on-chain Merkle leaf for an account-scoped permission.
   * Reproduces ClankerGateCore.hashPermissionWithAccount(account, permission, nonce) exactly.
   */
  hashPermissionLeaf,

  /**
   * Verifies a Merkle proof against a known root.
   */
  verifyProof: verifyMerkleProof,
  
  /**
   * Creates a new off-chain simulator for testing policies.
   * @returns Simulator instance
   */
  simulator: createSimulator,
  
  /**
   * Default ABI registry with Uniswap V3 Router pre-registered.
   */
  registry: defaultRegistry,
  
  /**
   * Creates a new empty ABI registry.
   */
  createRegistry: createABIRegistry,
} as const;

/**
 * Shorthand function to create a permission from policy components.
 * 
 * @param abi - Contract ABI
 * @param target - Target contract address
 * @param functionName - Function name to allow
 * @param rules - Array of validation rules
 * @returns Compiled permission
 * 
 * @example
 * ```typescript
 * const perm = permission(
 *   UNISWAP_V3_ROUTER_ABI,
 *   '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
 *   'exactInput',
 *   [{ paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') }]
 * );
 * ```
 */
export function permission(
  abi: readonly ABIEntry[],
  target: `0x${string}`,
  functionName: string,
  rules: readonly { paramPath: string; op: OpType; value: bigint | `0x${string}` }[]
): Permission {
  return compilePolicy({ abi, target, functionName, rules });
}
