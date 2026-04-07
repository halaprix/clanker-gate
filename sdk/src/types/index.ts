import type { Address, Hex } from 'viem';

/**
 * Comparison operators for policy rules.
 * Used to validate calldata values against defined constraints.
 */
export const OP = {
  /** Equal - value must match exactly */
  EQ: 0,
  /** Greater than - value must be strictly greater */
  GT: 1,
  /** Less than - value must be strictly less */
  LT: 2,
  /** Greater than or equal - value must be greater or match */
  GTE: 3,
  /** Less than or equal - value must be less or match */
  LTE: 4,
  /** In - value must be in the set of allowed values */
  IN: 5,
} as const;

/** Union type of all valid operator types */
export type OpType = (typeof OP)[keyof typeof OP];

/** 4-byte function selector (e.g., "0xc04b8d59") */
export type Selector = Hex;

/** 32-byte hex string (64 hex characters) */
export type Hex32 = Hex;

/**
 * A single validation rule applied to calldata at a specific offset.
 * 
 * @example
 * ```typescript
 * // Single value comparison
 * const rule: ParamRule = {
 *   offset: 128,
 *   op: OP.LTE,
 *   value: '0x...1e18'  // 1 ETH in hex32 format
 * };
 * 
 * // Multiple allowed values (OP_IN)
 * const inRule: ParamRule = {
 *   offset: 0,
 *   op: OP.IN,
 *   value: '0x0000000000000000000000000000000000000000000000000000000000000000', // unused
 *   values: [
 *     '0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 *     '0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 *   ]
 * };
 * ```
 */
export interface ParamRule {
  /** Byte offset in calldata where the value is located (excluding 4-byte selector) */
  readonly offset: number;
  /** Comparison operator to apply */
  readonly op: OpType;
  /** Expected value as 32-byte hex string (used for OP_EQ, OP_GT, OP_LT, OP_GTE, OP_LTE) */
  readonly value: Hex32;
  /** Array of allowed values (used for OP_IN) */
  readonly values?: readonly Hex32[];
}

/**
 * A permission defines what operations are allowed for a specific target contract.
 * 
 * Contains the target address, function selector, validation rules, and session lifecycle parameters.
 * 
 * @example
 * ```typescript
 * const permission: Permission = {
 *   target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap V3 Router
 *   selector: '0xc04b8d59', // exactInput
 *   rules: [
 *     { offset: 128, op: OP.LTE, value: toHex32(BigInt('1000000000000000000')) }
 *   ],
 *   validAfter: 0,           // Valid immediately (0 = no start time)
 *   validUntil: 1735689600,  // Expires Jan 1, 2025 (0 = never expires)
 *   chainId: 1,              // Ethereum mainnet only (0 = all chains)
 *   singleUse: true,         // Can only be used once
 * };
 * ```
 */
export interface Permission {
  /** Target contract address */
  readonly target: Address;
  /** 4-byte function selector */
  readonly selector: Selector;
  /** Array of validation rules (can be empty) */
  readonly rules: readonly ParamRule[];
  /** Timestamp after which permission becomes valid (0 = immediately) */
  readonly validAfter: number;
  /** Timestamp after which permission expires (0 = never expires) */
  readonly validUntil: number;
  /** Chain ID where permission is valid (0 = all chains) */
  readonly chainId: number;
  /** Whether this permission can only be used once (default: false) */
  readonly singleUse?: boolean;
}

/**
 * Input for creating a policy rule using named parameter paths.
 * 
 * @example
 * ```typescript
 * const rule: RuleInput = {
 *   paramPath: 'params.amountIn',
 *   op: OP.LTE,
 *   value: BigInt('1000000000000000000')
 * };
 * ```
 */
export interface RuleInput {
  /** Dot-notation path to the parameter (e.g., "params.amountIn") */
  readonly paramPath: string;
  /** Comparison operator */
  readonly op: OpType;
  /** Expected value (bigint or address) */
  readonly value: bigint | Address;
}

/**
 * ABI parameter definition for function inputs/outputs.
 * Supports nested structures via components.
 */
export interface ABIParam {
  /** Parameter name */
  readonly name: string;
  /** Solidity type (e.g., "address", "uint256", "tuple") */
  readonly type: string;
  /** Nested parameters for tuple types */
  readonly components?: readonly ABIParam[];
  /** Whether this is an indexed parameter (for events) */
  readonly indexed?: boolean;
}

/**
 * ABI entry for a function, event, or error.
 */
export interface ABIEntry {
  readonly name: string;
  readonly type: string;
  readonly inputs?: readonly ABIParam[];
  readonly outputs?: readonly ABIParam[];
  readonly stateMutability?: "view" | "nonpayable" | "payable";
  readonly anonymous?: boolean;
}

/**
 * Configuration for compiling a policy from ABI.
 * 
 * @example
 * ```typescript
 * const config: PolicyConfig = {
 *   abi: UNISWAP_V3_ROUTER_ABI,
 *   target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
 *   functionName: 'exactInput',
 *   rules: [
 *     { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') }
 *   ]
 * };
 * ```
 */
export interface PolicyConfig {
  /** ABI of the target contract */
  readonly abi: readonly ABIEntry[];
  /** Target contract address */
  readonly target: Address;
  /** Name of the function to allow */
  readonly functionName: string;
  /** Validation rules for function parameters */
  readonly rules: readonly RuleInput[];
}

/**
 * Result of generating a Merkle proof for a permission.
 */
export interface MerkleProofResult {
  /** Sibling hashes proving the leaf is in the tree */
  readonly proof: readonly Hex32[];
  /** Root hash of the Merkle tree (stored on-chain) */
  readonly root: Hex32;
  /** Hash of the permission being proved */
  readonly leaf: Hex32;
}

/**
 * Validation error codes matching contract error types.
 */
export const ValidationErrorCodes = {
  ROOT_NOT_SET: 0,
  INVALID_PROOF: 1,
  UNAUTHORIZED_SIGNER: 2,
  SELECTOR_MISMATCH: 3,
  CALLDATA_OUT_OF_RANGE: 4,
  RULE_VIOLATION: 5,
} as const;

export type ValidationErrorCode = (typeof ValidationErrorCodes)[keyof typeof ValidationErrorCodes];

/**
 * Detailed validation error information.
 */
export interface ValidationError {
  /** Error code matching contract error type */
  readonly code: ValidationErrorCode;
  /** Human-readable error message */
  readonly message: string;
  /** Additional context (e.g., rule index, expected/actual values) */
  readonly details?: {
    readonly ruleIndex?: number;
    readonly operator?: OpType;
    readonly expected?: Hex32;
    readonly actual?: Hex32;
    readonly offset?: number;
  };
}

/**
 * Result of validating a user operation.
 * 
 * @ discriminated union - check `success` property to narrow type
 */
export type ValidationResult = 
  | { readonly success: true }
  | { readonly success: false; readonly error: ValidationError };

/**
 * Result of simulating policy validation against calldata.
 */
export interface SimulatorResult {
  /** Whether validation passed */
  readonly valid: boolean;
  /** Error details if validation failed */
  readonly error?: ValidationError;
  /** Evaluated rules and their results */
  readonly evaluatedRules?: readonly {
    readonly offset: number;
    readonly op: OpType;
    readonly expected: Hex32;
    readonly actual: Hex32;
    readonly passed: boolean;
  }[];
}

/**
 * Known function selectors for Uniswap V3 Router.
 */
export const selectors = {
  /** exactInput selector */
  EXACT_INPUT: '0xc04b8d59' as Selector,
  /** exactInputSingle selector */
  EXACT_INPUT_SINGLE: '0x414bf389' as Selector,
  /** exactOutput selector */
  EXACT_OUTPUT: '0xf28c0498' as Selector,
  /** exactOutputSingle selector */
  EXACT_OUTPUT_SINGLE: '0x5023b4df' as Selector,
} as const;
