import type { Permission, ParamRule, PolicyConfig, RuleInput } from '../types/index.js';
import type { ABIEntry, ABIParam } from '../types/index.js';
import { resolveOffset, computeSelector, toHex32 } from './offset-calculator.js';

/**
 * Compiles a policy configuration into a Permission object.
 * 
 * Takes a high-level policy definition (with named parameter paths)
 * and converts it to the low-level format needed for on-chain validation.
 * 
 * @param config - Policy configuration with ABI, target, function name, and rules
 * @returns Compiled permission ready for Merkle tree construction
 * @throws Error if function not found in ABI
 * 
 * @example
 * ```typescript
 * const permission = compilePolicy({
 *   abi: UNISWAP_V3_ROUTER_ABI,
 *   target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
 *   functionName: 'exactInput',
 *   rules: [
 *     { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') }
 *   ]
 * });
 * ```
 */
export function compilePolicy(config: PolicyConfig): Permission {
  const func = config.abi.find(
    (e) => e.type === 'function' && e.name === config.functionName
  );

  if (!func?.inputs) {
    throw new Error(`Function not found in ABI: ${config.functionName}`);
  }

  const selector = computeSelector(config.functionName, func.inputs);
  const rules = compileRules(func.inputs, config.rules);

  return {
    target: config.target,
    selector,
    rules,
    validAfter: 0,
    validUntil: 0,
    chainId: 0,
  };
}

/**
 * Compiles rule inputs into ParamRule objects with resolved offsets.
 */
function compileRules(
  inputs: readonly ABIParam[],
  ruleInputs: readonly RuleInput[]
): readonly ParamRule[] {
  return ruleInputs.map((rule) => ({
    offset: resolveOffset({ type: 'function', name: '', inputs }, rule.paramPath),
    op: rule.op,
    value: toHex32(rule.value),
  }));
}

/**
 * Creates a fluent builder for constructing policies.
 * 
 * Provides a chainable API for defining transaction policies:
 * 
 * @example
 * ```typescript
 * const permission = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
 *   .allow()
 *   .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
 *   .fn('exactInput')
 *   .where('params.amountIn')
 *   .lte(BigInt('1000000000000000000'))
 *   .build();
 * ```
 * 
 * @param abi - Contract ABI to use for function lookup
 * @returns Policy builder with fluent API
 */
export function createPolicyBuilder(abi: readonly ABIEntry[]) {
  let target: `0x${string}` | undefined;
  let functionName: string | undefined;
  const rules: RuleInput[] = [];

  /**
   * Policy builder object with chainable methods.
   */
  const builder = {
    /**
     * Starts policy definition (identity function for readability).
     * @returns The builder for chaining
     */
    allow: () => builder,
    
    /**
     * Sets the target contract address.
     * @param address - Target contract address
     * @returns The builder for chaining
     */
    to: (address: `0x${string}`) => {
      target = address;
      return builder;
    },
    
    /**
     * Sets the function to be called.
     * @param name - Function name as defined in ABI
     * @returns The builder for chaining
     */
    fn: (name: string) => {
      functionName = name;
      return builder;
    },
    
    /**
     * Starts a rule definition for a parameter.
     * @param paramPath - Dot-notation path to parameter (e.g., "params.amountIn")
     * @returns Rule builder for adding comparison
     */
    where: (paramPath: string) => createRuleBuilder(paramPath),
    
    /**
     * Builds and returns the compiled permission.
     * @returns Compiled Permission object
     * @throws Error if target or function name not set
     */
    build: (): Permission => {
      if (!target || !functionName) {
        throw new Error('Policy requires target and function name');
      }
      return compilePolicy({
        abi,
        target: target as `0x${string}`,
        functionName,
        rules,
      });
    },
  };

  /**
   * Creates a rule builder for the specified parameter path.
   */
  const createRuleBuilder = (paramPath: string) => ({
    /**
     * Adds an equality constraint.
     * @param value - Value that the parameter must equal
     */
    eq: (value: bigint | `0x${string}`) => {
      rules.push({ paramPath, op: 0, value });
      return builder;
    },
    /**
     * Adds a greater-than constraint.
     * @param value - Value that the parameter must exceed
     */
    gt: (value: bigint | `0x${string}`) => {
      rules.push({ paramPath, op: 1, value });
      return builder;
    },
    /**
     * Adds a less-than constraint.
     * @param value - Value that the parameter must be below
     */
    lt: (value: bigint | `0x${string}`) => {
      rules.push({ paramPath, op: 2, value });
      return builder;
    },
    /**
     * Adds a greater-than-or-equal constraint.
     * @param value - Value that the parameter must meet or exceed
     */
    gte: (value: bigint | `0x${string}`) => {
      rules.push({ paramPath, op: 3, value });
      return builder;
    },
    /**
     * Adds a less-than-or-equal constraint.
     * @param value - Value that the parameter must not exceed
     */
    lte: (value: bigint | `0x${string}`) => {
      rules.push({ paramPath, op: 4, value });
      return builder;
    },
  });

  return builder;
}

/** Policy builder type returned by createPolicyBuilder */
export type PolicyBuilder = ReturnType<typeof createPolicyBuilder>;

/** Rule builder type returned by PolicyBuilder.where() */
export type RuleBuilder = ReturnType<PolicyBuilder['where']>;
