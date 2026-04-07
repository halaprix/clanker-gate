import type { ABIEntry, ABIParam } from '../types/index.js';

/**
 * Registry for storing and retrieving contract ABIs.
 * 
 * Provides a central location for ABI definitions used in policy compilation.
 * Supports registering custom ABIs and retrieving function definitions.
 * 
 * @example
 * ```typescript
 * const registry = createABIRegistry();
 * registry.register('MyContract', myAbi);
 * 
 * const abi = registry.get('MyContract');
 * const func = registry.getFunction('MyContract', 'transfer');
 * ```
 */
export interface ABIRegistry {
  /**
   * Registers an ABI under a given name.
   * @param name - Unique identifier for the ABI
   * @param abi - Contract ABI entries
   */
  readonly register: (name: string, abi: readonly ABIEntry[]) => void;
  
  /**
   * Retrieves an ABI by name.
   * @param name - ABI identifier
   * @returns ABI entries or undefined if not found
   */
  readonly get: (name: string) => readonly ABIEntry[] | undefined;
  
  /**
   * Retrieves a specific function from a registered ABI.
   * @param abiName - ABI identifier
   * @param functionName - Function name to find
   * @returns Function ABI entry or undefined
   */
  readonly getFunction: (abiName: string, functionName: string) => ABIEntry | undefined;
  
  /**
   * Checks if an ABI is registered.
   * @param name - ABI identifier
   * @returns true if ABI exists
   */
  readonly has: (name: string) => boolean;
}

/**
 * Creates a new ABI registry instance.
 * 
 * @returns Empty ABI registry ready for registrations
 * 
 * @example
 * ```typescript
 * const registry = createABIRegistry();
 * registry.register('UniswapV3Router', UNISWAP_V3_ROUTER_ABI);
 * ```
 */
export function createABIRegistry(): ABIRegistry {
  const registry = new Map<string, readonly ABIEntry[]>();

  return {
    register(name: string, abi: readonly ABIEntry[]) {
      registry.set(name, abi);
    },

    get(name: string) {
      return registry.get(name);
    },

    getFunction(abiName: string, functionName: string) {
      const abi = registry.get(abiName);
      if (!abi) return undefined;
      
      return abi.find(
        (entry) => entry.type === 'function' && entry.name === functionName
      );
    },

    has(name: string) {
      return registry.has(name);
    },
  };
}

/**
 * Parameter definitions for Uniswap V3 swap functions.
 * 
 * Common structure used by:
 * - exactInput
 * - exactInputSingle
 * - exactOutput
 * - exactOutputSingle
 */
const UNISWAP_V3_PARAMS = [
  { name: 'tokenIn', type: 'address' },
  { name: 'tokenOut', type: 'address' },
  { name: 'fee', type: 'uint24' },
  { name: 'recipient', type: 'address' },
  { name: 'deadline', type: 'uint256' },
  { name: 'amountIn', type: 'uint256' },
  { name: 'amountOutMinimum', type: 'uint256' },
  { name: 'sqrtPriceLimitX96', type: 'uint160' },
] as const satisfies readonly ABIParam[];

/** Output parameters for exact input functions */
const UNISWAP_V3_OUTPUT_PARAMS = [
  { name: 'amountOut', type: 'uint256' },
] as const satisfies readonly ABIParam[];

/** Output parameters for exact output functions */
const UNISWAP_V3_OUTPUT_PARAMS_REVERSE = [
  { name: 'amountIn', type: 'uint256' },
] as const satisfies readonly ABIParam[];

/**
 * ABI for Uniswap V3 SwapRouter functions.
 * 
 * Includes the four main swap functions:
 * - exactInput - Swap exact input for variable output
 * - exactInputSingle - Single-hop exact input swap
 * - exactOutput - Swap variable input for exact output
 * - exactOutputSingle - Single-hop exact output swap
 * 
 * @example
 * ```typescript
 * const permission = compilePolicy({
 *   abi: UNISWAP_V3_ROUTER_ABI,
 *   target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
 *   functionName: 'exactInput',
 *   rules: [...]
 * });
 * ```
 */
export const UNISWAP_V3_ROUTER_ABI = [
  {
    name: 'exactInput',
    type: 'function',
    inputs: [{ name: 'params', type: 'tuple', components: UNISWAP_V3_PARAMS }],
    outputs: UNISWAP_V3_OUTPUT_PARAMS,
  },
  {
    name: 'exactInputSingle',
    type: 'function',
    inputs: [{ name: 'params', type: 'tuple', components: UNISWAP_V3_PARAMS }],
    outputs: UNISWAP_V3_OUTPUT_PARAMS,
  },
  {
    name: 'exactOutput',
    type: 'function',
    inputs: [{ name: 'params', type: 'tuple', components: UNISWAP_V3_PARAMS }],
    outputs: UNISWAP_V3_OUTPUT_PARAMS_REVERSE,
  },
  {
    name: 'exactOutputSingle',
    type: 'function',
    inputs: [{ name: 'params', type: 'tuple', components: UNISWAP_V3_PARAMS }],
    outputs: UNISWAP_V3_OUTPUT_PARAMS_REVERSE,
  },
] as const satisfies readonly ABIEntry[];

/**
 * Default ABI registry with pre-registered Uniswap V3 Router.
 * 
 * @example
 * ```typescript
 * const abi = ClankerGate.registry.get('UniswapV3Router');
 * ```
 */
export const defaultRegistry = createABIRegistry();
defaultRegistry.register('UniswapV3Router', UNISWAP_V3_ROUTER_ABI);
