import { keccak256, toHex, pad } from 'viem';
import type { ABIEntry, ABIParam, Selector, Hex32 } from '../types/index.js';

/**
 * Internal parameter info computed during offset resolution.
 */
interface ParamInfo {
  readonly name: string;
  readonly type: string;
  readonly offset: number;
}

/**
 * Computes the 4-byte function selector from a function name and its inputs.
 * 
 * @param name - Function name (e.g., "exactInput")
 * @param inputs - Array of ABI parameter definitions
 * @returns 4-byte selector as hex string (e.g., "0xc04b8d59")
 * 
 * @example
 * ```typescript
 * const selector = computeSelector('transfer', [
 *   { name: 'to', type: 'address' },
 *   { name: 'amount', type: 'uint256' }
 * ]);
 * // Returns: "0xa9059cbb"
 * ```
 */
export function computeSelector(name: string, inputs: readonly ABIParam[]): Selector {
  const signature = `${name}(${inputs.map(getCanonicalType).join(',')})`;
  const hash = keccak256(toHex(signature));
  return hash.slice(0, 10) as Selector;
}

/**
 * Converts an ABI parameter to its canonical type string.
 * Handles nested tuple types recursively.
 */
function getCanonicalType(param: ABIParam): string {
  if (param.type === 'tuple' && param.components) {
    return `(${param.components.map(getCanonicalType).join(',')})`;
  }
  return param.type;
}

/**
 * Resolves a parameter path to its byte offset in calldata.
 * 
 * @param abiFunction - ABI entry for the function
 * @param paramPath - Dot-notation path (e.g., "params.amountIn")
 * @returns Byte offset in calldata (excluding selector)
 * @throws Error if parameter path cannot be resolved
 * 
 * @example
 * ```typescript
 * const offset = resolveOffset(exactInputABI, 'params.amountIn');
 * // Returns offset where amountIn is located in the tuple
 * ```
 */
export function resolveOffset(abiFunction: ABIEntry, paramPath: string): number {
  if (abiFunction.type !== 'function' || !abiFunction.inputs) {
    throw new Error('Invalid ABI function entry');
  }

  const parts = paramPath.split('.');
  const [firstPart, ...restParts] = parts;

  const paramInfos = computeParamOffsets(abiFunction.inputs);
  const paramInfo = paramInfos.find((p) => p.name === firstPart);

  if (!paramInfo) {
    throw new Error(`Parameter not found: ${firstPart}`);
  }

  if (restParts.length === 0) {
    return paramInfo.offset;
  }

  if (paramInfo.type === 'tuple') {
    const input = abiFunction.inputs.find((i) => i.name === firstPart);
    if (input?.components) {
      return resolveTupleOffset(input.components, restParts, paramInfo.offset);
    }
  }

  throw new Error(`Cannot resolve path: ${paramPath}`);
}

/**
 * Recursively resolves offset within a tuple structure.
 */
function resolveTupleOffset(
  components: readonly ABIParam[],
  path: readonly string[],
  baseOffset: number
): number {
  const [currentPart, ...remainingParts] = path;
  const paramInfos = computeParamOffsets(components);
  const paramInfo = paramInfos.find((p) => p.name === currentPart);

  if (!paramInfo) {
    throw new Error(`Tuple component not found: ${currentPart}`);
  }

  const currentOffset = baseOffset + paramInfo.offset;

  if (remainingParts.length === 0) {
    return currentOffset;
  }

  const component = components.find((c) => c.name === currentPart);
  if (component?.type === 'tuple' && component.components) {
    return resolveTupleOffset(component.components, remainingParts, currentOffset);
  }

  throw new Error(`Cannot resolve nested path: ${path.join('.')}`);
}

/**
 * Computes byte offsets for all parameters in an ABI parameter list.
 * Each parameter occupies 32 bytes in the ABI-encoded calldata.
 * 
 * @param params - Array of ABI parameters
 * @returns Array of parameter info with computed offsets
 */
export function computeParamOffsets(params: readonly ABIParam[]): readonly ParamInfo[] {
  let offset = 0;
  
  return params.map((param) => {
    const info: ParamInfo = {
      name: param.name,
      type: param.type,
      offset,
    };
    offset += 32;
    return info;
  });
}

/**
 * Determines if a type is dynamic in ABI encoding.
 * 
 * Dynamic types include: bytes, string, arrays, and tuples containing dynamic types.
 * 
 * @param type - Solidity type string
 * @param components - Tuple components (if type is tuple)
 * @returns true if the type is dynamic
 */
export function isDynamicType(type: string, components?: readonly ABIParam[]): boolean {
  if (type === 'bytes' || type === 'string') return true;
  if (type.endsWith('[]') || /\[\d+\]$/.test(type)) return true;
  
  if (type === 'tuple' || type.startsWith('tuple')) {
    return components 
      ? components.some((c) => isDynamicType(c.type, c.components))
      : true;
  }
  
  return false;
}

/**
 * Computes the static size of a tuple in bytes.
 * 
 * @param components - Tuple component definitions
 * @returns Total size in bytes
 */
export function getTupleStaticSize(components: readonly ABIParam[]): number {
  return components.reduce((size, comp) => {
    if (isDynamicType(comp.type, comp.components)) {
      return size + 32;
    }
    if (comp.type === 'tuple' && comp.components) {
      return size + getTupleStaticSize(comp.components);
    }
    return size + 32;
  }, 0);
}

/**
 * Converts a value to a 32-byte hex string for use in rules.
 * 
 * @param value - BigInt or hex address
 * @returns 32-byte hex string (64 hex characters)
 * 
 * @example
 * ```typescript
 * toHex32(BigInt('1000000000000000000'));  // 1 ETH
 * // Returns: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
 * ```
 */
export function toHex32(value: bigint | `0x${string}`): Hex32 {
  if (typeof value === 'bigint') {
    return `0x${value.toString(16).padStart(64, '0')}` as Hex32;
  }
  return pad(value, { size: 32 }) as Hex32;
}

/**
 * Validates that calldata is long enough for all rule offsets.
 * 
 * @param calldata - Full calldata including selector
 * @param rules - Array of rules with offsets
 * @returns true if calldata is valid for all rules
 */
export function validateCalldataLength(
  calldata: `0x${string}`,
  rules: readonly { readonly offset: number }[]
): boolean {
  const dataLength = (calldata.length - 2) / 2;
  return rules.every((rule) => rule.offset + 32 <= dataLength);
}

/**
 * Extracts the 4-byte selector from calldata.
 * 
 * @param calldata - Full calldata (at least 10 characters including "0x")
 * @returns 4-byte selector
 * @throws Error if calldata is too short
 */
export function getSelectorFromCalldata(calldata: `0x${string}`): Selector {
  if (calldata.length < 10) {
    throw new Error('Calldata too short to contain selector');
  }
  return calldata.slice(0, 10) as Selector;
}
