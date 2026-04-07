import type { ABIEntry, ABIParam } from "../types/index.js";

/**
 * Parsed ABI with computed offsets for each function.
 */
export interface ParsedABI {
  name: string;
  source: string;
  functions: ParsedFunction[];
  events: ParsedEvent[];
  errors: ParsedError[];
}

export interface ParsedFunction {
  name: string;
  selector: `0x${string}`;
  signature: string;
  inputs: ParsedParam[];
  outputs: ParsedParam[];
  stateMutability: "view" | "nonpayable" | "payable";
}

export interface ParsedEvent {
  name: string;
  signature: string;
  inputs: ParsedParam[];
  anonymous: boolean;
}

export interface ParsedError {
  name: string;
  signature: string;
  inputs: ParsedParam[];
}

export interface ParsedParam {
  name: string;
  type: string;
  baseType: string;
  components?: ParsedParam[];
  indexed?: boolean;
  dynamic: boolean;
  offset: number;
  size: number;
}

/**
 * Normalizes different ABI JSON formats to a standard format.
 * 
 * Handles:
 * - Standard Ethereum ABI (Etherscan, Foundry)
 * - Vyper-style ABI with gas estimates
 * - Hardhat artifacts with nested structure
 */
export function normalizeABI(abi: unknown): ABIEntry[] {
  if (!abi) return [];

  const abiArray = Array.isArray(abi) ? abi : [abi];

  return abiArray
    .filter((entry): entry is Record<string, unknown> => 
      entry && typeof entry === "object" && "type" in entry
    )
    .map(normalizeEntry)
    .filter((entry): entry is ABIEntry => entry !== null);
}

function normalizeEntry(entry: Record<string, unknown>): ABIEntry | null {
  const type = entry.type as string;

  if (!["function", "event", "error", "constructor"].includes(type)) {
    return null;
  }

  if (type === "function") {
    return {
      name: (entry.name as string) || "",
      type,
      inputs: normalizeInputs(entry.inputs),
      outputs: normalizeInputs(entry.outputs),
      stateMutability: (entry.stateMutability as "view" | "nonpayable" | "payable") || "nonpayable",
    };
  }

  if (type === "event") {
    return {
      name: (entry.name as string) || "",
      type,
      inputs: normalizeInputs(entry.inputs),
      anonymous: entry.anonymous as boolean,
    } as ABIEntry;
  }

  return {
    name: (entry.name as string) || "",
    type,
    inputs: normalizeInputs(entry.inputs),
  };
}

function normalizeInputs(inputs: unknown): readonly ABIParam[] {
  if (!Array.isArray(inputs)) return [];

  return inputs.map((input: Record<string, unknown>) => ({
    name: (input.name as string) || "",
    type: input.type as string,
    components: input.components ? normalizeInputs(input.components) : undefined,
    indexed: input.indexed as boolean | undefined,
  }));
}

/**
 * Parses a JSON ABI and computes offsets for all function parameters.
 */
export function parseABI(abi: ABIEntry[], name: string = "Unknown", source: string = "json"): ParsedABI {
  return {
    name,
    source,
    functions: abi
      .filter((e) => e.type === "function")
      .map(parseFunction),
    events: abi
      .filter((e) => e.type === "event")
      .map(parseEvent),
    errors: abi
      .filter((e) => e.type === "error")
      .map(parseError),
  };
}

function parseFunction(entry: ABIEntry): ParsedFunction {
  const inputs = computeParamOffsets(entry.inputs ? [...entry.inputs] : []);
  const signature = buildSignature(entry.name, entry.inputs ? [...entry.inputs] : []);

  return {
    name: entry.name,
    selector: computeSelector(signature),
    signature,
    inputs,
    outputs: computeParamOffsets(entry.outputs ? [...entry.outputs] : []),
    stateMutability: entry.stateMutability || "nonpayable",
  };
}

function parseEvent(entry: ABIEntry): ParsedEvent {
  return {
    name: entry.name,
    signature: buildSignature(entry.name, entry.inputs ? [...entry.inputs] : []),
    inputs: computeParamOffsets(entry.inputs ? [...entry.inputs] : []),
    anonymous: entry.anonymous || false,
  };
}

function parseError(entry: ABIEntry): ParsedError {
  return {
    name: entry.name,
    signature: buildSignature(entry.name, entry.inputs ? [...entry.inputs] : []),
    inputs: computeParamOffsets(entry.inputs ? [...entry.inputs] : []),
  };
}

/**
 * Computes byte offsets for all parameters, handling nested tuples.
 */
export function computeParamOffsets(params: ABIParam[]): ParsedParam[] {
  const result: ParsedParam[] = [];
  let offset = 0;

  for (const param of params) {
    const parsed = parseParam(param, "", offset);
    result.push(...flattenParams(parsed));
    offset = result[result.length - 1].offset + result[result.length - 1].size;
  }

  return result;
}

function parseParam(param: ABIParam, prefix: string, baseOffset: number): ParsedParam {
  const { baseType, dynamic, size } = analyzeType(param.type);
  const fullName = prefix ? `${prefix}.${param.name}` : param.name;

  const parsed: ParsedParam = {
    name: fullName,
    type: param.type,
    baseType,
    dynamic,
    offset: baseOffset,
    size,
  };

  if (param.type === "tuple" && param.components) {
    let nestedOffset = 0;
    const components = param.components.map((c) => {
      const comp = parseParam(c, fullName, baseOffset + nestedOffset);
      nestedOffset += 32;
      return comp;
    });
    parsed.components = components.flatMap(flattenParams);
    parsed.size = components.length * 32;
    parsed.dynamic = components.some((c) => c.dynamic);
  }

  return parsed;
}

function flattenParams(param: ParsedParam): ParsedParam[] {
  if (param.components && param.components.length > 0) {
    const flat: ParsedParam[] = [];
    for (const comp of param.components) {
      if (comp.components && comp.components.length > 0) {
        flat.push(...flattenParams(comp));
      } else {
        flat.push(comp);
      }
    }
    return flat;
  }
  return [param];
}

/**
 * Analyzes a Solidity type string.
 */
function analyzeType(type: string): { baseType: string; dynamic: boolean; size: number } {
  if (type === "bytes" || type === "string") {
    return { baseType: type, dynamic: true, size: 32 };
  }

  if (type.endsWith("[]") || /\[\d+\]$/.test(type)) {
    return { baseType: type, dynamic: true, size: 32 };
  }

  if (type.startsWith("uint") || type.startsWith("int")) {
    const bits = parseInt(type.replace(/^(uint|int)/, "")) || 256;
    return { baseType: type, dynamic: false, size: 32 };
  }

  if (type === "address") {
    return { baseType: type, dynamic: false, size: 32 };
  }

  if (type === "bool") {
    return { baseType: type, dynamic: false, size: 32 };
  }

  if (type.startsWith("bytes")) {
    const size = parseInt(type.replace("bytes", ""));
    return { baseType: type, dynamic: false, size: 32 };
  }

  if (type === "tuple") {
    return { baseType: type, dynamic: false, size: 32 };
  }

  return { baseType: type, dynamic: false, size: 32 };
}

/**
 * Builds a function signature from name and inputs.
 */
function buildSignature(name: string, inputs: ABIParam[]): string {
  const params = inputs.map((i) => getCanonicalType(i)).join(",");
  return `${name}(${params})`;
}

/**
 * Gets the canonical type for ABI encoding.
 */
function getCanonicalType(param: ABIParam): string {
  if (param.type === "tuple" && param.components) {
    return `(${param.components.map(getCanonicalType).join(",")})`;
  }
  return param.type;
}

/**
 * Computes the 4-byte function selector.
 */
import { keccak256, toHex } from "viem";

function computeSelector(signature: string): `0x${string}` {
  return keccak256(toHex(signature)).slice(0, 10) as `0x${string}`;
}

/**
 * Parses ABI from JSON string.
 */
export function parseABIFromJSON(json: string, name?: string): ParsedABI {
  const parsed = JSON.parse(json);
  const abi = normalizeABI(parsed);
  return parseABI(abi, name || "Unknown", "json");
}

/**
 * Creates a lookup map for functions by selector.
 */
export function createFunctionLookup(parsed: ParsedABI): Map<string, ParsedFunction> {
  return new Map(parsed.functions.map((f) => [f.selector, f]));
}

/**
 * Finds a parameter by path in a function's inputs.
 */
export function findParamByPath(func: ParsedFunction, path: string): ParsedParam | undefined {
  return func.inputs.find((p) => p.name === path);
}

/**
 * Resolves offset for a parameter path.
 */
export function resolveParamOffset(func: ParsedFunction, path: string): number | null {
  const param = findParamByPath(func, path);
  return param?.offset ?? null;
}
