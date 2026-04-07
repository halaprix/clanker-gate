export {
  normalizeABI,
  parseABI,
  parseABIFromJSON,
  computeParamOffsets,
  createFunctionLookup,
  findParamByPath,
  resolveParamOffset,
  type ParsedABI,
  type ParsedFunction,
  type ParsedEvent,
  type ParsedError,
  type ParsedParam,
} from "./abi-parser.js";

export {
  parseSolidityInterface,
  parseHumanReadableABI,
  type ParsedSolidityInterface,
  type SolidityStruct,
} from "./solidity-parser.js";

export {
  generateTypes,
  generateModuleFile,
  generateIndexFile,
  generateRegistryFile,
  type GeneratedTypes,
} from "./type-generator.js";

import { normalizeABI, parseABI, createFunctionLookup, resolveParamOffset } from "./abi-parser.js";
import { parseSolidityInterface } from "./solidity-parser.js";
import { encodeFunctionData, keccak256, toHex } from "viem";
import type { ParsedFunction, ParsedParam } from "./abi-parser.js";
import type { ABIEntry } from "../types/index.js";

/**
 * Verification result for a single ABI.
 */
export interface VerificationResult {
  file: string;
  name: string;
  success: boolean;
  functions: FunctionVerificationResult[];
  errors: string[];
}

export interface FunctionVerificationResult {
  name: string;
  selector: string;
  success: boolean;
  params: ParamVerificationResult[];
}

export interface ParamVerificationResult {
  path: string;
  expectedOffset: number;
  actualOffset: number | null;
  match: boolean;
  error?: string;
}

/**
 * Verifies computed offsets against viem-encoded calldata.
 */
export function verifyABIOffsets(
  abi: ABIEntry[],
  name: string,
  testData?: Record<string, Record<string, unknown>>
): VerificationResult {
  const errors: string[] = [];
  const functions: FunctionVerificationResult[] = [];
  const parsed = parseABI(abi, name);
  const lookup = createFunctionLookup(parsed);

  for (const func of parsed.functions) {
    const result = verifyFunction(func, testData?.[func.name]);
    functions.push(result);
    if (!result.success) {
      errors.push(`Function ${func.name}: offset mismatch`);
    }
  }

  return {
    file: name,
    name: parsed.name,
    success: functions.every((f) => f.success),
    functions,
    errors,
  };
}

/**
 * Verifies a single function's offsets.
 */
function verifyFunction(func: ParsedFunction, testValues?: Record<string, unknown>): FunctionVerificationResult {
  const params: ParamVerificationResult[] = [];

  if (func.inputs.length === 0) {
    return { name: func.name, selector: func.selector, success: true, params };
  }

  try {
    const abiItem = {
      name: func.name,
      type: "function",
      inputs: func.inputs.map((p) => ({
        name: p.name.includes(".") ? p.name.split(".").pop()! : p.name,
        type: p.type,
        components: p.components?.map((c) => ({
          name: c.name.includes(".") ? c.name.split(".").pop()! : c.name,
          type: c.type,
        })),
      })),
    };

    const testArgs = buildTestArgs(func.inputs, testValues);
    const calldata = encodeFunctionData({
      abi: [abiItem],
      functionName: func.name,
      args: testArgs,
    });

    for (const param of func.inputs) {
      const actualOffset = findActualOffset(calldata, param);
      params.push({
        path: param.name,
        expectedOffset: param.offset + 4,
        actualOffset,
        match: actualOffset === param.offset + 4,
      });
    }

    return {
      name: func.name,
      selector: func.selector,
      success: params.every((p) => p.match),
      params,
    };
  } catch (error) {
    return {
      name: func.name,
      selector: func.selector,
      success: false,
      params: func.inputs.map((p) => ({
        path: p.name,
        expectedOffset: p.offset + 4,
        actualOffset: null,
        match: false,
        error: error instanceof Error ? error.message : "Unknown error",
      })),
    };
  }
}

/**
 * Builds test arguments for encoding.
 */
function buildTestArgs(params: ParsedParam[], testValues?: Record<string, unknown>): unknown[] {
  const args: unknown[] = [];
  const grouped = groupParamsByParent(params);

  for (const [parent, children] of Object.entries(grouped)) {
    if (parent === "") {
      for (const child of children) {
        const value = testValues?.[child.name] ?? getDefaultValue(child.type);
        args.push(value);
      }
    } else {
      const tuple: Record<string, unknown> = {};
      for (const child of children) {
        const fieldName = child.name.split(".").pop()!;
        tuple[fieldName] = testValues?.[child.name] ?? getDefaultValue(child.type);
      }
      args.push(tuple);
    }
  }

  return args;
}

/**
 * Groups parameters by their parent (for tuple handling).
 */
function groupParamsByParent(params: ParsedParam[]): Record<string, ParsedParam[]> {
  const groups: Record<string, ParsedParam[]> = {};

  for (const param of params) {
    const parts = param.name.split(".");
    const parent = parts.length > 1 ? parts[0] : "";

    if (!groups[parent]) groups[parent] = [];
    groups[parent].push(param);
  }

  return groups;
}

/**
 * Gets a default value for a type.
 */
function getDefaultValue(type: string): unknown {
  if (type === "address") return "0x0000000000000000000000000000000000000001";
  if (type.startsWith("uint") || type.startsWith("int")) return BigInt(1);
  if (type === "bool") return true;
  if (type.startsWith("bytes")) return "0x01";
  if (type === "string") return "test";
  return BigInt(0);
}

/**
 * Finds the actual offset of a parameter in calldata by searching for the test value.
 */
function findActualOffset(calldata: `0x${string}`, param: ParsedParam): number | null {
  const expectedValue = getDefaultValue(param.type);

  if (typeof expectedValue === "bigint") {
    const hex = expectedValue.toString(16).padStart(64, "0");
    const searchHex = calldata.toLowerCase().slice(2);
    const index = searchHex.indexOf(hex);

    if (index !== -1 && index % 64 === 0) {
      return index / 2;
    }
  }

  if (typeof expectedValue === "string" && expectedValue.startsWith("0x")) {
    const padded = expectedValue.slice(2).padStart(64, "0").toLowerCase();
    const searchHex = calldata.toLowerCase().slice(2);
    const index = searchHex.indexOf(padded);

    if (index !== -1 && index % 64 === 0) {
      return index / 2;
    }
  }

  return null;
}

/**
 * Batch verify all ABIs in a directory.
 */
export async function verifyABIDirectory(
  _dir: string,
  _files: string[]
): Promise<VerificationResult[]> {
  const results: VerificationResult[] = [];

  for (const file of _files) {
    try {
      const content = await import(file);
      const abi = normalizeABI(content.default || content);
      results.push(verifyABIOffsets(abi, file));
    } catch (error) {
      results.push({
        file,
        name: file,
        success: false,
        functions: [],
        errors: [error instanceof Error ? error.message : "Failed to load ABI"],
      });
    }
  }

  return results;
}

/**
 * Formats verification results as a report.
 */
export function formatVerificationReport(results: VerificationResult[]): string {
  const lines: string[] = [];
  let totalFunctions = 0;
  let passedFunctions = 0;
  let totalParams = 0;
  let passedParams = 0;

  for (const result of results) {
    lines.push(`\n${"=".repeat(60)}`);
    lines.push(`File: ${result.file}`);
    lines.push(`Status: ${result.success ? "✅ PASS" : "❌ FAIL"}`);

    for (const func of result.functions) {
      totalFunctions++;
      if (func.success) passedFunctions++;

      lines.push(`\n  ${func.name}() [${func.selector}]`);
      lines.push(`  Status: ${func.success ? "✅" : "❌"}`);

      for (const param of func.params) {
        totalParams++;
        if (param.match) passedParams++;

        const status = param.match ? "✅" : "❌";
        lines.push(
          `    ${status} ${param.path}: expected +${param.expectedOffset}, got +${param.actualOffset ?? "N/A"}`
        );
      }
    }

    if (result.errors.length > 0) {
      lines.push(`\n  Errors:`);
      for (const error of result.errors) {
        lines.push(`    - ${error}`);
      }
    }
  }

  lines.push(`\n${"=".repeat(60)}`);
  lines.push(`Summary:`);
  lines.push(`  Files: ${results.filter((r) => r.success).length}/${results.length} passed`);
  lines.push(`  Functions: ${passedFunctions}/${totalFunctions} passed`);
  lines.push(`  Parameters: ${passedParams}/${totalParams} offsets verified`);

  return lines.join("\n");
}
