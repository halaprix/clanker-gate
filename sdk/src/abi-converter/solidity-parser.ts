import type { ABIEntry, ABIParam } from "../types/index.js";
import { parseABI, type ParsedABI, type ParsedFunction, type ParsedEvent } from "./abi-parser.js";

/**
 * Parsed Solidity interface with imports resolved.
 */
export interface ParsedSolidityInterface {
  name: string;
  path: string;
  imports: string[];
  structs: SolidityStruct[];
  functions: ParsedFunction[];
  events: ParsedEvent[];
  source: string;
}

export interface SolidityStruct {
  name: string;
  fields: { name: string; type: string }[];
}

/**
 * Parses a Solidity interface file into ABI entries.
 * 
 * Supports:
 * - Function definitions with NatSpec
 * - Event definitions
 * - Error definitions
 * - Struct definitions (for DataTypes)
 * - Import statements
 */
export function parseSolidityInterface(source: string, path: string = ""): ParsedSolidityInterface {
  const imports = extractImports(source);
  const structs = extractStructs(source);
  const abi = extractABI(source, structs);

  const parsed = parseABI(abi, extractInterfaceName(source) || "Unknown", path);

  return {
    name: extractInterfaceName(source) || "Unknown",
    path,
    imports,
    structs,
    functions: parsed.functions,
    events: parsed.events,
    source,
  };
}

/**
 * Extracts import statements from Solidity source.
 */
function extractImports(source: string): string[] {
  const importRegex = /import\s+(?:"([^"]+)"|{[^}]+}\s+from\s+"([^"]+)")/g;
  const imports: string[] = [];
  let match;

  while ((match = importRegex.exec(source)) !== null) {
    imports.push(match[1] || match[2]);
  }

  return imports;
}

/**
 * Extracts the interface name from source.
 */
function extractInterfaceName(source: string): string | null {
  const match = source.match(/interface\s+(\w+)/);
  return match ? match[1] : null;
}

/**
 * Extracts struct definitions from Solidity source.
 */
function extractStructs(source: string): SolidityStruct[] {
  const structs: SolidityStruct[] = [];
  const structRegex = /struct\s+(\w+)\s*{([^}]+)}/g;
  let match;

  while ((match = structRegex.exec(source)) !== null) {
    const name = match[1];
    const body = match[2];
    const fields = parseStructFields(body);
    structs.push({ name, fields });
  }

  return structs;
}

/**
 * Parses struct field definitions.
 */
function parseStructFields(body: string): { name: string; type: string }[] {
  const fields: { name: string; type: string }[] = [];
  const lines = body.split(";").map((l) => l.trim()).filter(Boolean);

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const type = parts[0];
      const name = parts[parts.length - 1];
      fields.push({ name, type });
    }
  }

  return fields;
}

/**
 * Extracts ABI entries from Solidity source.
 */
function extractABI(source: string, structs: SolidityStruct[]): ABIEntry[] {
  const entries: ABIEntry[] = [];

  entries.push(...extractFunctions(source, structs));
  entries.push(...extractEvents(source));
  entries.push(...extractErrors(source));

  return entries;
}

/**
 * Extracts function definitions from Solidity source.
 */
function extractFunctions(source: string, structs: SolidityStruct[]): ABIEntry[] {
  const functions: ABIEntry[] = [];

  const funcRegex = /function\s+(\w+)\s*\(([^)]*)\)\s*(external|public|internal|private)?\s*(view|pure|payable|nonpayable)?(?:\s+returns\s*\(([^)]*)\))?/g;
  let match;

  while ((match = funcRegex.exec(source)) !== null) {
    const name = match[1];
    const inputsStr = match[2];
    const mutability = match[4] || "nonpayable";
    const outputsStr = match[5];

    const inputs = parseParams(inputsStr, structs);
    const outputs = outputsStr ? parseParams(outputsStr, structs) : [];

    functions.push({
      name,
      type: "function",
      inputs,
      outputs,
      stateMutability: mutability as ABIEntry["stateMutability"],
    });
  }

  return functions;
}

/**
 * Extracts event definitions from Solidity source.
 */
function extractEvents(source: string): ABIEntry[] {
  const events: ABIEntry[] = [];
  const eventRegex = /event\s+(\w+)\s*\(([^)]*)\)/g;
  let match;

  while ((match = eventRegex.exec(source)) !== null) {
    const name = match[1];
    const inputsStr = match[2];

    events.push({
      name,
      type: "event",
      inputs: parseEventParams(inputsStr),
    });
  }

  return events;
}

/**
 * Extracts error definitions from Solidity source.
 */
function extractErrors(source: string): ABIEntry[] {
  const errors: ABIEntry[] = [];
  const errorRegex = /error\s+(\w+)\s*\(([^)]*)\)/g;
  let match;

  while ((match = errorRegex.exec(source)) !== null) {
    const name = match[1];
    const inputsStr = match[2];

    errors.push({
      name,
      type: "error",
      inputs: parseParams(inputsStr, []),
    });
  }

  return errors;
}

/**
 * Parses function parameters from a string.
 */
function parseParams(paramsStr: string, structs: SolidityStruct[]): ABIParam[] {
  if (!paramsStr.trim()) return [];

  const params: ABIParam[] = [];
  const parts = splitParams(paramsStr);

  for (const part of parts) {
    const param = parseParam(part.trim(), structs);
    if (param) params.push(param);
  }

  return params;
}

/**
 * Parses event parameters with indexed support.
 */
function parseEventParams(paramsStr: string): ABIParam[] {
  if (!paramsStr.trim()) return [];

  const params: ABIParam[] = [];
  const parts = splitParams(paramsStr);

  for (const part of parts) {
    const indexed = /indexed/.test(part);
    const cleaned = part.replace(/indexed/, "").trim();
    const parsedParam = parseParam(cleaned, []);
    if (parsedParam) {
      params.push({
        ...parsedParam,
        indexed,
      });
    }
  }

  return params;
}

/**
 * Splits parameter string handling nested types.
 */
function splitParams(paramsStr: string): string[] {
  const params: string[] = [];
  let current = "";
  let depth = 0;

  for (const char of paramsStr) {
    if (char === "(" || char === "[" || char === "{") depth++;
    if (char === ")" || char === "]" || char === "}") depth--;

    if (char === "," && depth === 0) {
      params.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    params.push(current.trim());
  }

  return params;
}

/**
 * Parses a single parameter.
 */
function parseParam(paramStr: string, structs: SolidityStruct[]): ABIParam | null {
  const parts = paramStr.split(/\s+/).filter(Boolean);
  if (parts.length < 1) return null;

  let type = parts[0];
  let name = parts[parts.length - 1];

  if (parts.length === 1) {
    name = "";
  }

  if (type === "memory" || type === "calldata" || type === "storage") {
    type = parts[1];
    name = parts.length > 2 ? parts[parts.length - 1] : "";
  }

  if (name === "memory" || name === "calldata") {
    name = "";
  }

  const structDef = structs.find((s) => s.name === type);
  if (structDef) {
    return {
      name,
      type: "tuple",
      components: structDef.fields.map((f) => ({ name: f.name, type: f.type })),
    };
  }

  if (type.includes(".")) {
    return {
      name,
      type: "tuple",
      components: [],
    };
  }

  return { name, type };
}

/**
 * Parses human-readable ABI format.
 * 
 * Example: "function transfer(address to, uint256 amount) returns (bool)"
 */
export function parseHumanReadableABI(lines: string[]): ABIEntry[] {
  const entries: ABIEntry[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith("function ")) {
      const func = parseHumanReadableFunction(trimmed);
      if (func) entries.push(func);
    } else if (trimmed.startsWith("event ")) {
      const event = parseHumanReadableEvent(trimmed);
      if (event) entries.push(event);
    } else if (trimmed.startsWith("error ")) {
      const error = parseHumanReadableError(trimmed);
      if (error) entries.push(error);
    }
  }

  return entries;
}

function parseHumanReadableFunction(line: string): ABIEntry | null {
  const match = line.match(/function\s+(\w+)\s*\(([^)]*)\)(?:\s+returns\s*\(([^)]*)\))?/);
  if (!match) return null;

  return {
    name: match[1],
    type: "function",
    inputs: parseParams(match[2], []),
    outputs: match[3] ? parseParams(match[3], []) : [],
  };
}

function parseHumanReadableEvent(line: string): ABIEntry | null {
  const match = line.match(/event\s+(\w+)\s*\(([^)]*)\)/);
  if (!match) return null;

  return {
    name: match[1],
    type: "event",
    inputs: parseEventParams(match[2]),
  };
}

function parseHumanReadableError(line: string): ABIEntry | null {
  const match = line.match(/error\s+(\w+)\s*\(([^)]*)\)/);
  if (!match) return null;

  return {
    name: match[1],
    type: "error",
    inputs: parseParams(match[2], []),
  };
}
