import { describe, it, expect } from "vitest";
import {
  normalizeABI,
  parseABI,
  parseABIFromJSON,
  computeParamOffsets,
  createFunctionLookup,
  findParamByPath,
  resolveParamOffset,
} from "../abi-converter/abi-parser.js";
import { parseHumanReadableABI } from "../abi-converter/solidity-parser.js";
import { generateTypes, generateModuleFile } from "../abi-converter/type-generator.js";
import { verifyABIOffsets, formatVerificationReport } from "../abi-converter/index.js";
import type { ABIEntry } from "../types/index.js";

describe("ABI Parser", () => {
  describe("normalizeABI", () => {
    it("should normalize standard Ethereum ABI", () => {
      const abi = [
        {
          name: "transfer",
          type: "function",
          inputs: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
          ],
          outputs: [{ name: "", type: "bool" }],
          stateMutability: "nonpayable",
        },
      ];

      const normalized = normalizeABI(abi);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].name).toBe("transfer");
      expect(normalized[0].inputs).toHaveLength(2);
    });

    it("should handle Vyper-style ABI with gas estimates", () => {
      const abi = [
        {
          name: "decimals",
          type: "function",
          inputs: [],
          outputs: [{ name: "", type: "uint256" }],
          stateMutability: "view",
          gas: 288,
        },
      ];

      const normalized = normalizeABI(abi);
      expect(normalized).toHaveLength(1);
      expect(normalized[0].name).toBe("decimals");
    });

    it("should filter out invalid entries", () => {
      const abi = [
        { name: "transfer", type: "function", inputs: [] },
        { type: "fallback" },
        null,
        undefined,
      ];

      const normalized = normalizeABI(abi);
      expect(normalized).toHaveLength(1);
    });
  });

  describe("computeParamOffsets", () => {
    it("should compute offsets for simple parameters", () => {
      const params = [
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets).toHaveLength(2);
      expect(offsets[0].offset).toBe(0);
      expect(offsets[1].offset).toBe(32);
    });

    it("should compute offsets for tuple parameters", () => {
      const params = [
        {
          name: "params",
          type: "tuple",
          components: [
            { name: "tokenIn", type: "address" },
            { name: "tokenOut", type: "address" },
            { name: "amount", type: "uint256" },
          ],
        },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets).toHaveLength(3);
      expect(offsets[0].name).toBe("params.tokenIn");
      expect(offsets[0].offset).toBe(0);
      expect(offsets[1].name).toBe("params.tokenOut");
      expect(offsets[1].offset).toBe(32);
      expect(offsets[2].name).toBe("params.amount");
      expect(offsets[2].offset).toBe(64);
    });

    it("should identify dynamic types", () => {
      const params = [
        { name: "data", type: "bytes" },
        { name: "path", type: "address[]" },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets[0].dynamic).toBe(true);
      expect(offsets[1].dynamic).toBe(true);
    });

    it("should identify static types", () => {
      const params = [
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
        { name: "flag", type: "bool" },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets.every((p) => !p.dynamic)).toBe(true);
    });
  });

  describe("parseABI", () => {
    it("should parse complete ABI with functions, events, errors", () => {
      const abi: ABIEntry[] = [
        {
          name: "transfer",
          type: "function",
          inputs: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
          ],
          outputs: [{ name: "", type: "bool" }],
          stateMutability: "nonpayable",
        },
        {
          name: "Transfer",
          type: "event",
          inputs: [
            { name: "from", type: "address", indexed: true },
            { name: "to", type: "address", indexed: true },
            { name: "value", type: "uint256" },
          ],
        },
        {
          name: "InsufficientBalance",
          type: "error",
          inputs: [{ name: "balance", type: "uint256" }],
        },
      ];

      const parsed = parseABI(abi, "ERC20");

      expect(parsed.name).toBe("ERC20");
      expect(parsed.functions).toHaveLength(1);
      expect(parsed.events).toHaveLength(1);
      expect(parsed.errors).toHaveLength(1);
    });

    it("should compute function selectors", () => {
      const abi: ABIEntry[] = [
        {
          name: "transfer",
          type: "function",
          inputs: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
          ],
          outputs: [{ name: "", type: "bool" }],
        },
      ];

      const parsed = parseABI(abi);
      expect(parsed.functions[0].selector).toBe("0xa9059cbb");
    });
  });

  describe("parseABIFromJSON", () => {
    it("should parse JSON string", () => {
      const json = JSON.stringify([
        {
          name: "balanceOf",
          type: "function",
          inputs: [{ name: "account", type: "address" }],
          outputs: [{ name: "", type: "uint256" }],
        },
      ]);

      const parsed = parseABIFromJSON(json, "ERC20");

      expect(parsed.functions).toHaveLength(1);
      expect(parsed.functions[0].name).toBe("balanceOf");
    });
  });

  describe("createFunctionLookup", () => {
    it("should create selector to function map", () => {
      const abi: ABIEntry[] = [
        {
          name: "transfer",
          type: "function",
          inputs: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
          ],
          outputs: [{ name: "", type: "bool" }],
        },
      ];

      const parsed = parseABI(abi);
      const lookup = createFunctionLookup(parsed);

      expect(lookup.has("0xa9059cbb")).toBe(true);
      expect(lookup.get("0xa9059cbb")?.name).toBe("transfer");
    });
  });

  describe("findParamByPath", () => {
    it("should find parameter by path", () => {
      const abi: ABIEntry[] = [
        {
          name: "exactInputSingle",
          type: "function",
          inputs: [
            {
              name: "params",
              type: "tuple",
              components: [
                { name: "tokenIn", type: "address" },
                { name: "amountIn", type: "uint256" },
              ],
            },
          ],
          outputs: [{ name: "", type: "uint256" }],
        },
      ];

      const parsed = parseABI(abi);
      const func = parsed.functions[0];
      const param = findParamByPath(func, "params.tokenIn");

      expect(param).toBeDefined();
      expect(param?.offset).toBe(0);
    });
  });

  describe("resolveParamOffset", () => {
    it("should resolve offset for parameter path", () => {
      const abi: ABIEntry[] = [
        {
          name: "exactInputSingle",
          type: "function",
          inputs: [
            {
              name: "params",
              type: "tuple",
              components: [
                { name: "tokenIn", type: "address" },
                { name: "tokenOut", type: "address" },
                { name: "amountIn", type: "uint256" },
              ],
            },
          ],
          outputs: [],
        },
      ];

      const parsed = parseABI(abi);
      const func = parsed.functions[0];

      expect(resolveParamOffset(func, "params.tokenIn")).toBe(0);
      expect(resolveParamOffset(func, "params.tokenOut")).toBe(32);
      expect(resolveParamOffset(func, "params.amountIn")).toBe(64);
    });

    it("should return null for non-existent path", () => {
      const abi: ABIEntry[] = [
        {
          name: "transfer",
          type: "function",
          inputs: [{ name: "to", type: "address" }],
          outputs: [],
        },
      ];

      const parsed = parseABI(abi);
      const offset = resolveParamOffset(parsed.functions[0], "nonexistent");

      expect(offset).toBeNull();
    });
  });
});

describe("Human Readable ABI Parser", () => {
  it("should parse function definitions", () => {
    const lines = ["function transfer(address to, uint256 amount) returns (bool)"];

    const abi = parseHumanReadableABI(lines);

    expect(abi).toHaveLength(1);
    expect(abi[0].name).toBe("transfer");
    expect(abi[0].inputs).toHaveLength(2);
  });

  it("should parse event definitions", () => {
    const lines = ["event Transfer(address indexed from, address indexed to, uint256 value)"];

    const abi = parseHumanReadableABI(lines);

    expect(abi).toHaveLength(1);
    expect(abi[0].name).toBe("Transfer");
    expect(abi[0].type).toBe("event");
  });

  it("should parse error definitions", () => {
    const lines = ["error InsufficientBalance(uint256 balance)"];

    const abi = parseHumanReadableABI(lines);

    expect(abi).toHaveLength(1);
    expect(abi[0].name).toBe("InsufficientBalance");
    expect(abi[0].type).toBe("error");
  });
});

describe("Type Generator", () => {
  it("should generate TypeScript types", () => {
    const abi: ABIEntry[] = [
      {
        name: "transfer",
        type: "function",
        inputs: [
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
        ],
        outputs: [{ name: "", type: "bool" }],
      },
    ];

    const parsed = parseABI(abi, "ERC20");
    const generated = generateTypes(parsed, "erc20");

    expect(generated.name).toBe("erc20");
    expect(generated.types).toContain("Erc20FunctionName");
    expect(generated.types).toContain("0xa9059cbb");
    expect(generated.exports).toContain("ERC20_ABI");
  });

  it("should generate module file", () => {
    const abi: ABIEntry[] = [
      {
        name: "balanceOf",
        type: "function",
        inputs: [{ name: "account", type: "address" }],
        outputs: [{ name: "", type: "uint256" }],
      },
    ];

    const parsed = parseABI(abi, "ERC20");
    const file = generateModuleFile(parsed, "erc20");

    expect(file).toContain("ERC20_ABI");
    expect(file).toContain("balanceOf");
  });
});

describe("Verification", () => {
  it("should verify simple function offsets", () => {
    const abi: ABIEntry[] = [
      {
        name: "transfer",
        type: "function",
        inputs: [
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
        ],
        outputs: [{ name: "", type: "bool" }],
      },
    ];

    const result = verifyABIOffsets(abi, "ERC20");

    expect(result.functions).toHaveLength(1);
    expect(result.functions[0].name).toBe("transfer");
    expect(result.functions[0].params).toHaveLength(2);
    expect(result.functions[0].params[0].expectedOffset).toBe(4);
    expect(result.functions[0].params[1].expectedOffset).toBe(36);
  });

  it("should verify tuple function offsets", () => {
    const abi: ABIEntry[] = [
      {
        name: "exactInputSingle",
        type: "function",
        inputs: [
          {
            name: "params",
            type: "tuple",
            components: [
              { name: "tokenIn", type: "address" },
              { name: "tokenOut", type: "address" },
              { name: "fee", type: "uint24" },
              { name: "recipient", type: "address" },
              { name: "deadline", type: "uint256" },
              { name: "amountIn", type: "uint256" },
              { name: "amountOutMinimum", type: "uint256" },
              { name: "sqrtPriceLimitX96", type: "uint160" },
            ],
          },
        ],
        outputs: [{ name: "amountOut", type: "uint256" }],
      },
    ];

    const result = verifyABIOffsets(abi, "UniswapV3");

    expect(result.functions).toHaveLength(1);
    expect(result.functions[0].params).toHaveLength(8);
    expect(result.functions[0].params[0].expectedOffset).toBe(4);
    expect(result.functions[0].params[5].expectedOffset).toBe(164);
  });

  it("should generate verification report", () => {
    const abi: ABIEntry[] = [
      {
        name: "transfer",
        type: "function",
        inputs: [
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
        ],
        outputs: [{ name: "", type: "bool" }],
      },
    ];

    const result = verifyABIOffsets(abi, "ERC20");
    const report = formatVerificationReport([result]);

    expect(report).toContain("ERC20");
    expect(report).toContain("transfer");
  });

  it("should handle complex nested tuple with dynamic types", () => {
    const abi: ABIEntry[] = [
      {
        name: "complexFunction",
        type: "function",
        inputs: [
          {
            name: "outerTuple",
            type: "tuple",
            components: [
              { name: "value", type: "uint256" },
              {
                name: "nestedTuple",
                type: "tuple",
                components: [
                  { name: "innerValue", type: "uint256" },
                  { name: "dynamicData", type: "bytes" },
                  { name: "dataArray", type: "bytes[]" },
                ],
              },
            ],
          },
          { name: "extraBytes", type: "bytes" },
        ],
        outputs: [],
      },
    ];

    const parsed = parseABI(abi, "Complex");
    const func = parsed.functions[0];
    const params = func.inputs;

    expect(func.name).toBe("complexFunction");
    expect(params).toHaveLength(5);

    expect(params[0].name).toBe("outerTuple.value");
    expect(params[0].type).toBe("uint256");
    expect(params[0].offset).toBe(0);
    expect(params[0].dynamic).toBe(false);

    expect(params[1].name).toBe("outerTuple.nestedTuple.innerValue");
    expect(params[1].type).toBe("uint256");
    expect(params[1].offset).toBe(32);
    expect(params[1].dynamic).toBe(false);

    expect(params[2].name).toBe("outerTuple.nestedTuple.dynamicData");
    expect(params[2].type).toBe("bytes");
    expect(params[2].offset).toBe(64);
    expect(params[2].dynamic).toBe(true);

    expect(params[3].name).toBe("outerTuple.nestedTuple.dataArray");
    expect(params[3].type).toBe("bytes[]");
    expect(params[3].offset).toBe(96);
    expect(params[3].dynamic).toBe(true);

    expect(params[4].name).toBe("extraBytes");
    expect(params[4].type).toBe("bytes");
    expect(params[4].offset).toBe(128);
    expect(params[4].dynamic).toBe(true);
  });
});
