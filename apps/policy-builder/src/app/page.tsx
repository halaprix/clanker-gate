"use client";

import { useState, useCallback } from "react";
import {
  ClankerGate,
  UNISWAP_V3_ROUTER_ABI,
  OP,
  resolveOffset,
  type Permission,
  type ABIEntry,
  type OpType,
} from "@clanker/gate-client";

const OpLabels: Record<number, string> = { 0: "==", 1: ">", 2: "<", 3: ">=", 4: "<=" };

interface Rule {
  fieldName: string;
  op: OpType;
  rawValue: string;
}

interface PolicyConfig {
  id: string;
  label: string;
  target: string;
  functionName: string;
  rules: Rule[];
}

interface Field {
  name: string;
  type: string;
  offset: number;
}

const EXAMPLE_POLICIES: PolicyConfig[] = [
  {
    id: "uni-v3-exact-input-single",
    label: "UniV3 exactInputSingle – bounded swap",
    target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    functionName: "exactInputSingle",
    rules: [
      { fieldName: "params.recipient", op: OP.EQ, rawValue: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
      { fieldName: "params.amountIn", op: OP.LTE, rawValue: "1000000000000000000" },
    ],
  },
  {
    id: "uni-v3-exact-input-single-whitelist",
    label: "UniV3 exactInputSingle – whitelist USDC",
    target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    functionName: "exactInputSingle",
    rules: [
      { fieldName: "params.tokenIn", op: OP.EQ, rawValue: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" },
      { fieldName: "params.recipient", op: OP.EQ, rawValue: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
      { fieldName: "params.amountIn", op: OP.LTE, rawValue: "5000000000" },
    ],
  },
];

function getFunctionEntry(fnName: string): ABIEntry | undefined {
  return UNISWAP_V3_ROUTER_ABI.find(
    e => e.type === "function" && e.name === fnName
  );
}

// Fields and their calldata offsets come from the SDK's ABI registry and
// policy compiler — the same resolution `.where("params.amountIn")` uses.
function getFieldsForFunction(fnName: string): Field[] {
  const entry = getFunctionEntry(fnName);
  if (!entry?.inputs) return [];
  return entry.inputs
    .flatMap(input =>
      input.type === "tuple" && input.components
        ? input.components.map(c => ({ name: `${input.name}.${c.name}`, type: c.type }))
        : [{ name: input.name, type: input.type }]
    )
    .map(f => {
      try {
        return { ...f, offset: resolveOffset(entry, f.name) };
      } catch {
        return { ...f, offset: -1 };
      }
    });
}

function buildPermission(policy: PolicyConfig): Permission {
  let builder = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
    .allow()
    .to(policy.target as `0x${string}`)
    .fn(policy.functionName);
  
  for (const rule of policy.rules) {
    const value = rule.rawValue.startsWith("0x") 
      ? rule.rawValue as `0x${string}` 
      : BigInt(rule.rawValue);
    
    const ruleBuilder = builder.where(rule.fieldName);
    switch (rule.op) {
      case OP.EQ: builder = ruleBuilder.eq(value); break;
      case OP.GT: builder = ruleBuilder.gt(value); break;
      case OP.LT: builder = ruleBuilder.lt(value); break;
      case OP.GTE: builder = ruleBuilder.gte(value); break;
      case OP.LTE: builder = ruleBuilder.lte(value); break;
    }
  }
  
  return builder.build();
}

// User-typed values can be mid-edit garbage; never let that crash the page.
function tryBuildPermission(policy: PolicyConfig): { permission: Permission | null; error: string | null } {
  try {
    return { permission: buildPermission(policy), error: null };
  } catch (e) {
    return { permission: null, error: e instanceof Error ? e.message : String(e) };
  }
}

function InvalidPolicyNote({ error }: { error: string }) {
  return (
    <div className="text-xs text-[#ff9f61] bg-[#2a1500] border border-[#ff6b35]/[0.4] rounded-md px-3 py-2">
      Policy doesn&apos;t compile yet: <span className="text-gray-400">{error}</span>
    </div>
  );
}

function CalldataVisualizer({ policy, permission, error }: { policy: PolicyConfig; permission: Permission | null; error: string | null }) {
  const fields = getFieldsForFunction(policy.functionName);
  if (fields.length === 0) {
    return <div className="text-gray-500 text-xs">Unknown function – no visualization available</div>;
  }
  if (!permission) {
    return <InvalidPolicyNote error={error ?? "invalid rule value"} />;
  }

  const ruleOffsets = new Set(permission.rules.map(r => r.offset));
  
  const getRuleForOffset = (offset: number) => {
    return permission.rules.find(r => r.offset === offset);
  };

  return (
    <div className="mt-2">
      <div className="text-[10px] text-gray-500 mb-1.5 tracking-widest uppercase">
        Calldata layout — {policy.functionName}()
      </div>
      <div className="flex flex-col gap-0.5">
        <div className="flex gap-0.5">
          <div className="w-[52px] text-[9px] text-gray-500 font-mono">offset</div>
          <div className="text-[9px] text-gray-500 font-mono">field</div>
        </div>
        <div className="flex gap-0.5 items-center">
          <div className="w-[52px] text-[9px] text-gray-500 font-mono">0x00</div>
          <div className="bg-[#1a1a2e] border border-[#2a2a4a] rounded px-2 py-1 text-[10px] text-[#6666aa] font-mono w-[280px]">
            selector · {permission.selector.slice(0, 10)}...
          </div>
        </div>
        {fields.map(field => {
          const offset = field.offset;
          const isHighlighted = ruleOffsets.has(offset);
          const rule = getRuleForOffset(offset);
          return (
            <div key={field.name} className="flex gap-0.5 items-center">
              <div className={`w-[52px] text-[9px] font-mono ${isHighlighted ? "text-[#ff6b35] font-bold" : "text-gray-500"}`}>
                +0x{offset.toString(16).padStart(2, "0")}
              </div>
              <div className={`border rounded px-2 py-1 text-[10px] font-mono w-[280px] flex justify-between items-center ${
                isHighlighted 
                  ? "bg-gradient-to-r from-[#2a1500] to-[#1a0d00] border-[#ff6b35] text-[#ff9f61]" 
                  : "bg-[#0f0f1a] border-[#1e1e2e] text-gray-500"
              }`}>
                <span>
                  <span className={isHighlighted ? "text-[#ff6b35]" : "text-gray-600"}>{field.type}</span>
                  {" "}
                  <span className={isHighlighted ? "text-[#ffd0a0]" : "text-gray-500"}>{field.name}</span>
                </span>
                {rule && (
                  <span className="bg-[#ff6b35]/[0.12] border border-[#ff6b35]/[0.4] rounded px-1.5 text-[9px] text-[#ff9f61]">
                    {OpLabels[rule.op]} {rule.value.slice(0, 10)}…
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GeneratedCode({ policy, permission, error }: { policy: PolicyConfig; permission: Permission | null; error: string | null }) {
  const [copied, setCopied] = useState(false);

  if (!permission) {
    return <InvalidPolicyNote error={error ?? "invalid rule value"} />;
  }

  const tsCode = `import { ClankerGate, UNISWAP_V3_ROUTER_ABI, OP } from '@clanker/gate-client';

const permission = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
  .allow()
  .to("${policy.target}")
  .fn("${policy.functionName}")
${policy.rules.map(r => `  .where("${r.fieldName}")\n  .${Object.keys(OP).find(k => OP[k as keyof typeof OP] === r.op)?.toLowerCase() || "eq"}(${r.rawValue.startsWith("0x") ? `"${r.rawValue}"` : `BigInt("${r.rawValue}")`})`).join("\n")}
  .build();

// Compiled Permission (auto-resolved offsets):
const compiled = ${JSON.stringify({
    target: permission.target,
    selector: permission.selector,
    rules: permission.rules.map(r => ({
      offset: r.offset,
      op: r.op,
      value: r.value,
    })),
  }, null, 2)};

// Build Merkle tree
const builder = ClankerGate.merkleTree();
builder.addPermission(permission);
const { root } = builder.build();`;

  const copy = () => {
    navigator.clipboard.writeText(tsCode).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="relative">
      <button 
        onClick={copy} 
        className={`absolute top-2 right-2 border rounded px-2.5 py-1 text-[10px] cursor-pointer z-10 ${
          copied 
            ? "bg-[#1a3a1a] border-[#4a9] text-green-400" 
            : "bg-[#1a1a2e] border-gray-700 text-gray-500"
        }`}
      >
        {copied ? "copied!" : "copy"}
      </button>
      <pre className="bg-[#080812] border border-[#1a1a2e] rounded-md p-3.5 text-[11px] leading-relaxed text-[#7a8] overflow-x-auto m-0 font-mono max-h-[380px] overflow-y-auto">
        <code>{tsCode}</code>
      </pre>
    </div>
  );
}

function RuleRow({ rule, index, functionName, onUpdate, onRemove }: {
  rule: Rule;
  index: number;
  functionName: string;
  onUpdate: (idx: number, newRule: Rule) => void;
  onRemove: (idx: number) => void;
}) {
  const fields = getFieldsForFunction(functionName);
  const fieldOffset = fields.find(f => f.name === rule.fieldName)?.offset ?? -1;
  const offset: number | string = fieldOffset >= 0 ? fieldOffset : "???";

  return (
    <div className="flex gap-2 items-center bg-[#0c0c18] rounded-md border border-[#1e1e30] px-3 py-2">
      <select
        value={rule.fieldName}
        onChange={e => onUpdate(index, { ...rule, fieldName: e.target.value })}
        className="bg-[#080812] border border-[#2a2a4a] rounded text-[#ff9f61] text-[11px] px-2 py-1 font-mono flex-[2] focus:outline-none focus:border-[#ff6b35]"
      >
        {fields.length === 0 && <option>— unknown function —</option>}
        {fields.map(f => (
          <option key={f.name} value={f.name}>
            {f.name} ({f.type})
          </option>
        ))}
      </select>

      <select
        value={rule.op}
        onChange={e => onUpdate(index, { ...rule, op: Number(e.target.value) as OpType })}
        className="bg-[#080812] border border-[#2a2a4a] rounded text-[#8888ff] text-[13px] px-1.5 py-1 font-mono w-[52px] focus:outline-none focus:border-blue-500"
      >
        {Object.entries(OpLabels).map(([k, v]) => (
          <option key={k} value={k}>{v}</option>
        ))}
      </select>

      <input
        value={rule.rawValue}
        onChange={e => onUpdate(index, { ...rule, rawValue: e.target.value })}
        placeholder="value (hex or decimal)"
        className="bg-[#080812] border border-[#2a2a4a] rounded text-gray-400 text-[11px] px-2 py-1 font-mono flex-[3] focus:outline-none focus:border-gray-500"
      />

      <div className={`text-[9px] font-mono w-[60px] text-right whitespace-nowrap ${
        typeof offset === "number" ? "text-[#ff6b35]" : "text-gray-600"
      }`}>
        {typeof offset === "number" ? `→ +0x${offset.toString(16)}` : "offset: ?"}
      </div>

      <button
        onClick={() => onRemove(index)}
        className="bg-none border border-[#2a1a1a] rounded text-[#663333] text-xs cursor-pointer px-1.5 py-0.5 hover:border-red-800 hover:text-red-400 transition-colors"
      >
        ×
      </button>
    </div>
  );
}

export default function ClankerGateDX() {
  const [activePolicy, setActivePolicy] = useState<PolicyConfig>(EXAMPLE_POLICIES[0]);
  const [tab, setTab] = useState<"visualizer" | "code" | "solidity">("visualizer");

  const updateRule = useCallback((idx: number, newRule: Rule) => {
    setActivePolicy(p => ({
      ...p,
      rules: p.rules.map((r, i) => i === idx ? newRule : r)
    }));
  }, []);

  const removeRule = useCallback((idx: number) => {
    setActivePolicy(p => ({
      ...p,
      rules: p.rules.filter((_, i) => i !== idx)
    }));
  }, []);

  const addRule = useCallback(() => {
    const fields = getFieldsForFunction(activePolicy.functionName);
    const firstField = fields[0];
    setActivePolicy(p => ({
      ...p,
      rules: [...p.rules, {
        fieldName: firstField?.name ?? "",
        op: OP.EQ,
        rawValue: "0x0000000000000000000000000000000000000000"
      }]
    }));
  }, [activePolicy.functionName]);

  const { permission, error } = tryBuildPermission(activePolicy);
  const soliditySnippet = permission
    ? `// Auto-generated by @clanker/gate-client
Permission memory perm = Permission({
    target: ${permission.target},
    selector: ${permission.selector},
    rules: new ParamRule[](${permission.rules.length})
});
${permission.rules.map((r, i) => `perm.rules[${i}] = ParamRule({ offset: ${r.offset}, op: ${r.op}, value: ${r.value} });`).join("\n")}`
    : "";

  return (
    <div className="min-h-screen bg-[#05050f] text-gray-300 font-mono p-0">
      <div className="border-b border-[#111124] px-8 py-[18px] flex items-center gap-4 bg-gradient-to-r from-[#05050f] to-[#0a0a1e]">
        <div className="w-8 h-8 bg-gradient-to-br from-[#ff6b35] to-[#c02020] rounded-md flex items-center justify-center text-base font-bold text-white">
          ⛨
        </div>
        <div>
          <div className="text-sm font-bold text-white tracking-wide">
            ClankerGate <span className="text-[#ff6b35]">Policy Builder</span>
          </div>
          <div className="text-[10px] text-gray-600 mt-0.5">
            Powered by @clanker/gate-client SDK
          </div>
        </div>
      </div>

      <div className="flex h-[calc(100vh-61px)]">
        <div className="w-[220px] border-r border-[#111124] py-4 overflow-y-auto bg-[#060610]">
          <div className="text-[9px] text-gray-600 px-4 pb-2 tracking-widest uppercase">
            Example Policies
          </div>
          {EXAMPLE_POLICIES.map(p => (
            <button
              key={p.id}
              onClick={() => { setActivePolicy(p); setTab("visualizer"); }}
              className={`w-full text-left bg-none border-none px-4 py-2.5 cursor-pointer text-[11px] leading-snug transition-colors ${
                activePolicy.id === p.id 
                  ? "bg-[#0f0f22] border-l-[3px] border-l-[#ff6b35] text-[#ff9f61]" 
                  : "border-l-[3px] border-l-transparent text-gray-500 hover:text-gray-400"
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        <div className="flex-1 px-7 py-6 overflow-y-auto">
          <div className="flex gap-3 mb-5 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <div className="text-[9px] text-gray-600 mb-1 tracking-widest uppercase">Target</div>
              <div className="bg-[#0a0a18] border border-[#1a1a2e] rounded-sm px-2.5 py-1.5 text-[11px] text-[#8888cc] font-mono">
                {activePolicy.target}
              </div>
            </div>
            <div className="flex-[0_0_200px]">
              <div className="text-[9px] text-gray-600 mb-1 tracking-widest uppercase">Selector</div>
              <div className="bg-[#0a0a18] border border-[#1a1a2e] rounded-sm px-2.5 py-1.5 text-[11px] text-[#ff9f61] font-mono">
                {permission?.selector ?? "—"}
                <span className="text-gray-500 ml-2">· {activePolicy.functionName}()</span>
              </div>
            </div>
          </div>

          <div className="text-[9px] text-gray-600 mb-2 tracking-widest uppercase">
            Param Rules ({activePolicy.rules.length})
          </div>
          <div className="flex flex-col gap-1.5">
            {activePolicy.rules.map((rule, i) => (
              <RuleRow
                key={i}
                rule={rule}
                index={i}
                functionName={activePolicy.functionName}
                onUpdate={updateRule}
                onRemove={removeRule}
              />
            ))}
          </div>
          <button
            onClick={addRule}
            className="mt-2.5 bg-[#0c0c1e] border border-dashed border-[#2a2a4a] rounded-sm px-4 py-2 text-[#4444aa] text-[11px] cursor-pointer w-full hover:border-[#4444aa] transition-colors"
          >
            + add rule
          </button>

          <div className="mt-6 bg-[#0a1208] border border-[#1a3018] rounded-md px-4 py-3.5">
            <div className="text-[10px] text-[#4a8] mb-2.5 tracking-widest uppercase">
              SDK Integration
            </div>
            {[
              ["ABI Registry", "Uses UNISWAP_V3_ROUTER_ABI from @clanker/gate-client"],
              ["Offset Resolution", "Auto-computed via SDK policy compiler"],
              ["Merkle Tree", "builder.addPermission() → root generation"],
              ["Type-safe", "Full TypeScript support with viem types"],
            ].map(([title, desc]) => (
              <div key={title} className="flex gap-2.5 mb-1.5 text-[11px]">
                <span className="text-[#4a8] min-w-[130px]">✓ {title}</span>
                <span className="text-gray-600">{desc}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="w-[460px] border-l border-[#111124] flex flex-col">
          <div className="flex border-b border-[#111124] bg-[#060610]">
            {[
              ["visualizer", "Calldata Map"],
              ["code", "TypeScript"],
              ["solidity", "Solidity"]
            ].map(([id, label]) => (
              <button
                key={id}
                onClick={() => setTab(id as typeof tab)}
                className={`px-4.5 py-2.5 bg-none border-none text-[11px] cursor-pointer transition-colors ${
                  tab === id 
                    ? "bg-[#0c0c1e] border-b-2 border-b-[#ff6b35] text-[#ff9f61]" 
                    : "border-b-2 border-b-transparent text-gray-500 hover:text-gray-400"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="p-5 overflow-y-auto flex-1">
            {tab === "visualizer" && (
              <CalldataVisualizer policy={activePolicy} permission={permission} error={error} />
            )}
            {tab === "code" && (
              <GeneratedCode policy={activePolicy} permission={permission} error={error} />
            )}
            {tab === "solidity" && !permission && (
              <InvalidPolicyNote error={error ?? "invalid rule value"} />
            )}
            {tab === "solidity" && permission && (
              <div className="relative">
                <pre className="bg-[#080812] border border-[#1a1a2e] rounded-md p-3.5 text-[11px] leading-loose text-[#6fa] overflow-x-auto m-0 font-mono">
                  {soliditySnippet}
                </pre>
                <div className="mt-3 p-3 bg-[#0a0a08] border border-[#222210] rounded-md text-[10px] text-gray-500 leading-relaxed">
                  Offsets computed by SDK. Re-generate after ABI changes.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}