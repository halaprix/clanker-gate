import { describe, it, expect } from 'vitest';
import { toFunctionSelector } from 'viem';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { computeSelector, resolveOffset } from '../policy-compiler/offset-calculator.js';
import { compilePolicy } from '../policy-compiler/index.js';
import { OP } from '../types/index.js';

const ROUTER = '0xE592427A0AEce92De3Edee1F18E0157C05861564' as const;

function entry(name: string) {
  const e = UNISWAP_V3_ROUTER_ABI.find(f => f.name === name);
  if (!e) throw new Error(`missing ${name}`);
  return e;
}

describe('UNISWAP_V3_ROUTER_ABI', () => {
  // Canonical ISwapRouter selectors — pinned literals, cross-checked against viem.
  const EXPECTED: Record<string, `0x${string}`> = {
    exactInput: '0xc04b8d59',
    exactInputSingle: '0x414bf389',
    exactOutput: '0xf28c0498',
    exactOutputSingle: '0xdb3e2198',
  };

  it.each(Object.entries(EXPECTED))('%s compiles to the on-chain selector %s', (name, selector) => {
    const e = entry(name);
    expect(computeSelector(name, e.inputs!)).toBe(selector);

    const canonical = `${name}((${e.inputs![0].components!.map(c => c.type).join(',')}))`;
    expect(toFunctionSelector(canonical)).toBe(selector);
  });

  it('single-hop struct fields resolve to fixed offsets', () => {
    expect(resolveOffset(entry('exactInputSingle'), 'params.amountIn')).toBe(160);
    expect(resolveOffset(entry('exactOutputSingle'), 'params.amountOut')).toBe(160);
  });

  it('multi-hop (bytes path) struct fields refuse fixed-offset rules', () => {
    for (const name of ['exactInput', 'exactOutput']) {
      expect(() => resolveOffset(entry(name), 'params.recipient')).toThrow(/dynamic/i);
      expect(() =>
        compilePolicy({
          abi: UNISWAP_V3_ROUTER_ABI,
          target: ROUTER,
          functionName: name,
          rules: [{ paramPath: 'params.recipient', op: OP.EQ, value: ROUTER }],
        })
      ).toThrow(/dynamic/i);
    }
  });
});
