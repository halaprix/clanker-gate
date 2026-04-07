import { describe, it, expect } from 'vitest';
import { compilePolicy, createPolicyBuilder } from '../policy-compiler/index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { OP } from '../types/index.js';

describe('policy-compiler', () => {
  describe('compilePolicy', () => {
    it('should compile policy for exactInput with amountIn rule', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      expect(permission.target).toBe('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45');
      expect(permission.selector).toMatch(/^0x[a-f0-9]{8}$/);
      expect(permission.rules).toHaveLength(1);
      expect(permission.rules[0].op).toBe(OP.LTE);
    });

    it('should compile policy with multiple rules', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
          { paramPath: 'params', op: OP.GTE, value: BigInt('100000000000000000') },
        ],
      });

      expect(permission.rules).toHaveLength(2);
      expect(permission.rules[0].op).toBe(OP.LTE);
      expect(permission.rules[1].op).toBe(OP.GTE);
    });

    it('should compile policy with EQ rule', () => {
      const recipientAddress = '0x1234567890123456789012345678901234567890' as `0x${string}`;
      
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.EQ, value: recipientAddress },
        ],
      });

      expect(permission.rules[0].op).toBe(OP.EQ);
      expect(permission.rules[0].value).toMatch(/^0x[a-f0-9]{64}$/);
      expect(permission.rules[0].value.endsWith(recipientAddress.slice(2))).toBe(true);
    });

    it('should throw for invalid function name', () => {
      expect(() =>
        compilePolicy({
          abi: UNISWAP_V3_ROUTER_ABI,
          target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
          functionName: 'nonexistentFunction',
          rules: [],
        })
      ).toThrow('Function not found in ABI');
    });
  });

  describe('createPolicyBuilder', () => {
    it('should build policy using fluent API', () => {
      const permission = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .lte(BigInt('1000000000000000000'))
        .build();

      expect(permission.target).toBe('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45');
      expect(permission.rules).toHaveLength(1);
      expect(permission.rules[0].op).toBe(OP.LTE);
    });

    it('should build policy with multiple rules', () => {
      const permission = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInputSingle')
        .where('params')
        .lte(BigInt('1000000000000000000'))
        .where('params')
        .gte(BigInt('100000000000000000'))
        .build();

      expect(permission.rules).toHaveLength(2);
    });

    it('should throw when building without target', () => {
      expect(() =>
        createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
          .allow()
          .fn('exactInput')
          .build()
      ).toThrow('Policy requires target and function name');
    });

    it('should throw when building without function name', () => {
      expect(() =>
        createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
          .allow()
          .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
          .build()
      ).toThrow('Policy requires target and function name');
    });

    it('should support all operators', () => {
      const permEQ = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .eq(BigInt(100))
        .build();
      expect(permEQ.rules[0].op).toBe(OP.EQ);

      const permGT = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .gt(BigInt(100))
        .build();
      expect(permGT.rules[0].op).toBe(OP.GT);

      const permLT = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .lt(BigInt(100))
        .build();
      expect(permLT.rules[0].op).toBe(OP.LT);

      const permGTE = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .gte(BigInt(100))
        .build();
      expect(permGTE.rules[0].op).toBe(OP.GTE);

      const permLTE = createPolicyBuilder(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .lte(BigInt(100))
        .build();
      expect(permLTE.rules[0].op).toBe(OP.LTE);
    });
  });
});