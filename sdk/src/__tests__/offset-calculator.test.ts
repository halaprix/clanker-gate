import { describe, it, expect } from 'vitest';
import { 
  resolveOffset, 
  computeParamOffsets, 
  isDynamicType,
  getTupleStaticSize,
  computeSelector,
  toHex32,
  validateCalldataLength,
  getSelectorFromCalldata,
} from '../policy-compiler/offset-calculator.js';
import type { ABIEntry, ABIParam } from '../types/index.js';

describe('offset-calculator', () => {
  describe('toHex32', () => {
    it('should convert bigint to 32-byte hex', () => {
      expect(toHex32(BigInt(123))).toBe('0x000000000000000000000000000000000000000000000000000000000000007b');
    });

    it('should convert address to 32-byte hex', () => {
      const result = toHex32('0x1234567890123456789012345678901234567890');
      expect(result).toHaveLength(66);
      expect(result.endsWith('1234567890123456789012345678901234567890')).toBe(true);
    });

    it('should convert 1 ETH to correct hex', () => {
      const oneEth = BigInt('1000000000000000000');
      expect(toHex32(oneEth)).toBe('0x0000000000000000000000000000000000000000000000000de0b6b3a7640000');
    });
  });

  describe('isDynamicType', () => {
    it('should identify bytes as dynamic', () => {
      expect(isDynamicType('bytes')).toBe(true);
    });

    it('should identify string as dynamic', () => {
      expect(isDynamicType('string')).toBe(true);
    });

    it('should identify dynamic array as dynamic', () => {
      expect(isDynamicType('uint256[]')).toBe(true);
      expect(isDynamicType('address[]')).toBe(true);
    });

    it('should identify fixed array as dynamic (ABI encoding)', () => {
      expect(isDynamicType('uint256[3]')).toBe(true);
    });

    it('should identify static types as not dynamic', () => {
      expect(isDynamicType('address')).toBe(false);
      expect(isDynamicType('uint256')).toBe(false);
      expect(isDynamicType('bytes32')).toBe(false);
      expect(isDynamicType('bool')).toBe(false);
    });

    it('should identify tuple with dynamic component as dynamic', () => {
      const components: ABIParam[] = [
        { name: 'token', type: 'address' },
        { name: 'data', type: 'bytes' },
      ];
      expect(isDynamicType('tuple', components)).toBe(true);
    });

    it('should identify tuple with only static components as not dynamic', () => {
      const components: ABIParam[] = [
        { name: 'tokenIn', type: 'address' },
        { name: 'tokenOut', type: 'address' },
        { name: 'amount', type: 'uint256' },
      ];
      expect(isDynamicType('tuple', components)).toBe(false);
    });
  });

  describe('getTupleStaticSize', () => {
    it('should compute size for static tuple', () => {
      const components: ABIParam[] = [
        { name: 'tokenIn', type: 'address' },
        { name: 'tokenOut', type: 'address' },
        { name: 'fee', type: 'uint24' },
      ];
      expect(getTupleStaticSize(components)).toBe(96);
    });

    it('should compute size for UniV3 exactInput params', () => {
      const components: ABIParam[] = [
        { name: 'tokenIn', type: 'address' },
        { name: 'tokenOut', type: 'address' },
        { name: 'fee', type: 'uint24' },
        { name: 'recipient', type: 'address' },
        { name: 'deadline', type: 'uint256' },
        { name: 'amountIn', type: 'uint256' },
        { name: 'amountOutMinimum', type: 'uint256' },
        { name: 'sqrtPriceLimitX96', type: 'uint160' },
      ];
      expect(getTupleStaticSize(components)).toBe(256);
    });
  });

  describe('computeParamOffsets', () => {
    it('should compute offsets for simple params', () => {
      const params: ABIParam[] = [
        { name: 'tokenIn', type: 'address' },
        { name: 'tokenOut', type: 'address' },
        { name: 'fee', type: 'uint24' },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets).toHaveLength(3);
      expect(offsets[0]).toEqual({ name: 'tokenIn', type: 'address', offset: 0 });
      expect(offsets[1]).toEqual({ name: 'tokenOut', type: 'address', offset: 32 });
      expect(offsets[2]).toEqual({ name: 'fee', type: 'uint24', offset: 64 });
    });

    it('should compute offsets for tuple params', () => {
      const params: ABIParam[] = [
        { 
          name: 'params', 
          type: 'tuple',
          components: [
            { name: 'tokenIn', type: 'address' },
            { name: 'amountIn', type: 'uint256' },
          ]
        },
        { name: 'deadline', type: 'uint256' },
      ];

      const offsets = computeParamOffsets(params);

      expect(offsets).toHaveLength(2);
      expect(offsets[0].offset).toBe(0);
      expect(offsets[1].offset).toBe(32);
    });
  });

  describe('resolveOffset', () => {
    const exactInputABI: ABIEntry = {
      name: 'exactInput',
      type: 'function',
      inputs: [
        {
          name: 'params',
          type: 'tuple',
          components: [
            { name: 'tokenIn', type: 'address' },
            { name: 'tokenOut', type: 'address' },
            { name: 'fee', type: 'uint24' },
            { name: 'recipient', type: 'address' },
            { name: 'deadline', type: 'uint256' },
            { name: 'amountIn', type: 'uint256' },
            { name: 'amountOutMinimum', type: 'uint256' },
            { name: 'sqrtPriceLimitX96', type: 'uint160' },
          ],
        },
      ],
      outputs: [{ name: 'amountOut', type: 'uint256' }],
    };

    it('should resolve offset for tuple param (dynamic pointer)', () => {
      const offset = resolveOffset(exactInputABI, 'params');
      expect(offset).toBe(0);
    });

    it('should throw for invalid param path', () => {
      expect(() => resolveOffset(exactInputABI, 'nonexistent')).toThrow('Parameter not found');
    });
  });

  describe('computeSelector', () => {
    it('should compute selector for exactInput', () => {
      const inputs: ABIParam[] = [
        {
          name: 'params',
          type: 'tuple',
          components: [
            { name: 'tokenIn', type: 'address' },
            { name: 'tokenOut', type: 'address' },
            { name: 'fee', type: 'uint24' },
            { name: 'recipient', type: 'address' },
            { name: 'deadline', type: 'uint256' },
            { name: 'amountIn', type: 'uint256' },
            { name: 'amountOutMinimum', type: 'uint256' },
            { name: 'sqrtPriceLimitX96', type: 'uint160' },
          ],
        },
      ];

      const selector = computeSelector('exactInput', inputs);
      expect(selector).toMatch(/^0x[a-f0-9]{8}$/);
    });

    it('should compute selector for simple function', () => {
      const inputs: ABIParam[] = [
        { name: 'to', type: 'address' },
        { name: 'amount', type: 'uint256' },
      ];

      const selector = computeSelector('transfer', inputs);
      expect(selector).toMatch(/^0x[a-f0-9]{8}$/);
    });

    it('should compute selector for function with bytes argument', () => {
      const inputs: ABIParam[] = [
        { name: 'data', type: 'bytes' },
      ];

      const selector = computeSelector('execute', inputs);
      expect(selector).toMatch(/^0x[a-f0-9]{8}$/);
    });
  });

  describe('validateCalldataLength', () => {
    it('should return true for valid calldata', () => {
      const calldata = '0x12345678' + '00'.repeat(100);
      const rules = [{ offset: 0 }, { offset: 32 }, { offset: 64 }];
      expect(validateCalldataLength(calldata as `0x${string}`, rules)).toBe(true);
    });

    it('should return false for calldata too short', () => {
      const calldata = '0x12345678' + '00'.repeat(10);
      const rules = [{ offset: 100 }];
      expect(validateCalldataLength(calldata as `0x${string}`, rules)).toBe(false);
    });
  });

  describe('getSelectorFromCalldata', () => {
    it('should extract selector from calldata', () => {
      const calldata = '0xc04b8d59' + '00'.repeat(64);
      expect(getSelectorFromCalldata(calldata as `0x${string}`)).toBe('0xc04b8d59');
    });

    it('should throw for calldata too short', () => {
      const calldata = '0x1234';
      expect(() => getSelectorFromCalldata(calldata as `0x${string}`)).toThrow('Calldata too short');
    });
  });
});