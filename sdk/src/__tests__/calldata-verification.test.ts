import { describe, it, expect } from 'vitest';
import { encodeFunctionData, pad, toHex } from 'viem';
import { computeSelector, toHex32, getSelectorFromCalldata } from '../policy-compiler/offset-calculator.js';
import { compilePolicy, createPolicyBuilder } from '../policy-compiler/index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { OP } from '../types/index.js';

/**
 * Reads a 32-byte value from calldata at the specified byte offset.
 * Offset is absolute (0 = first byte after '0x').
 */
function readBytes32FromCalldata(calldata: `0x${string}`, byteOffset: number): `0x${string}` {
  const hexOffset = 2 + (byteOffset * 2); // Skip '0x', convert byte offset to hex chars
  const value = calldata.slice(hexOffset, hexOffset + 64);
  if (value.length < 64) {
    return '0x' + value.padEnd(64, '0') as `0x${string}`;
  }
  return '0x' + value as `0x${string}`;
}

/**
 * Reads the selector (first 4 bytes) from calldata.
 */
function readSelector(calldata: `0x${string}`): `0x${string}` {
  return calldata.slice(0, 10) as `0x${string}`;
}

describe('Calldata Offset Verification', () => {
  const UNISWAP_V3_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45' as const;
  
  /**
   * For exactInput with static tuple, ABI encoding is:
   * - Selector: 4 bytes (offset 0)
   * - tokenIn: 32 bytes (offset 4)
   * - tokenOut: 32 bytes (offset 36)
   * - fee: 32 bytes (offset 68)
   * - recipient: 32 bytes (offset 100)
   * - deadline: 32 bytes (offset 132)
   * - amountIn: 32 bytes (offset 164)
   * - amountOutMinimum: 32 bytes (offset 196)
   * - sqrtPriceLimitX96: 32 bytes (offset 228)
   */

  const exactInputABI = [{
    name: 'exactInputSingle',
    type: 'function',
    inputs: [{
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
    }],
    outputs: [{ name: 'amountOut', type: 'uint256' }],
  }] as const;

  // Offsets for tuple fields (relative to start of calldata)
  const OFFSETS = {
    selector: 0,
    tokenIn: 4,
    tokenOut: 36,
    fee: 68,
    recipient: 100,
    deadline: 132,
    amountIn: 164,
    amountOutMinimum: 196,
    sqrtPriceLimitX96: 228,
  };

  describe('Selector Verification', () => {
    it('should compute correct selector for exactInput', () => {
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const computedSelector = computeSelector('exactInputSingle', exactInputABI[0].inputs!);
      const actualSelector = readSelector(calldata);

      expect(actualSelector).toBe(computedSelector);
    });
  });

  describe('Tuple Field Offsets', () => {
    it('should correctly read tokenIn (first field, offset 4)', () => {
      const tokenIn = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn,
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualTokenIn = readBytes32FromCalldata(calldata, OFFSETS.tokenIn);
      const expectedTokenIn = pad(tokenIn, { size: 32 });

      expect(actualTokenIn.toLowerCase()).toBe(expectedTokenIn.toLowerCase());
    });

    it('should correctly read tokenOut (second field, offset 36)', () => {
      const tokenOut = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut,
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualTokenOut = readBytes32FromCalldata(calldata, OFFSETS.tokenOut);
      const expectedTokenOut = pad(tokenOut, { size: 32 });

      expect(actualTokenOut.toLowerCase()).toBe(expectedTokenOut.toLowerCase());
    });

    it('should correctly read fee (third field, offset 68)', () => {
      const fee = 3000;
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualFee = readBytes32FromCalldata(calldata, OFFSETS.fee);
      expect(BigInt(actualFee)).toBe(BigInt(fee));
    });

    it('should correctly read recipient (fourth field, offset 100)', () => {
      const recipient = '0x1234567890123456789012345678901234567890';
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient,
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualRecipient = readBytes32FromCalldata(calldata, OFFSETS.recipient);
      const expectedRecipient = pad(recipient, { size: 32 });

      expect(actualRecipient.toLowerCase()).toBe(expectedRecipient.toLowerCase());
    });

    it('should correctly read deadline (fifth field, offset 132)', () => {
      const deadline = BigInt(1234567890);
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline,
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualDeadline = readBytes32FromCalldata(calldata, OFFSETS.deadline);
      expect(BigInt(actualDeadline)).toBe(deadline);
    });

    it('should correctly read amountIn (sixth field, offset 164)', () => {
      const amountIn = BigInt('1000000000000000000'); // 1 ETH
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn,
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actualAmountIn = readBytes32FromCalldata(calldata, OFFSETS.amountIn);
      const expectedAmountIn = toHex32(amountIn);

      expect(actualAmountIn).toBe(expectedAmountIn);
    });

    it('should correctly read amountOutMinimum (seventh field, offset 196)', () => {
      const amountOutMinimum = BigInt('500000000000000000'); // 0.5 ETH
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum,
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const actual = readBytes32FromCalldata(calldata, OFFSETS.amountOutMinimum);
      expect(BigInt(actual)).toBe(amountOutMinimum);
    });

    it('should correctly read sqrtPriceLimitX96 (eighth field, offset 228)', () => {
      const sqrtPriceLimitX96 = BigInt('79228162514264337593543950336'); // 2^96
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96,
        }],
      });

      const actual = readBytes32FromCalldata(calldata, OFFSETS.sqrtPriceLimitX96);
      expect(BigInt(actual)).toBe(sqrtPriceLimitX96);
    });
  });

  describe('Policy Compilation with Real Calldata', () => {
    it('should create policy with matching selector', () => {
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 3000,
          recipient: '0x1234567890123456789012345678901234567890',
          deadline: BigInt(1234567890),
          amountIn: BigInt('1000000000000000000'),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const actualSelector = getSelectorFromCalldata(calldata);
      expect(permission.selector).toBe(actualSelector);
    });
  });

  describe('Edge Cases', () => {
    it('should handle zero values correctly', () => {
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 0,
          recipient: '0x0000000000000000000000000000000000000001',
          deadline: BigInt(0),
          amountIn: BigInt(0),
          amountOutMinimum: BigInt(0),
          sqrtPriceLimitX96: BigInt(0),
        }],
      });

      const amountIn = readBytes32FromCalldata(calldata, OFFSETS.amountIn);
      expect(amountIn).toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
    });

    it('should handle maximum uint256 values', () => {
      const maxUint256 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
      const maxUint160 = BigInt('0xffffffffffffffffffffffffffffffffffffffff');
      
      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [{
          tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
          tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          fee: 0,
          recipient: '0x0000000000000000000000000000000000000001',
          deadline: maxUint256,
          amountIn: maxUint256,
          amountOutMinimum: maxUint256,
          sqrtPriceLimitX96: maxUint160, // uint160 max
        }],
      });

      const amountIn = readBytes32FromCalldata(calldata, OFFSETS.amountIn);
      expect(BigInt(amountIn)).toBe(maxUint256);
    });

    it('should verify all fields match expected values', () => {
      const testData = {
        tokenIn: '0x1111111111111111111111111111111111111111' as `0x${string}`,
        tokenOut: '0x2222222222222222222222222222222222222222' as `0x${string}`,
        fee: 500,
        recipient: '0x3333333333333333333333333333333333333333' as `0x${string}`,
        deadline: BigInt(999999),
        amountIn: BigInt('123456789012345678'),
        amountOutMinimum: BigInt('100000'),
        sqrtPriceLimitX96: BigInt('79228162514264337593543950336'),
      };

      const calldata = encodeFunctionData({
        abi: exactInputABI,
        functionName: 'exactInputSingle',
        args: [testData],
      });

      // Verify each field
      expect(readBytes32FromCalldata(calldata, OFFSETS.tokenIn).toLowerCase())
        .toBe(pad(testData.tokenIn, { size: 32 }).toLowerCase());
      
      expect(readBytes32FromCalldata(calldata, OFFSETS.tokenOut).toLowerCase())
        .toBe(pad(testData.tokenOut, { size: 32 }).toLowerCase());
      
      expect(BigInt(readBytes32FromCalldata(calldata, OFFSETS.fee)))
        .toBe(BigInt(testData.fee));
      
      expect(readBytes32FromCalldata(calldata, OFFSETS.recipient).toLowerCase())
        .toBe(pad(testData.recipient, { size: 32 }).toLowerCase());
      
      expect(BigInt(readBytes32FromCalldata(calldata, OFFSETS.deadline)))
        .toBe(testData.deadline);
      
      expect(BigInt(readBytes32FromCalldata(calldata, OFFSETS.amountIn)))
        .toBe(testData.amountIn);
      
      expect(BigInt(readBytes32FromCalldata(calldata, OFFSETS.amountOutMinimum)))
        .toBe(testData.amountOutMinimum);
      
      expect(BigInt(readBytes32FromCalldata(calldata, OFFSETS.sqrtPriceLimitX96)))
        .toBe(testData.sqrtPriceLimitX96);
    });
  });
});
