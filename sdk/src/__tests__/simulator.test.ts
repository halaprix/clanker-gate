import { describe, it, expect } from 'vitest';
import { encodeFunctionData } from 'viem';
import { createSimulator, simulator } from '../simulator/index.js';
import { compilePolicy, createMerkleTreeBuilder } from '../index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { OP, ValidationErrorCodes } from '../types/index.js';
import type { Permission } from '../types/index.js';
import type { MerkleTreeConfig } from '../builder/index.js';

const UNISWAP_V3_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45' as const;

// Deterministic test config — arbitrary fixed values consistent within tests.
const TEST_CONFIG: MerkleTreeConfig = {
  account: '0x1111111111111111111111111111111111111111',
  gateAddress: '0x2222222222222222222222222222222222222222',
  chainId: 1n,
  nonce: 0n,
};

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

function createTestCalldata(amountIn: bigint): `0x${string}` {
  return encodeFunctionData({
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
}

function toHex32(value: bigint): `0x${string}` {
  const hex = value.toString(16);
  return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
}

describe('Simulator', () => {
  describe('validateCalldata', () => {
    it('should pass valid calldata with matching selector and no rules', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
      expect(result.evaluatedRules).toEqual([]);
    });

    it('should pass valid calldata with EQ rule', () => {
      const sim = createSimulator();
      const amountIn = BigInt('1000000000000000000');
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.EQ, value: amountIn },
        ],
      });

      const calldata = createTestCalldata(amountIn);
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
      expect(result.evaluatedRules).toHaveLength(1);
      expect(result.evaluatedRules![0].passed).toBe(true);
    });

    it('should pass valid calldata with LTE rule', () => {
      const sim = createSimulator();
      const maxAmount = BigInt('2000000000000000000');
      const actualAmount = BigInt('1000000000000000000');
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: maxAmount },
        ],
      });

      const calldata = createTestCalldata(actualAmount);
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
    });

    it('should fail with selector mismatch', () => {
      const sim = createSimulator();
      const permission: Permission = {
        target: UNISWAP_V3_ROUTER,
        selector: '0xdeadbeef',
        rules: [],
      };

      const calldata = createTestCalldata(BigInt(1000));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.SELECTOR_MISMATCH);
    });

    it('should fail with calldata too short', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const result = sim.validateCalldata('0x1234', permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.CALLDATA_OUT_OF_RANGE);
    });

    it('should fail with rule violation - EQ mismatch', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.EQ, value: BigInt('1000000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('2000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.RULE_VIOLATION);
      expect(result.error?.details?.ruleIndex).toBe(0);
    });

    it('should fail with rule violation - LTE exceeded', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('2000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.RULE_VIOLATION);
    });

    it('should pass with GT rule', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.GT, value: BigInt('500000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
    });

    it('should fail with GT rule - value not greater', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.GT, value: BigInt('1000000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.RULE_VIOLATION);
    });

    it('should pass with GTE rule', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.GTE, value: BigInt('1000000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
    });

    it('should pass with LT rule', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LT, value: BigInt('2000000000000000000') },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
    });

    it('should fail with calldata out of range for offset', () => {
      const sim = createSimulator();
      const permission: Permission = {
        target: UNISWAP_V3_ROUTER,
        selector: '0x414bf389',
        rules: [
          { offset: 10000, op: OP.EQ, value: toHex32(BigInt(0)) },
        ],
      };

      const calldata = createTestCalldata(BigInt(1000));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.CALLDATA_OUT_OF_RANGE);
    });

    it('should evaluate multiple rules in order', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.GTE, value: BigInt('100000000000000000') },
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('10000000000000000000') },
          { paramPath: 'params.fee', op: OP.EQ, value: BigInt(3000) },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
      expect(result.evaluatedRules).toHaveLength(3);
      expect(result.evaluatedRules!.every(r => r.passed)).toBe(true);
    });

    it('should stop at first failed rule', () => {
      const sim = createSimulator();
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('100000000000000000') },
          { paramPath: 'params.fee', op: OP.EQ, value: BigInt(3000) },
        ],
      });

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validateCalldata(calldata, permission);

      expect(result.valid).toBe(false);
      expect(result.error?.details?.ruleIndex).toBe(0);
    });
  });

  describe('verifyProof', () => {
    it('should verify valid Merkle proof', () => {
      const sim = createSimulator();
      const builder = createMerkleTreeBuilder(TEST_CONFIG);

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      builder.addPermission(permission);
      const { root } = builder.build();
      const { proof, leaf } = builder.getProof(permission);

      expect(sim.verifyProof(root, proof, leaf)).toBe(true);
    });

    it('should reject invalid Merkle proof', () => {
      const sim = createSimulator();
      const builder = createMerkleTreeBuilder(TEST_CONFIG);

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const otherPermission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactOutputSingle',
        rules: [],
      });

      builder.addPermission(permission);
      const { root } = builder.build();
      const { proof } = builder.getProof(permission);
      // Compute leaf for a different permission — proof won't verify
      const otherLeaf = builder.getProof(permission).leaf; // same tree
      // Actually use the other permission's leaf
      const otherBuilder = createMerkleTreeBuilder(TEST_CONFIG);
      otherBuilder.addPermission(otherPermission);
      const { leaf: wrongLeaf } = otherBuilder.getProof(otherPermission);

      expect(sim.verifyProof(root, proof, wrongLeaf)).toBe(false);
    });
  });

  describe('validate (full validation)', () => {
    it('should pass full validation with valid proof and calldata', () => {
      const sim = createSimulator();
      const builder = createMerkleTreeBuilder(TEST_CONFIG);

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('2000000000000000000') },
        ],
      });

      builder.addPermission(permission);
      const { root } = builder.build();
      const { proof, leaf } = builder.getProof(permission);

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validate({ calldata, permission, proof, root, leaf });

      expect(result.success).toBe(true);
    });

    it('should fail with zero root', () => {
      const sim = createSimulator();
      const builder = createMerkleTreeBuilder(TEST_CONFIG);

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      builder.addPermission(permission);
      const { proof, leaf } = builder.getProof(permission);

      const calldata = createTestCalldata(BigInt(1000));
      const result = sim.validate({
        calldata,
        permission,
        proof,
        leaf,
        root: '0x0000000000000000000000000000000000000000000000000000000000000000',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.ROOT_NOT_SET);
    });

    it('should fail with invalid proof', () => {
      const sim = createSimulator();

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const otherPermission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactOutputSingle',
        rules: [],
      });

      const otherBuilder = createMerkleTreeBuilder(TEST_CONFIG);
      otherBuilder.addPermission(otherPermission);
      const { root } = otherBuilder.build();
      const { proof } = otherBuilder.getProof(otherPermission);

      // Compute leaf for permission (not in this tree)
      const permBuilder = createMerkleTreeBuilder(TEST_CONFIG);
      permBuilder.addPermission(permission);
      const { leaf } = permBuilder.getProof(permission);

      const calldata = createTestCalldata(BigInt(1000));
      const result = sim.validate({ calldata, permission, proof, root, leaf });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.INVALID_PROOF);
    });

    it('should fail with rule violation', () => {
      const sim = createSimulator();
      const builder = createMerkleTreeBuilder(TEST_CONFIG);

      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params.amountIn', op: OP.LTE, value: BigInt('100000000000000000') },
        ],
      });

      builder.addPermission(permission);
      const { root } = builder.build();
      const { proof, leaf } = builder.getProof(permission);

      const calldata = createTestCalldata(BigInt('1000000000000000000'));
      const result = sim.validate({ calldata, permission, proof, root, leaf });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(ValidationErrorCodes.RULE_VIOLATION);
    });
  });

  describe('singleton instance', () => {
    it('should work with pre-created simulator instance', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: UNISWAP_V3_ROUTER,
        functionName: 'exactInputSingle',
        rules: [],
      });

      const calldata = createTestCalldata(BigInt(1000));
      const result = simulator.validateCalldata(calldata, permission);

      expect(result.valid).toBe(true);
    });
  });
});
