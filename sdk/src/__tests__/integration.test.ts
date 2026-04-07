import { describe, it, expect } from 'vitest';
import { ClankerGate, permission } from '../index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { OP } from '../types/index.js';
import { encodeFunctionData } from 'viem';

describe('integration', () => {
  describe('ClankerGate API', () => {
    it('should create policy using fluent API', () => {
      const perm = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .lte(BigInt('1000000000000000000'))
        .build();

      expect(perm.target).toBe('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45');
      expect(perm.selector).toMatch(/^0x[a-f0-9]{8}$/);
      expect(perm.rules).toHaveLength(1);
    });

    it('should build merkle tree and generate proof', () => {
      const perm = ClankerGate.policy(UNISWAP_V3_ROUTER_ABI)
        .allow()
        .to('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')
        .fn('exactInput')
        .where('params')
        .lte(BigInt('1000000000000000000'))
        .build();

      const builder = ClankerGate.merkleTree();
      builder.addPermission(perm);
      
      const { root } = builder.build();
      const proof = builder.getProof(perm);

      expect(root).toMatch(/^0x[a-f0-9]{64}$/);
      expect(proof.leaf).toBe(ClankerGate.hashPermission(perm));
      expect(ClankerGate.verifyProof(proof.root, proof.proof, proof.leaf)).toBe(true);
    });

    it('should use permission shorthand', () => {
      const perm = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactInput',
        [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }]
      );

      expect(perm.target).toBe('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45');
    });
  });

  describe('Calldata offset validation', () => {
    it('should compute correct selector for exactInput', () => {
      const perm = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactInput',
        []
      );

      const calldata = encodeFunctionData({
        abi: [{
          name: 'exactInput',
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
        }],
        functionName: 'exactInput',
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

      expect(calldata.slice(0, 10)).toBe(perm.selector);
    });

    it('should compute correct selector for exactInputSingle', () => {
      const perm = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactInputSingle',
        []
      );

      const calldata = encodeFunctionData({
        abi: [{
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
        }],
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

      expect(calldata.slice(0, 10)).toBe(perm.selector);
    });
  });

  describe('ABI Registry', () => {
    it('should have UniswapV3Router ABI registered', () => {
      const abi = ClankerGate.registry.get('UniswapV3Router');
      expect(abi).toBeDefined();
      expect(abi?.find(e => e.name === 'exactInput')).toBeDefined();
      expect(abi?.find(e => e.name === 'exactInputSingle')).toBeDefined();
    });

    it('should get function from registry', () => {
      const func = ClankerGate.registry.getFunction('UniswapV3Router', 'exactInput');
      expect(func).toBeDefined();
      expect(func?.type).toBe('function');
      expect(func?.inputs).toBeDefined();
    });

    it('should create custom registry', () => {
      const customRegistry = ClankerGate.createRegistry();
      customRegistry.register('CustomContract', [
        { name: 'transfer', type: 'function', inputs: [
          { name: 'to', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ]},
      ]);

      const func = customRegistry.getFunction('CustomContract', 'transfer');
      expect(func).toBeDefined();
      expect(func?.name).toBe('transfer');
    });

    it('should check if registry has ABI', () => {
      expect(ClankerGate.registry.has('UniswapV3Router')).toBe(true);
      expect(ClankerGate.registry.has('NonExistent')).toBe(false);
    });
  });

  describe('Multiple permissions in merkle tree', () => {
    it('should handle 4 permissions in tree', () => {
      const builder = ClankerGate.merkleTree();

      const perm1 = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactInput',
        [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }]
      );

      const perm2 = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactInputSingle',
        [{ paramPath: 'params', op: OP.LTE, value: BigInt('2000000000000000000') }]
      );

      const perm3 = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactOutput',
        [{ paramPath: 'params', op: OP.LTE, value: BigInt('3000000000000000000') }]
      );

      const perm4 = permission(
        UNISWAP_V3_ROUTER_ABI,
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'exactOutputSingle',
        [{ paramPath: 'params', op: OP.LTE, value: BigInt('4000000000000000000') }]
      );

      builder.addPermission(perm1);
      builder.addPermission(perm2);
      builder.addPermission(perm3);
      builder.addPermission(perm4);

      const { root, leaves } = builder.build();
      expect(leaves).toHaveLength(4);

      const proof1 = builder.getProof(perm1);
      const proof2 = builder.getProof(perm2);
      const proof3 = builder.getProof(perm3);
      const proof4 = builder.getProof(perm4);

      expect(ClankerGate.verifyProof(root, proof1.proof, proof1.leaf)).toBe(true);
      expect(ClankerGate.verifyProof(root, proof2.proof, proof2.leaf)).toBe(true);
      expect(ClankerGate.verifyProof(root, proof3.proof, proof3.leaf)).toBe(true);
      expect(ClankerGate.verifyProof(root, proof4.proof, proof4.leaf)).toBe(true);
    });
  });
});