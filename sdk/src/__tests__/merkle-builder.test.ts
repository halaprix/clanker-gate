import { describe, it, expect } from 'vitest';
import {
  createMerkleTreeBuilder,
  hashPermissionLeaf,
  verifyMerkleProof,
} from '../builder/index.js';
import { UNISWAP_V3_ROUTER_ABI } from '../abi-registry/index.js';
import { compilePolicy } from '../policy-compiler/index.js';
import { OP } from '../types/index.js';
import type { MerkleTreeConfig } from '../builder/index.js';

// Deterministic test config — gate address / chain / account / nonce are
// arbitrary fixed values; they just need to be consistent within each test.
const TEST_CONFIG: MerkleTreeConfig = {
  account: '0x1111111111111111111111111111111111111111',
  gateAddress: '0x2222222222222222222222222222222222222222',
  chainId: 1n,
  nonce: 0n,
};

describe('merkle-builder', () => {
  describe('hashPermissionLeaf', () => {
    it('should produce consistent hash for same permission', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const hash1 = hashPermissionLeaf({ permission, ...TEST_CONFIG });
      const hash2 = hashPermissionLeaf({ permission, ...TEST_CONFIG });

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it('should produce different hashes for different permissions', () => {
      const permission1 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const permission2 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInputSingle',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const hash1 = hashPermissionLeaf({ permission: permission1, ...TEST_CONFIG });
      const hash2 = hashPermissionLeaf({ permission: permission2, ...TEST_CONFIG });

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different rules', () => {
      const permission1 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const permission2 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('2000000000000000000') },
        ],
      });

      const hash1 = hashPermissionLeaf({ permission: permission1, ...TEST_CONFIG });
      const hash2 = hashPermissionLeaf({ permission: permission2, ...TEST_CONFIG });

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different accounts', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [],
      });

      const hash1 = hashPermissionLeaf({ permission, ...TEST_CONFIG, account: '0x1111111111111111111111111111111111111111' });
      const hash2 = hashPermissionLeaf({ permission, ...TEST_CONFIG, account: '0x2222222222222222222222222222222222222222' });

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different nonces', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [],
      });

      const hash1 = hashPermissionLeaf({ permission, ...TEST_CONFIG, nonce: 0n });
      const hash2 = hashPermissionLeaf({ permission, ...TEST_CONFIG, nonce: 1n });

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('createMerkleTreeBuilder', () => {
    it('should build tree with single permission', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [
          { paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') },
        ],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission);

      const { root, leaves } = builder.build();

      expect(root).toMatch(/^0x[a-f0-9]{64}$/);
      expect(leaves).toHaveLength(1);
      expect(leaves[0]).toBe(hashPermissionLeaf({ permission, ...TEST_CONFIG }));
    });

    it('should build tree with multiple permissions', () => {
      const permission1 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const permission2 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInputSingle',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('500000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission1);
      builder.addPermission(permission2);

      const { root, leaves } = builder.build();

      expect(root).toMatch(/^0x[a-f0-9]{64}$/);
      expect(leaves).toHaveLength(2);
    });

    it('should return empty root for no permissions', () => {
      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      const { root, leaves } = builder.build();

      expect(root).toBe('0x0000000000000000000000000000000000000000000000000000000000000000');
      expect(leaves).toHaveLength(0);
    });

    it('should generate valid proof', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission);

      const { root } = builder.build();
      const proof = builder.getProof(permission);

      expect(proof.root).toBe(root);
      expect(proof.leaf).toBe(hashPermissionLeaf({ permission, ...TEST_CONFIG }));
      expect(proof.proof).toBeDefined();
    });
  });

  describe('verifyMerkleProof', () => {
    it('should verify valid proof for single leaf', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission);

      const { root } = builder.build();
      const proof = builder.getProof(permission);

      expect(verifyMerkleProof(root, proof.proof, proof.leaf)).toBe(true);
    });

    it('should verify valid proof for multiple leaves', () => {
      const permission1 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const permission2 = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInputSingle',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('500000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission1);
      builder.addPermission(permission2);

      const { root } = builder.build();
      const proof1 = builder.getProof(permission1);
      const proof2 = builder.getProof(permission2);

      expect(verifyMerkleProof(root, proof1.proof, proof1.leaf)).toBe(true);
      expect(verifyMerkleProof(root, proof2.proof, proof2.leaf)).toBe(true);
    });

    it('should reject invalid proof', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission);

      const { root } = builder.build();
      const wrongLeaf = '0x0000000000000000000000000000000000000000000000000000000000000001' as `0x${string}`;

      expect(verifyMerkleProof(root, [], wrongLeaf)).toBe(false);
    });

    it('should reject proof with wrong root', () => {
      const permission = compilePolicy({
        abi: UNISWAP_V3_ROUTER_ABI,
        target: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        functionName: 'exactInput',
        rules: [{ paramPath: 'params', op: OP.LTE, value: BigInt('1000000000000000000') }],
      });

      const builder = createMerkleTreeBuilder(TEST_CONFIG);
      builder.addPermission(permission);

      const proof = builder.getProof(permission);
      const wrongRoot = '0x0000000000000000000000000000000000000000000000000000000000000001' as `0x${string}`;

      expect(verifyMerkleProof(wrongRoot, proof.proof, proof.leaf)).toBe(false);
    });
  });
});
