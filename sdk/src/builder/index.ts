import { keccak256, encodeAbiParameters, parseAbiParameters } from 'viem';
import type { Permission, Hex32, MerkleProofResult, ParamRule } from '../types/index.js';

export { computeDomainSeparator, hashPermissionStruct, hashPermissionLeaf } from './leaf.js';

function encodeRule(rule: ParamRule): readonly [bigint, number, Hex32, readonly Hex32[]] {
  return [
    BigInt(rule.offset),
    rule.op,
    rule.value,
    rule.values ?? [],
  ] as const;
}

/**
 * Computes the keccak256 hash of a permission.
 * 
 * The hash is used as a leaf in the Merkle tree. The permission is ABI-encoded
 * with the following structure: (address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256, bool)
 * 
 * @param permission - Permission to hash
 * @returns 32-byte keccak256 hash
 * 
 * @example
 * ```typescript
 * const hash = hashPermission(permission);
 * // Returns: "0x..." (32 bytes)
 * ```
 */
export function hashPermission(permission: Permission): Hex32 {
  const rulesEncoded = permission.rules.map(encodeRule);

  const encoded = encodeAbiParameters(
    parseAbiParameters('address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256, bool'),
    [
      permission.target,
      permission.selector,
      rulesEncoded,
      permission.validAfter,
      permission.validUntil,
      BigInt(permission.chainId),
      permission.singleUse ?? false,
    ]
  );

  return keccak256(encoded) as Hex32;
}

/**
 * Creates a builder for constructing Merkle trees from permissions.
 * 
 * The builder accumulates permissions and provides methods to:
 * - Build the Merkle tree and get the root
 * - Generate proofs for individual permissions
 * 
 * @example
 * ```typescript
 * const builder = createMerkleTreeBuilder();
 * builder.addPermission(permission1);
 * builder.addPermission(permission2);
 * 
 * const { root, leaves } = builder.build();
 * const proof = builder.getProof(permission1);
 * ```
 * 
 * @returns Merkle tree builder object
 */
export function createMerkleTreeBuilder() {
  const permissions: Permission[] = [];

  return {
    /**
     * Adds a permission to the tree.
     * Permissions are hashed to create the tree leaves.
     * @param permission - Permission to add
     */
    addPermission: (permission: Permission) => {
      permissions.push(permission);
    },

    /**
     * Builds the Merkle tree from all added permissions.
     * @returns Object containing root hash and leaf hashes
     */
    build: () => {
      const leaves = permissions.map(hashPermission);
      const tree = buildMerkleTree(leaves);
      return { root: tree.root, leaves };
    },

    /**
     * Generates a Merkle proof for a specific permission.
     * The proof can be verified on-chain to prove the permission is in the tree.
     * 
     * @param permission - Permission to generate proof for
     * @returns Proof result with proof array, root, and leaf hash
     * @throws Error if permission not found in tree
     */
    getProof: (permission: Permission): MerkleProofResult => {
      const leaf = hashPermission(permission);
      const leaves = permissions.map(hashPermission);
      const tree = buildMerkleTree(leaves);
      const proof = generateProof(tree, leaf);

      return { proof, root: tree.root, leaf };
    },

    /**
     * Returns a copy of all added permissions.
     * @returns Array of permissions
     */
    getPermissions: () => [...permissions],
  };
}

/** Merkle tree builder type returned by createMerkleTreeBuilder */
export type MerkleTreeBuilder = ReturnType<typeof createMerkleTreeBuilder>;

/**
 * Internal representation of a Merkle tree.
 */
interface MerkleTree {
  /** Root hash of the tree */
  readonly root: Hex32;
  /** All nodes organized by level */
  readonly nodes: readonly (readonly Hex32[])[];
  /** Leaf hashes (hashed permissions) */
  readonly leaves: readonly Hex32[];
}

/**
 * Builds a Merkle tree from leaf hashes.
 * 
 * Uses sorted hash combination for each pair to ensure
 * consistent proof generation regardless of node order.
 * 
 * @param leaves - Array of leaf hashes
 * @returns Merkle tree structure
 */
function buildMerkleTree(leaves: readonly Hex32[]): MerkleTree {
  if (leaves.length === 0) {
    return {
      root: '0x0000000000000000000000000000000000000000000000000000000000000000' as Hex32,
      nodes: [],
      leaves: [],
    };
  }

  if (leaves.length === 1) {
    return { root: leaves[0], nodes: [leaves], leaves };
  }

  const nodes: Hex32[][] = [];
  let currentLevel = [...leaves];
  nodes.push(currentLevel);

  while (currentLevel.length > 1) {
    const nextLevel: Hex32[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
      nextLevel.push(combineHashes(left, right));
    }

    currentLevel = nextLevel;
    nodes.push(currentLevel);
  }

  return { root: currentLevel[0], nodes, leaves };
}

/**
 * Combines two hashes by sorting them and computing keccak256.
 * 
 * Sorting ensures that hash(a, b) == hash(b, a), which is important
 * for Merkle proof verification on-chain.
 * 
 * @param a - First hash
 * @param b - Second hash
 * @returns Combined hash
 */
function combineHashes(a: Hex32, b: Hex32): Hex32 {
  const [first, second] = a < b ? [a, b] : [b, a];
  const encoded = encodeAbiParameters(
    parseAbiParameters('bytes32, bytes32'),
    [first, second]
  );
  return keccak256(encoded) as Hex32;
}

/**
 * Generates a Merkle proof for a leaf in the tree.
 * 
 * The proof consists of sibling hashes at each level of the tree,
 * needed to reconstruct the root hash.
 * 
 * @param tree - Merkle tree structure
 * @param leaf - Leaf hash to generate proof for
 * @returns Array of sibling hashes
 * @throws Error if leaf not found in tree
 */
function generateProof(tree: MerkleTree, leaf: Hex32): readonly Hex32[] {
  const proof: Hex32[] = [];
  let index = tree.leaves.indexOf(leaf);

  if (index === -1) {
    throw new Error('Leaf not found in tree');
  }

  for (let i = 0; i < tree.nodes.length - 1; i++) {
    const level = tree.nodes[i];
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : index + 1;

    if (siblingIndex < level.length) {
      proof.push(level[siblingIndex]);
    } else {
      proof.push(level[index]);
    }

    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Verifies a Merkle proof against a known root.
 * 
 * Recombines the leaf with proof hashes to reconstruct the root.
 * If the reconstructed root matches, the leaf is proven to be in the tree.
 * 
 * @param root - Known root hash (stored on-chain)
 * @param proof - Array of sibling hashes
 * @param leaf - Leaf hash to verify
 * @returns true if proof is valid, false otherwise
 * 
 * @example
 * ```typescript
 * const isValid = verifyMerkleProof(root, proof, leaf);
 * if (isValid) {
 *   // Permission is authorized
 * }
 * ```
 */
export function verifyMerkleProof(
  root: Hex32,
  proof: readonly Hex32[],
  leaf: Hex32
): boolean {
  let current = leaf;

  for (const sibling of proof) {
    current = combineHashes(current, sibling);
  }

  return current === root;
}
