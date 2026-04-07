import type { Hex } from "viem";
import { keccak256, encodeAbiParameters, parseAbiParameters } from "viem";
import type { Permission } from "../domain/entities/Permission.js";
import type { ParamRule } from "../domain/entities/ParamRule.js";
import type {
  BuildMerkleTreeInput,
  BuildMerkleTreeOutput,
  GenerateProofInput,
  GenerateProofOutput,
} from "./types.js";
import type { MerkleProof } from "../domain/ports/index.js";

export class HashPermissionService {
  hash(permission: Permission): Hex {
    const rulesEncoded = permission.rules.map((rule: ParamRule) => [
      BigInt(rule.offset.value),
      rule.op,
      rule.toHex(),
      rule.toHexValues(),
    ] as const);

    const encoded = encodeAbiParameters(
      parseAbiParameters("address, bytes4, (uint256, uint8, bytes32, bytes32[])[], uint48, uint48, uint256"),
      [
        permission.target,
        permission.selector.value,
        rulesEncoded,
        permission.validAfter,
        permission.validUntil,
        BigInt(permission.chainId),
      ]
    );

    return keccak256(encoded);
  }
}

export class MerkleTreeService {
  private readonly hasher = new HashPermissionService();
  private tree: MerkleTree | null = null;

  async buildTree(input: BuildMerkleTreeInput): Promise<BuildMerkleTreeOutput> {
    const leaves = input.permissions.map((p) => this.hasher.hash(p));
    this.tree = this.createTree(leaves);
    
    return {
      root: this.tree.root,
      leaves,
    };
  }

  async generateProof(input: GenerateProofInput): Promise<GenerateProofOutput> {
    if (!this.tree) {
      throw new Error("Tree not built. Call buildTree first.");
    }

    const leaf = this.hasher.hash(input.permission);
    const proof = this.createProof(this.tree, leaf);

    return { proof, leaf };
  }

  verifyProof(root: Hex, proof: MerkleProof, leaf: Hex): boolean {
    let current = leaf;

    for (const sibling of proof.siblings) {
      current = this.combineHashes(current, sibling);
    }

    return current === root;
  }

  private createTree(leaves: readonly Hex[]): MerkleTree {
    if (leaves.length === 0) {
      return {
        root: "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex,
        nodes: [],
        leaves: [],
      };
    }

    if (leaves.length === 1) {
      return { root: leaves[0], nodes: [leaves], leaves };
    }

    const nodes: Hex[][] = [];
    let currentLevel = [...leaves];
    nodes.push(currentLevel);

    while (currentLevel.length > 1) {
      const nextLevel: Hex[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        nextLevel.push(this.combineHashes(left, right));
      }
      currentLevel = nextLevel;
      nodes.push(currentLevel);
    }

    return { root: currentLevel[0], nodes, leaves };
  }

  private combineHashes(a: Hex, b: Hex): Hex {
    const [first, second] = a < b ? [a, b] : [b, a];
    const encoded = encodeAbiParameters(
      parseAbiParameters("bytes32, bytes32"),
      [first, second]
    );
    return keccak256(encoded);
  }

  private createProof(tree: MerkleTree, leaf: Hex): MerkleProof {
    const proof: Hex[] = [];
    let index = tree.leaves.indexOf(leaf);

    if (index === -1) {
      throw new Error("Leaf not found in tree");
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

    return { siblings: proof };
  }
}

interface MerkleTree {
  root: Hex;
  nodes: readonly (readonly Hex[])[];
  leaves: readonly Hex[];
}
