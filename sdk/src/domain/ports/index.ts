import type { Hex, Address } from "viem";
import type { Permission } from "../entities/Permission.js";
import type { ValidationResult } from "../value-objects/ValidationResult.js";

export interface MerkleProof {
  readonly siblings: readonly Hex[];
}

export interface HashPermissionPort {
  hash(permission: Permission): Hex;
}

export interface MerkleTreePort {
  buildRoot(permissions: readonly Permission[]): Hex;
  generateProof(permission: Permission, root: Hex): MerkleProof;
  verifyProof(root: Hex, proof: MerkleProof, leaf: Hex): boolean;
}

export interface CalldataValidatorPort {
  validate(calldata: Hex, permission: Permission): ValidationResult;
}

export interface SignatureValidatorPort {
  verifySignature(hash: Hex, signature: Hex, expectedSigner: Address): boolean;
}

export interface ABIResolverPort {
  resolveOffset(abi: unknown, functionName: string, paramPath: string): number;
  computeSelector(abi: unknown, functionName: string): Hex;
}
