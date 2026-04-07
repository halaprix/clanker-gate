import type { Hex, Address } from "viem";
import type { Permission } from "../domain/entities/Permission.js";
import type { ValidationResult } from "../domain/value-objects/ValidationResult.js";
import type { MerkleProof } from "../domain/ports/index.js";

export interface CreatePolicyInput {
  readonly target: Address;
  readonly selector: Hex;
  readonly rules: readonly { offset: number; op: number; value: bigint }[];
}

export interface CreatePolicyOutput {
  readonly permission: Permission;
}

export interface CreatePolicyUseCase {
  execute(input: CreatePolicyInput): Promise<CreatePolicyOutput>;
}

export interface VerifyPolicyInput {
  readonly calldata: Hex;
  readonly permission: Permission;
  readonly proof: MerkleProof;
  readonly root: Hex;
}

export interface VerifyPolicyUseCase {
  execute(input: VerifyPolicyInput): Promise<ValidationResult>;
}

export interface BuildMerkleTreeInput {
  readonly permissions: readonly Permission[];
}

export interface BuildMerkleTreeOutput {
  readonly root: Hex;
  readonly leaves: readonly Hex[];
}

export interface BuildMerkleTreeUseCase {
  execute(input: BuildMerkleTreeInput): Promise<BuildMerkleTreeOutput>;
}

export interface GenerateProofInput {
  readonly permission: Permission;
  readonly root: Hex;
}

export interface GenerateProofOutput {
  readonly proof: MerkleProof;
  readonly leaf: Hex;
}

export interface GenerateProofUseCase {
  execute(input: GenerateProofInput): Promise<GenerateProofOutput>;
}
