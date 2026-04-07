import { ValidationError, ValidationErrorCode } from "../value-objects/ValidationResult.js";
import type { ParamRule } from "../entities/ParamRule.js";

export class CalldataTooShortError extends ValidationError {
  readonly code = ValidationErrorCode.CALLED_TOO_SHORT;

  constructor(readonly length: number) {
    super(`Calldata too short: ${length} bytes. Minimum is 4 bytes for selector.`);
    this.name = "CalldataTooShortError";
  }
}

export class SelectorMismatchError extends ValidationError {
  readonly code = ValidationErrorCode.SELECTOR_MISMATCH;

  constructor(
    readonly expected: `0x${string}`,
    readonly actual: `0x${string}`
  ) {
    super(`Selector mismatch: expected ${expected}, got ${actual}`);
    this.name = "SelectorMismatchError";
  }
}

export class CalldataOutOfRangeError extends ValidationError {
  readonly code = ValidationErrorCode.CALLDATA_OUT_OF_RANGE;

  constructor(
    readonly offset: number,
    readonly calldataLength: number
  ) {
    super(`Offset ${offset} exceeds calldata length ${calldataLength}`);
    this.name = "CalldataOutOfRangeError";
  }
}

export class RuleViolationError extends ValidationError {
  readonly code = ValidationErrorCode.RULE_VIOLATION;

  constructor(
    readonly ruleIndex: number,
    readonly rule: ParamRule,
    readonly actualValue: bigint
  ) {
    super(
      `Rule ${ruleIndex} violated: ${actualValue} does not satisfy rule at offset ${rule.offset.value}`
    );
    this.name = "RuleViolationError";
  }
}

export class RootNotSetError extends ValidationError {
  readonly code = ValidationErrorCode.ROOT_NOT_SET;

  constructor() {
    super("Policy root not set for account");
    this.name = "RootNotSetError";
  }
}

export class InvalidProofError extends ValidationError {
  readonly code = ValidationErrorCode.INVALID_PROOF;

  constructor() {
    super("Invalid Merkle proof");
    this.name = "InvalidProofError";
  }
}

export class UnauthorizedSignerError extends ValidationError {
  readonly code = ValidationErrorCode.UNAUTHORIZED_SIGNER;

  constructor(
    readonly expected: `0x${string}`,
    readonly actual: `0x${string}`
  ) {
    super(`Unauthorized signer: expected ${expected}, got ${actual}`);
    this.name = "UnauthorizedSignerError";
  }
}

export class PermissionExpiredError extends ValidationError {
  readonly code = ValidationErrorCode.PERMISSION_EXPIRED;

  constructor(
    readonly currentTime: number,
    readonly validUntil: number
  ) {
    super(`Permission expired at ${validUntil}, current time is ${currentTime}`);
    this.name = "PermissionExpiredError";
  }
}

export class PermissionNotYetValidError extends ValidationError {
  readonly code = ValidationErrorCode.PERMISSION_NOT_YET_VALID;

  constructor(
    readonly currentTime: number,
    readonly validAfter: number
  ) {
    super(`Permission not yet valid until ${validAfter}, current time is ${currentTime}`);
    this.name = "PermissionNotYetValidError";
  }
}

export class ChainIdMismatchError extends ValidationError {
  readonly code = ValidationErrorCode.CHAIN_ID_MISMATCH;

  constructor(
    readonly expectedChainId: number,
    readonly actualChainId: number
  ) {
    super(`Permission not valid for chain ${actualChainId}, expected chain ${expectedChainId} (0 = all chains)`);
    this.name = "ChainIdMismatchError";
  }
}
