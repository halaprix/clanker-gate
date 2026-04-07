import type { Hex } from "viem";

export class ValidationResult {
  private constructor(
    readonly success: boolean,
    readonly error?: ValidationError
  ) {}

  static ok(): ValidationResult {
    return new ValidationResult(true);
  }

  static fail(error: ValidationError): ValidationResult {
    return new ValidationResult(false, error);
  }

  isOk(): boolean {
    return this.success;
  }

  isError(): boolean {
    return !this.success;
  }

  unwrap(): void {
    if (!this.success) {
      throw this.error;
    }
  }

  unwrapOr<T>(defaultValue: T): T | void {
    if (this.success) return;
    return defaultValue;
  }

  match<T>(handlers: { ok: () => T; fail: (error: ValidationError) => T }): T {
    return this.success ? handlers.ok() : handlers.fail(this.error!);
  }
}

export abstract class ValidationError extends Error {
  abstract readonly code: ValidationErrorCode;
  
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export const ValidationErrorCode = {
  ROOT_NOT_SET: 0,
  INVALID_PROOF: 1,
  UNAUTHORIZED_SIGNER: 2,
  SELECTOR_MISMATCH: 3,
  CALLDATA_OUT_OF_RANGE: 4,
  RULE_VIOLATION: 5,
  INVALID_SELECTOR: 6,
  CALLED_TOO_SHORT: 7,
  PERMISSION_NOT_YET_VALID: 8,
  PERMISSION_EXPIRED: 9,
  CHAIN_ID_MISMATCH: 10,
} as const;

export type ValidationErrorCode = (typeof ValidationErrorCode)[keyof typeof ValidationErrorCode];
