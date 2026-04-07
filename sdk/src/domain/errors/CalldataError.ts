import { ValidationError, ValidationErrorCode } from "../value-objects/ValidationResult.js";

export class CalldataError extends ValidationError {
  readonly code = ValidationErrorCode.CALLED_TOO_SHORT;
}

export class CalldataTooShortError extends CalldataError {
  constructor(readonly length: number) {
    super(`Calldata too short: ${length} bytes`);
    this.name = "CalldataTooShortError";
  }
}
