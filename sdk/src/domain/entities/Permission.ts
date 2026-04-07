import type { Address, Hex } from "viem";
import { ValidationResult } from "../value-objects/ValidationResult.js";
import { CalldataTooShortError } from "../errors/CalldataError.js";
import { SelectorMismatchError, CalldataOutOfRangeError, RuleViolationError, PermissionExpiredError, PermissionNotYetValidError, ChainIdMismatchError } from "../errors/ValidationError.js";
import { Selector, InvalidSelectorError } from "../value-objects/Selector.js";
import { ParamRule, type ParamRuleProps } from "./ParamRule.js";

export interface PermissionProps {
  readonly target: Address;
  readonly selector: Hex;
  readonly rules: readonly ParamRuleProps[];
  readonly validAfter: number;
  readonly validUntil: number;
  readonly chainId: number;
}

export class Permission {
  readonly target: Address;
  readonly selector: Selector;
  readonly rules: readonly ParamRule[];
  readonly validAfter: number;
  readonly validUntil: number;
  readonly chainId: number;

  private constructor(props: PermissionProps) {
    this.target = props.target;
    this.selector = new Selector(props.selector);
    this.rules = props.rules.map((r) => ParamRule.create(r));
    this.validAfter = props.validAfter;
    this.validUntil = props.validUntil;
    this.chainId = props.chainId;
  }

  static create(props: PermissionProps): Permission {
    return new Permission(props);
  }

  hasRules(): boolean {
    return this.rules.length > 0;
  }

  getRuleCount(): number {
    return this.rules.length;
  }

  findRuleByOffset(offset: number): ParamRule | undefined {
    return this.rules.find((r) => r.offset.value === offset);
  }

  isExpired(currentTime: number): boolean {
    return this.validUntil > 0 && currentTime > this.validUntil;
  }

  isNotYetValid(currentTime: number): boolean {
    return this.validAfter > 0 && currentTime < this.validAfter;
  }

  isValidForChain(currentChainId: number): boolean {
    return this.chainId === 0 || this.chainId === currentChainId;
  }

  validateTimeWindow(currentTime: number): ValidationResult {
    if (this.isNotYetValid(currentTime)) {
      return ValidationResult.fail(new PermissionNotYetValidError(currentTime, this.validAfter));
    }
    if (this.isExpired(currentTime)) {
      return ValidationResult.fail(new PermissionExpiredError(currentTime, this.validUntil));
    }
    return ValidationResult.ok();
  }

  validateChainId(currentChainId: number): ValidationResult {
    if (!this.isValidForChain(currentChainId)) {
      return ValidationResult.fail(new ChainIdMismatchError(this.chainId, currentChainId));
    }
    return ValidationResult.ok();
  }

  validateCalldata(calldata: Hex): ValidationResult {
    if (calldata.length < 10) {
      return ValidationResult.fail(new CalldataTooShortError(calldata.length));
    }

    const calldataSelector = calldata.slice(0, 10) as Hex;
    if (calldataSelector !== this.selector.value) {
      return ValidationResult.fail(
        new SelectorMismatchError(this.selector.value, calldataSelector)
      );
    }

    for (let i = 0; i < this.rules.length; i++) {
      const rule = this.rules[i];
      const absoluteOffset = rule.absoluteOffset;

      if (absoluteOffset + 32 > (calldata.length - 2) / 2) {
        return ValidationResult.fail(
          new CalldataOutOfRangeError(absoluteOffset, calldata.length)
        );
      }

      const actualValue = this.readValueAtOffset(calldata, absoluteOffset);
      
      if (!rule.matches(actualValue)) {
        return ValidationResult.fail(
          new RuleViolationError(i, rule, actualValue)
        );
      }
    }

    return ValidationResult.ok();
  }

  private readValueAtOffset(calldata: Hex, byteOffset: number): bigint {
    const start = 2 + byteOffset * 2;
    const hex = calldata.slice(start, start + 64);
    return BigInt(`0x${hex || "0"}`);
  }

  equals(other: Permission): boolean {
    if (this.target !== other.target) return false;
    if (this.selector.value !== other.selector.value) return false;
    if (this.rules.length !== other.rules.length) return false;
    if (this.validAfter !== other.validAfter) return false;
    if (this.validUntil !== other.validUntil) return false;
    if (this.chainId !== other.chainId) return false;
    
    return this.rules.every((rule, i) => rule.equals(other.rules[i]));
  }
}
