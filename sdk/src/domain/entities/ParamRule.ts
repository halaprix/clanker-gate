import type { Hex } from "viem";
import { Operator, type OperatorType, compare, OP } from "../value-objects/Operator.js";
import { Offset, InvalidOffsetError } from "../value-objects/Offset.js";

export interface ParamRuleProps {
  readonly offset: number;
  readonly op: OperatorType;
  readonly value: bigint;
  readonly values?: readonly bigint[];
}

export class ParamRule {
  readonly offset: Offset;
  readonly op: OperatorType;
  readonly value: bigint;
  readonly values: readonly bigint[];

  private constructor(props: ParamRuleProps) {
    this.offset = new Offset(props.offset);
    this.op = props.op;
    this.value = props.value;
    this.values = props.values ?? [];
  }

  static create(props: ParamRuleProps): ParamRule {
    return new ParamRule(props);
  }

  matches(actualValue: bigint): boolean {
    if (this.op === OP.IN) {
      return this.values.includes(actualValue);
    }
    return compare(this.op, actualValue, this.value);
  }

  toHex(): Hex {
    return `0x${this.value.toString(16).padStart(64, "0")}` as Hex;
  }

  toHexValues(): readonly Hex[] {
    return this.values.map((v) => `0x${v.toString(16).padStart(64, "0")}` as Hex);
  }

  get absoluteOffset(): number {
    return 4 + this.offset.value;
  }

  equals(other: ParamRule): boolean {
    if (this.offset.value !== other.offset.value) return false;
    if (this.op !== other.op) return false;
    if (this.value !== other.value) return false;
    if (this.values.length !== other.values.length) return false;
    return this.values.every((v, i) => v === other.values[i]);
  }
}

export { Offset, InvalidOffsetError };
