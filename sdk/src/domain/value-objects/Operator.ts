import type { Hex } from "viem";

export const OP = {
  EQ: 0,
  GT: 1,
  LT: 2,
  GTE: 3,
  LTE: 4,
  IN: 5,
} as const;

export const Operator = OP;

export type OperatorType = (typeof Operator)[keyof typeof Operator];

export const OperatorSymbol: Record<OperatorType, string> = {
  [Operator.EQ]: "==",
  [Operator.GT]: ">",
  [Operator.LT]: "<",
  [Operator.GTE]: ">=",
  [Operator.LTE]: "<=",
  [Operator.IN]: "in",
};

export function isOperator(value: number): value is OperatorType {
  return Object.values(Operator).includes(value as OperatorType);
}

export function operatorFromNumber(value: number): OperatorType | null {
  if (isOperator(value)) return value;
  return null;
}

export function compare(operator: OperatorType, actual: bigint, expected: bigint): boolean {
  switch (operator) {
    case Operator.EQ: return actual === expected;
    case Operator.GT: return actual > expected;
    case Operator.LT: return actual < expected;
    case Operator.GTE: return actual >= expected;
    case Operator.LTE: return actual <= expected;
    case Operator.IN: return false; // IN requires array, handled separately
    default: return false;
  }
}
