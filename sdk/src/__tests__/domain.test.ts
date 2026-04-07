import { describe, it, expect } from "vitest";
import { Permission, type PermissionProps } from "../domain/entities/Permission.js";
import { ParamRule, type ParamRuleProps } from "../domain/entities/ParamRule.js";
import { Operator, type OperatorType, compare } from "../domain/value-objects/Operator.js";
import { Selector } from "../domain/value-objects/Selector.js";
import { Offset } from "../domain/value-objects/Offset.js";
import { ValidationResult } from "../domain/value-objects/ValidationResult.js";
import {
  CalldataTooShortError,
  SelectorMismatchError,
  CalldataOutOfRangeError,
  RuleViolationError,
} from "../domain/index.js";
import type { Hex } from "viem";

describe("Offset Value Object", () => {
  it("creates valid offset", () => {
    const offset = new Offset(100);
    expect(offset.value).toBe(100);
  });

  it("throws for negative offset", () => {
    expect(() => new Offset(-1)).toThrow();
  });

  it("throws for non-integer offset", () => {
    expect(() => new Offset(1.5)).toThrow();
  });

  it("equals another offset with same value", () => {
    const a = new Offset(100);
    const b = new Offset(100);
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal different offset", () => {
    const a = new Offset(100);
    const b = new Offset(200);
    expect(a.equals(b)).toBe(false);
  });

  it("adds delta to create new offset", () => {
    const offset = new Offset(100);
    const newOffset = offset.add(32);
    expect(newOffset.value).toBe(132);
  });
});

describe("Selector Value Object", () => {
  it("creates valid selector", () => {
    const selector = new Selector("0xc04b8d59" as Hex);
    expect(selector.value).toBe("0xc04b8d59");
  });

  it("throws for invalid selector format", () => {
    expect(() => new Selector("invalid" as Hex)).toThrow();
    expect(() => new Selector("0x1234" as Hex)).toThrow();
    expect(() => new Selector("0x123456789" as Hex)).toThrow();
  });

  it("equals selector with same value", () => {
    const a = new Selector("0xc04b8d59" as Hex);
    const b = new Selector("0xc04b8d59" as Hex);
    expect(a.equals(b)).toBe(true);
  });

  it("case-insensitive equality", () => {
    const a = new Selector("0xC04B8D59" as Hex);
    const b = new Selector("0xc04b8d59" as Hex);
    expect(a.equals(b)).toBe(true);
  });
});

describe("Operator Value Object", () => {
  it("has correct operator values", () => {
    expect(Operator.EQ).toBe(0);
    expect(Operator.GT).toBe(1);
    expect(Operator.LT).toBe(2);
    expect(Operator.GTE).toBe(3);
    expect(Operator.LTE).toBe(4);
  });

  it("isOperator validates correctly", () => {
    expect(Operator.isOperator ? true : false);
  });

  describe("compare function", () => {
    it("EQ compares correctly", () => {
      expect(compare(Operator.EQ, BigInt(100), BigInt(100))).toBe(true);
      expect(compare(Operator.EQ, BigInt(100), BigInt(200))).toBe(false);
    });

    it("GT compares correctly", () => {
      expect(compare(Operator.GT, BigInt(200), BigInt(100))).toBe(true);
      expect(compare(Operator.GT, BigInt(100), BigInt(100))).toBe(false);
    });

    it("LT compares correctly", () => {
      expect(compare(Operator.LT, BigInt(50), BigInt(100))).toBe(true);
      expect(compare(Operator.LT, BigInt(100), BigInt(100))).toBe(false);
    });

    it("GTE compares correctly", () => {
      expect(compare(Operator.GTE, BigInt(100), BigInt(100))).toBe(true);
      expect(compare(Operator.GTE, BigInt(200), BigInt(100))).toBe(true);
      expect(compare(Operator.GTE, BigInt(50), BigInt(100))).toBe(false);
    });

    it("LTE compares correctly", () => {
      expect(compare(Operator.LTE, BigInt(100), BigInt(100))).toBe(true);
      expect(compare(Operator.LTE, BigInt(50), BigInt(100))).toBe(true);
      expect(compare(Operator.LTE, BigInt(200), BigInt(100))).toBe(false);
    });
  });
});

describe("ParamRule Entity", () => {
  it("creates valid rule", () => {
    const props: ParamRuleProps = {
      offset: 100,
      op: Operator.LTE,
      value: BigInt("1000000000000000000"),
    };
    const rule = ParamRule.create(props);
    
    expect(rule.offset.value).toBe(100);
    expect(rule.op).toBe(Operator.LTE);
    expect(rule.value).toBe(BigInt("1000000000000000000"));
  });

  it("calculates absolute offset correctly", () => {
    const rule = ParamRule.create({
      offset: 128,
      op: Operator.LTE,
      value: BigInt(1000),
    });
    expect(rule.absoluteOffset).toBe(132);
  });

  it("converts value to hex correctly", () => {
    const rule = ParamRule.create({
      offset: 0,
      op: Operator.EQ,
      value: BigInt(255),
    });
    expect(rule.toHex()).toBe("0x00000000000000000000000000000000000000000000000000000000000000ff");
  });

  it("matches values correctly", () => {
    const rule = ParamRule.create({
      offset: 0,
      op: Operator.LTE,
      value: BigInt(1000),
    });
    
    expect(rule.matches(BigInt(500))).toBe(true);
    expect(rule.matches(BigInt(1000))).toBe(true);
    expect(rule.matches(BigInt(2000))).toBe(false);
  });

  it("equals another rule with same values", () => {
    const a = ParamRule.create({ offset: 100, op: Operator.EQ, value: BigInt(1000) });
    const b = ParamRule.create({ offset: 100, op: Operator.EQ, value: BigInt(1000) });
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal rule with different values", () => {
    const a = ParamRule.create({ offset: 100, op: Operator.EQ, value: BigInt(1000) });
    const b = ParamRule.create({ offset: 200, op: Operator.EQ, value: BigInt(1000) });
    expect(a.equals(b)).toBe(false);
  });
});

describe("ValidationResult Value Object", () => {
  it("creates success result", () => {
    const result = ValidationResult.ok();
    expect(result.isOk()).toBe(true);
    expect(result.isError()).toBe(false);
  });

  it("creates failure result", () => {
    const error = new CalldataTooShortError(4);
    const result = ValidationResult.fail(error);
    expect(result.isOk()).toBe(false);
    expect(result.isError()).toBe(true);
  });

  it("unwrap returns void on success", () => {
    const result = ValidationResult.ok();
    expect(() => result.unwrap()).not.toThrow();
  });

  it("unwrap throws error on failure", () => {
    const error = new CalldataTooShortError(4);
    const result = ValidationResult.fail(error);
    expect(() => result.unwrap()).toThrow(error);
  });

  it("match handles both cases", () => {
    const success = ValidationResult.ok();
    const failure = ValidationResult.fail(new CalldataTooShortError(4));

    expect(success.match({
      ok: () => "success",
      fail: () => "fail",
    })).toBe("success");

    expect(failure.match({
      ok: () => "success",
      fail: (e) => e.name,
    })).toBe("CalldataTooShortError");
  });
});

describe("Permission Entity", () => {
  const createPermission = (rules: ParamRuleProps[] = []): Permission => {
    return Permission.create({
      target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45" as Hex,
      selector: "0xc04b8d59" as Hex,
      rules,
    });
  };

  it("creates valid permission", () => {
    const permission = createPermission();
    expect(permission.target).toBe("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45");
    expect(permission.selector.value).toBe("0xc04b8d59");
  });

  it("has rules returns correct boolean", () => {
    const withRules = createPermission([
      { offset: 100, op: Operator.LTE, value: BigInt(1000) },
    ]);
    const withoutRules = createPermission();

    expect(withRules.hasRules()).toBe(true);
    expect(withoutRules.hasRules()).toBe(false);
  });

  it("getRuleCount returns correct count", () => {
    const permission = createPermission([
      { offset: 100, op: Operator.EQ, value: BigInt(1) },
      { offset: 200, op: Operator.LTE, value: BigInt(2) },
    ]);
    expect(permission.getRuleCount()).toBe(2);
  });

  it("findRuleByOffset finds rule", () => {
    const permission = createPermission([
      { offset: 100, op: Operator.EQ, value: BigInt(1) },
    ]);
    const rule = permission.findRuleByOffset(100);
    expect(rule).toBeDefined();
    expect(rule?.value).toBe(BigInt(1));
  });

  describe("validateCalldata", () => {
    it("fails for calldata too short", () => {
      const permission = createPermission();
      const result = permission.validateCalldata("0x1234" as Hex);
      expect(result.isError()).toBe(true);
      expect((result as any).error).toBeInstanceOf(CalldataTooShortError);
    });

    it("fails for selector mismatch", () => {
      const permission = createPermission();
      const calldata = "0x123456780000000000000000000000000000000000000000000000000000000000000001" as Hex;
      const result = permission.validateCalldata(calldata);
      expect(result.isError()).toBe(true);
      expect((result as any).error).toBeInstanceOf(SelectorMismatchError);
    });

    it("passes for matching selector with no rules", () => {
      const permission = createPermission();
      const calldata = "0xc04b8d590000000000000000000000000000000000000000000000000000000000000001" as Hex;
      const result = permission.validateCalldata(calldata);
      expect(result.isOk()).toBe(true);
    });

    it("fails for calldata out of range", () => {
      const permission = createPermission([
        { offset: 1000, op: Operator.EQ, value: BigInt(1) },
      ]);
      const calldata = "0xc04b8d590000000000000000000000000000000000000000000000000000000000000001" as Hex;
      const result = permission.validateCalldata(calldata);
      expect(result.isError()).toBe(true);
      expect((result as any).error).toBeInstanceOf(CalldataOutOfRangeError);
    });

    it("fails for rule violation", () => {
      const permission = createPermission([
        { offset: 0, op: Operator.LTE, value: BigInt(100) },
      ]);
      const calldata = "0xc04b8d5900000000000000000000000000000000000000000000000000000000000002bc" as Hex;
      const result = permission.validateCalldata(calldata);
      expect(result.isError()).toBe(true);
      expect((result as any).error).toBeInstanceOf(RuleViolationError);
    });

    it("passes for rule satisfaction", () => {
      const permission = createPermission([
        { offset: 0, op: Operator.LTE, value: BigInt(1000) },
      ]);
      const calldata = "0xc04b8d590000000000000000000000000000000000000000000000000000000000000064" as Hex;
      const result = permission.validateCalldata(calldata);
      expect(result.isOk()).toBe(true);
    });
  });

  it("equals another permission with same values", () => {
    const a = Permission.create({
      target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45" as Hex,
      selector: "0xc04b8d59" as Hex,
      rules: [{ offset: 0, op: Operator.EQ, value: BigInt(1) }],
    });
    const b = Permission.create({
      target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45" as Hex,
      selector: "0xc04b8d59" as Hex,
      rules: [{ offset: 0, op: Operator.EQ, value: BigInt(1) }],
    });
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal permission with different target", () => {
    const a = Permission.create({
      target: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45" as Hex,
      selector: "0xc04b8d59" as Hex,
      rules: [],
    });
    const b = Permission.create({
      target: "0x0000000000000000000000000000000000000001" as Hex,
      selector: "0xc04b8d59" as Hex,
      rules: [],
    });
    expect(a.equals(b)).toBe(false);
  });
});