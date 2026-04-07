import type { Hex } from "viem";

const SELECTOR_REGEX = /^0x[a-fA-F0-9]{8}$/;

export class Selector {
  readonly value: Hex;

  constructor(value: Hex) {
    if (!SELECTOR_REGEX.test(value)) {
      throw new InvalidSelectorError(value);
    }
    this.value = value;
  }

  static fromSignature(signature: string, hashFn: (sig: string) => Hex): Selector {
    const hash = hashFn(signature);
    return new Selector(hash.slice(0, 10) as Hex);
  }

  equals(other: Selector): boolean {
    return this.value.toLowerCase() === other.value.toLowerCase();
  }

  toString(): string {
    return this.value;
  }
}

export class InvalidSelectorError extends Error {
  constructor(readonly value: Hex) {
    super(`Invalid selector: ${value}. Expected format: 0x + 8 hex characters.`);
    this.name = "InvalidSelectorError";
  }
}
