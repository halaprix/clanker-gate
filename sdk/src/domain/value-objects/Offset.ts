export class Offset {
  readonly value: number;

  constructor(value: number) {
    if (value < 0 || !Number.isInteger(value)) {
      throw new InvalidOffsetError(value);
    }
    this.value = value;
  }

  equals(other: Offset): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return String(this.value);
  }

  add(delta: number): Offset {
    return new Offset(this.value + delta);
  }
}

export class InvalidOffsetError extends Error {
  constructor(readonly offset: number) {
    super(`Invalid offset: ${offset}. Offset must be a non-negative integer.`);
    this.name = "InvalidOffsetError";
  }
}
