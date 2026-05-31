import type { Permission, Hex32, ValidationError, ValidationErrorCode, SimulatorResult, OpType, ValidationResult, ParamRule } from '../types/index.js';
import { OP, ValidationErrorCodes } from '../types/index.js';
import { verifyMerkleProof } from '../builder/index.js';

const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000' as Hex32;

/**
 * Reads a 32-byte value from calldata at the specified byte offset.
 */
function readBytes32(calldata: `0x${string}`, byteOffset: number): Hex32 {
  const start = 2 + byteOffset * 2;
  const value = calldata.slice(start, start + 64);
  if (value.length < 64) {
    return ('0x' + value.padEnd(64, '0')) as Hex32;
  }
  return ('0x' + value) as Hex32;
}

/**
 * Reads the 4-byte function selector from calldata.
 */
function readSelector(calldata: `0x${string}`): `0x${string}` {
  return calldata.slice(0, 10) as `0x${string}`;
}

/**
 * Checks if a value is in an array.
 */
function inArray(value: Hex32, array: readonly Hex32[]): boolean {
  return array.includes(value);
}

/**
 * Compares values using the specified operator.
 * Matches the contract's compareRule function exactly.
 */
function compareRule(op: OpType, actual: Hex32, expected: Hex32, values?: readonly Hex32[]): boolean {
  switch (op) {
    case OP.EQ:
      return actual === expected;
    case OP.GT:
      return actual > expected;
    case OP.LT:
      return actual < expected;
    case OP.GTE:
      return actual >= expected;
    case OP.LTE:
      return actual <= expected;
    case OP.IN:
      return values ? inArray(actual, values) : false;
    default:
      return false;
  }
}

/**
 * Creates an off-chain simulator for validating transactions against policies.
 *
 * The simulator replicates the on-chain validation logic exactly, allowing
 * developers to test policies before deploying them.
 *
 * @example
 * ```typescript
 * const simulator = createSimulator();
 *
 * // Validate calldata against a permission
 * const result = simulator.validateCalldata(calldata, permission);
 * if (!result.valid) {
 *   console.log('Rule violation:', result.error);
 * }
 *
 * // Full validation with Merkle proof + pre-computed leaf
 * const { proof, leaf } = builder.getProof(permission);
 * const fullResult = simulator.validate({
 *   calldata,
 *   permission,
 *   proof,
 *   root,
 *   leaf,
 * });
 * ```
 */
export function createSimulator() {
  return {
    /**
     * Validates calldata against a permission's rules.
     *
     * This replicates the contract's _validateCallData logic.
     *
     * @param calldata - Transaction calldata (including selector)
     * @param permission - Permission to validate against
     * @returns SimulatorResult with detailed validation info
     */
    validateCalldata(calldata: `0x${string}`, permission: Permission): SimulatorResult {
      if (calldata.length < 10) {
        return {
          valid: false,
          error: {
            code: ValidationErrorCodes.CALLDATA_OUT_OF_RANGE,
            message: 'Calldata too short (must be at least 4 bytes)',
            details: { offset: 0 },
          },
        };
      }

      const selector = readSelector(calldata);
      if (selector !== permission.selector) {
        return {
          valid: false,
          error: {
            code: ValidationErrorCodes.SELECTOR_MISMATCH,
            message: `Selector mismatch: expected ${permission.selector}, got ${selector}`,
          },
        };
      }

      const evaluatedRules: {
        readonly offset: number;
        readonly op: OpType;
        readonly expected: Hex32;
        readonly actual: Hex32;
        readonly passed: boolean;
      }[] = [];

      for (let i = 0; i < permission.rules.length; i++) {
        const rule = permission.rules[i];
        const absoluteOffset = 4 + rule.offset;

        if (absoluteOffset + 32 > (calldata.length - 2) / 2) {
          return {
            valid: false,
            error: {
              code: ValidationErrorCodes.CALLDATA_OUT_OF_RANGE,
              message: `Calldata out of range: offset ${absoluteOffset} exceeds calldata length`,
              details: { offset: absoluteOffset },
            },
            evaluatedRules,
          };
        }

        const actualValue = readBytes32(calldata, absoluteOffset);
        const passed = compareRule(rule.op, actualValue, rule.value, rule.values);

        evaluatedRules.push({
          offset: rule.offset,
          op: rule.op,
          expected: rule.value,
          actual: actualValue,
          passed,
        });

        if (!passed) {
          const message = rule.op === OP.IN
            ? `Rule ${i} violated: ${actualValue} not in allowed values`
            : `Rule ${i} violated: ${actualValue} does not satisfy operator ${rule.op} with expected ${rule.value}`;
          return {
            valid: false,
            error: {
              code: ValidationErrorCodes.RULE_VIOLATION,
              message,
              details: {
                ruleIndex: i,
                operator: rule.op,
                expected: rule.value,
                actual: actualValue,
                offset: rule.offset,
              },
            },
            evaluatedRules,
          };
        }
      }

      return { valid: true, evaluatedRules };
    },

    /**
     * Verifies that a pre-computed leaf is included in the Merkle tree.
     *
     * Use builder.getProof(permission).leaf as the leaf argument.
     *
     * @param root  - Merkle tree root hash
     * @param proof - Merkle proof siblings
     * @param leaf  - Pre-computed canonical leaf hash (from hashPermissionLeaf or builder.getProof)
     * @returns true if proof is valid
     */
    verifyProof(root: Hex32, proof: readonly Hex32[], leaf: Hex32): boolean {
      return verifyMerkleProof(root, proof, leaf);
    },

    /**
     * Full validation matching the contract's validateUserOp logic.
     *
     * The caller must supply a pre-computed canonical leaf (from builder.getProof or
     * hashPermissionLeaf) so the simulator does not need to know the gate/chain/nonce context.
     *
     * @param params - Validation parameters including pre-computed leaf
     * @returns ValidationResult with success or detailed error
     */
    validate(params: {
      calldata: `0x${string}`;
      permission: Permission;
      proof: readonly Hex32[];
      root: Hex32;
      leaf: Hex32;
    }): ValidationResult {
      if (params.root === ZERO_BYTES32) {
        return {
          success: false,
          error: {
            code: ValidationErrorCodes.ROOT_NOT_SET,
            message: 'Policy root is not set (zero bytes32)',
          },
        };
      }

      if (!verifyMerkleProof(params.root, params.proof, params.leaf)) {
        return {
          success: false,
          error: {
            code: ValidationErrorCodes.INVALID_PROOF,
            message: 'Invalid Merkle proof for permission',
          },
        };
      }

      const calldataResult = this.validateCalldata(params.calldata, params.permission);
      if (!calldataResult.valid) {
        return { success: false, error: calldataResult.error! };
      }

      return { success: true };
    },
  };
}

export type Simulator = ReturnType<typeof createSimulator>;

/**
 * Pre-created simulator instance for convenience.
 */
export const simulator = createSimulator();
