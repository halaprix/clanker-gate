# ClankerGate Gas Report

Generated: 2026-02-23

## Summary

ClankerGate provides efficient policy-based transaction validation with gas costs ranging from ~16k to ~42k depending on the number of rules.

## validateUserOp Gas Costs

| Configuration | Gas | Notes |
|---------------|-----|-------|
| 0 rules | 16,064 | Base validation cost |
| 1 rule (EQ) | 18,523 | +2,459 over base |
| 1 rule (IN, 3 values) | 19,959 | +3,895 over base |
| 5 rules (LTE) | 28,846 | +12,782 over base |
| 10 rules (LTE) | 41,695 | +25,631 over base |
| singleUse=true | 38,448 | Includes SSTORE for tracking |

## Other Operations

| Operation | Gas | Notes |
|-----------|-----|-------|
| setPolicyRoot | 51,606 | SSTORE + event emit |

## Calldata Extraction Comparison

| Approach | Gas | Notes |
|----------|-----|-------|
| ClankerGate (assembly) | 14 | Direct calldataload |
| ABI decode | 604 | 43x more expensive |

## Validation Approach Comparison

| Approach | Gas | Notes |
|----------|-----|-------|
| ABI decode validator | 6,366 | Simple decode + check |
| ClankerGate (1 rule LTE) | 18,620 | Full validation pipeline |

Note: The ABI decode approach is simpler but lacks:
- Merkle proof verification
- Signature validation
- Time window validation
- Chain ID validation
- Target validation
- Single-use tracking

## Scaling Analysis

Per-rule overhead is approximately:
- ~2,500 gas per EQ rule
- ~3,900 gas per IN rule (3 values)
- ~2,500 gas per LTE rule

For a typical DEX swap with 3 rules (token address, amount, recipient), expect ~25,000 gas for validation.

## Optimization Notes

1. **Calldata extraction**: Using inline assembly (`calldataload`) is 43x cheaper than ABI decode
2. **Single-use tracking**: Adds ~22k gas due to SSTORE (cold write)
3. **Rule overhead**: Each rule adds ~2-4k gas depending on operator type
4. **Merkle proof**: Cost scales with proof depth (tree size)

## Recommendations

- Use zero-proof validation (direct leaf) when only one permission is needed
- Limit rule count to 5 or fewer for gas efficiency
- Use singleUse sparingly due to SSTORE overhead
- Consider batch operations to amortize validation costs
