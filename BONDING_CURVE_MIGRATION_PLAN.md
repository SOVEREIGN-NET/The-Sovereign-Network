# Bonding Curve Migration Plan

## Goal

Replace the current bonding-curve implementation with the canonical 18-decimal, integer-only, fixed-layout protocol defined in `BONDING_CURVE_TECHNICAL_SPEC.md`.

## Phases

1. Protocol lock
2. Math engine replacement
3. State migration to `u128`
4. Fixed-layout buy/sell transaction model
5. API/runtime alignment
6. Genesis reset

## Merge gates

- no floating-point operations in bonding-curve consensus path
- no runtime-derived intercepts
- no `1e8` scale constants in bonding-curve consensus math
- no variable-length buy/sell tx layout
- all amount-bearing bonding-curve state uses `u128`
- restart and replay tests green
