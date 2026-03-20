# Bonding Curve Spec

## Scope

This defines the canonical CBE/SOV bonding-curve protocol for testnet reset.

## Token Units

- `SCALE: u128 = 1_000_000_000_000_000_000`
- `1 CBE = 10^18` raw units
- `1 SOV = 10^18` raw units
- All protocol amounts are raw integers
- No floating point anywhere

## Numeric Types

- Use `u128` for:
  - `gross_sov`
  - `min_cbe`
  - `delta_s`
  - `min_sov`
  - `circulating_supply`
  - `reserve_sov`
  - `treasury_sov`
  - `price`
  - `intercepts`
  - `buy receipt fields`
  - `sell receipt fields`
- Use `u64` for:
  - `nonce`
  - `deadline`
  - `block height`
  - `band index`
- Overflow aborts the transaction
- Division truncates down
- `isqrt` rounds down

## Curve Configuration

- `BAND_COUNT = 5`
- Bands:
  - Band 0: `[0, 10_000_000_000 * SCALE)`, `slope_num = 1`, `slope_den = 100_000_000_000_000`
  - Band 1: `[10_000_000_000 * SCALE, 30_000_000_000 * SCALE)`, `slope_num = 2`, `slope_den = 100_000_000_000_000`
  - Band 2: `[30_000_000_000 * SCALE, 60_000_000_000 * SCALE)`, `slope_num = 3`, `slope_den = 100_000_000_000_000`
  - Band 3: `[60_000_000_000 * SCALE, 85_000_000_000 * SCALE)`, `slope_num = 4`, `slope_den = 100_000_000_000_000`
  - Band 4: `[85_000_000_000 * SCALE, 100_000_000_000 * SCALE]`, `slope_num = 5`, `slope_den = 100_000_000_000_000`
- Intercepts:
  - `INTERCEPT_0 = 313_345_700_000_000`
  - `INTERCEPT_1..4` are precomputed offline and hardcoded as genesis constants
- Intercepts are never derived at runtime

## Price Function

Within band `i`:

```text
P(S) = (slope_num_i * S / slope_den_i) + intercept_i
```

## Split Rule

For buy input `gross_sov`:

```text
reserve_credit  = gross_sov * 20 / 100
treasury_credit = gross_sov * 80 / 100
remainder       = gross_sov - reserve_credit - treasury_credit
```

Protocol rule:

```text
reserve_credit = reserve_credit + remainder
```

## Single-Band Cost

```text
C(Sa, Sb) =
  (slope_num * (Sb - Sa) * (Sb + Sa) / slope_den / 2) +
  (intercept * (Sb - Sa))
```

## Single-Band Buy Inversion

```text
P0 = P(S)

delta_S =
  ((isqrt(P0^2 + (2 * slope_num * c / slope_den)) - P0) * slope_den) / slope_num
```

Rules:

- `isqrt` is floor
- If `slope_num == 0`, use `delta_S = c / intercept`

## Single-Band Sell

```text
R = C(S - delta_S, S)
```

Equivalent form:

```text
R =
  (slope_num * delta_S * (2*S - delta_S) / slope_den / 2) +
  (intercept * delta_S)
```

## Protocol Bounds

- `MAX_GROSS_SOV_PER_TX = 1_000_000_000_000_000_000_000_000`
- `MAX_DELTA_S_PER_TX = 100_000_000_000 * SCALE`
- `MAX_SUPPLY = 100_000_000_000 * SCALE`
- `BAND_COUNT = 5`
