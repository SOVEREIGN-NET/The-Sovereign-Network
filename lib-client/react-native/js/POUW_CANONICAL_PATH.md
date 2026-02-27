# PoUW Canonical Integration Path

This package supports exactly one production integration path for PoUW:

1. Use `PoUWController`.
2. Call `start()`.
3. Record work using:
   - `recordWeb4ManifestRoute(...)`
   - `recordWeb4ContentServed(...)`
4. Let the controller batch/sign/submit receipts.

## Removed Paths

The following are intentionally unsupported and removed for production integration:

- Manual receipt JSON construction for submission.
- Direct app-managed PoUW receipt signing APIs in `lib-client`.
- App-level direct receipt/batch wiring as a public integration contract.

## Signature Policy

PoUW submissions use `dilithium5` signatures only.
`PoUWController` now emits `sig_scheme: "dilithium5"` unconditionally.

## Field Requirements

`provider_id` remains required by server receipt schema.
`PoUWController` always includes the field in emitted receipts.
