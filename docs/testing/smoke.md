# Smoke Test Plan

## Purpose
- Provide a fast, reliable gate that checks the workspace builds and critical paths run before merging to `development`.
- Keep runtime under a few minutes so it can run on every PR and in pre-merge checks.

## What the smoke test runs
- Workspace build: `cargo test --workspace --tests --no-run` (compile all tests without executing).
- Core crates quick execution (pick one minimal test each to validate runtime wiring):
  - `cargo test -p lib-blockchain --tests -- --nocapture --test-threads=1`
  - `cargo test -p zhtp --tests -- --nocapture --test-threads=1`
- Optional (enable when time allows): `cargo check -p lib-network -p lib-identity` to catch interface drift.
- Integration readiness check for runtime identity wiring: `cargo test -p integration-tests -- --nocapture` (covers NodeId/DID stability across restarts).

## When to run
- On every PR via CI (fast lane).
- Locally before pushing if you touch interfaces used across crates.

## How to add new smoke cases
- Prefer minimal assertions that exercise the hot path without heavy fixtures.
- Place new smoke-focused tests in existing suites but gate heavier ones behind `#[ignore]` so they are not pulled into smoke.
- Keep per-crate additions under ~30s runtime; if longer, document in the test and mark `#[ignore]`.
- Name tests with a `smoke_` prefix to make intent clear (e.g., `smoke_identity_init`).

## CI integration notes
- Use `--no-run` for broad coverage to keep builds fast and network-independent.
- Avoid adding tests that require external services or network; if unavoidable, mark ignored and document setup.
- If the smoke set starts exceeding time budgets, split into:
  - `smoke` (always on)
  - `full` (manual/cron) using the same commands without `--no-run`.
