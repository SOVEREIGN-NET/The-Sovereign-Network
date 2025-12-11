# macOS CI (manual run) with simulated BLE link

This workflow uses GitHub Actions to build on `macos-14` and run the lib-network test suite (including the mock BLE link tests). No hardware is required.

## When to run
- To validate macOS build/link and BLE/GATT code paths without hardware.
- After changes to `lib-network` BLE/GATT modules, mock adapters, or UHP framing.

## Prereqs
- Your branch is pushed to GitHub (HTTPS remote is fine; credential manager will prompt).
- Permissions to run workflows in the repo.

## Trigger via GitHub UI (recommended)
1) Push your branch: `git push origin <branch>`.
2) In GitHub, open **Actions** ➜ choose the **CI** workflow.
3) Click **Run workflow** (top-right).
4) Set **Branch** (`ref` input) to your branch (e.g., `issue-137-pqc`). Default is `development`.
5) Click **Run workflow** to start the job.

## Trigger via `gh` CLI (alternative)
```bash
# Login (browser flow)
gh auth login

# From repo root, trigger CI on your branch
gh workflow run ci.yml -f ref=<branch-name>
```

## What runs on macOS
- `cargo build --workspace --locked`
- `cargo test -p lib-network --locked -- --nocapture`
  - Includes BLE mock link tests (`mock_link_round_trip`, `mock_link_verifier_rejects_unverified_payload`) and UHP-over-GATT framing tests.

## Validate results
- In the workflow run, open the **macos** job logs.
- Confirm build succeeded and the lib-network test section shows the mock link tests passing.
- No deploy occurs for manual runs; deploy only happens on push to `development`.

## Notes
- Push/PR to `development` still auto-runs CI; the manual trigger is for ad-hoc macOS validation on other branches.
