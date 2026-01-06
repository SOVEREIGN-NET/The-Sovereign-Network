Web4 CLI End-to-End Test Suite
================================

Location: tests/e2e/

Quick start
-----------

Requirements:
- `zhtp-cli` must be on PATH
- `jq` must be installed
- `./run-node.sh` should be runnable in repo root

Run the suite:

```bash
bash tests/e2e/runner.sh
```

What is included
-----------------
- `lib/cli.sh` — CLI wrappers and JSON extraction helpers
- `lib/site_generator.sh` — generates simple sites for deploys
- `lib/node_ctrl.sh` — start/stop/restart node helper (uses `run-node.sh`)
- `lib/asserts.sh` — small assertion helpers
- `runner.sh` — orchestrates the 7 phases described in the issue
- `BUG_REPORT_TEMPLATE.md` — template for filing bugs discovered by the tests

Git workflow for committing tests
--------------------------------
1. Create a feature branch from `development`:

```bash
git checkout development
git pull origin development
git checkout -b feat/e2e-tests-537
```

2. Add & stage your files:

```bash
git add tests/e2e/
git commit -m "tests(e2e): add Web4 CLI E2E suite for issue #537"
git push -u origin feat/e2e-tests-537
```

3. Open a PR targeting `development`, reference `#537` in the PR description.

Notes
-----
- The runner uses `run-node.sh` to start the local node. Adjust `node_ctrl.sh` if you prefer `cargo run -p zhtp` directly.
- The scripts write debug artifacts to `tests/e2e/tmp/` — include these when filing bugs.
