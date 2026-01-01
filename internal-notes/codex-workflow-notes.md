# Working Pattern (keep consistent)

- Check branch cleanliness, stay on the issue branch, avoid touching the original checkout with local user changes.
- Read the related docs in `docs/` and `/internal-docs` before coding; prefer existing patterns over new ones.
- Add targeted tests near the code under test; keep them deterministic and fast. If network features are heavy, isolate under feature flags or pure units.
- Run the narrowest possible command to validate (e.g., `cargo test -p <crate> --test <file>`), record the exact command in the PR body.
- Only change files that belong to the issue branch or original base; avoid unrelated churn.
- Keep PR summaries concise: what changed, why, tests.
- Never mention tooling/AI in commits or PR text; write as the human author.
