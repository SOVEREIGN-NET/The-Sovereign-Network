# Branch Protection Setup

The PR Quality Gates workflows are wired up in `.github/workflows/`, but
GitHub will not enforce them until you configure a **branch protection rule**
or **repository ruleset** in the UI. The workflows themselves only *report*
status checks; making those checks **required** is a one-time manual step.

This document is the canonical setup guide. Apply these settings to `main`
(and any other long-lived branch you want to protect, e.g. `release/*`).

## 1. Choose: Branch Protection Rule or Ruleset

GitHub supports both. Either works. **Rulesets** are the newer mechanism and
are recommended for new repositories because they support multiple targets,
import/export, and bypass lists. The "Branches" rule UI remains supported.

- **Rulesets:** Settings → **Rules → Rulesets** → **New ruleset → New branch ruleset**
- **Classic:** Settings → **Branches** → **Add branch protection rule**

## 2. Target the protected branch

- Branch name pattern (or "Target" in rulesets): `main`
- If you use release branches, add a second target like `release/*`.

## 3. Enable these checks

The exact label naming differs slightly between Rulesets and the classic UI;
the substantive settings are the same.

### Required pull request before merge

- Require a pull request before merging: **on**
- Required approvals: **at least 1** (raise this for higher-risk repos)
- Dismiss stale pull request approvals when new commits are pushed: **on**
- Require approval of the most recent reviewable push: **on** (rulesets only)
- **Require review from Code Owners: on** — this is what makes
  `.github/CODEOWNERS` actually enforce per-path reviewer assignment.

### Require status checks to pass before merging

- Require status checks to pass before merging: **on**
- Require branches to be up to date before merging: **on** (recommended)
- **Status checks that are required** — search and add **each of the
  following job names exactly**:

  From the **PR Quality Gates** workflow:
  - `architecture`
  - `security`
  - `blockchain`
  - `tokenomics`
  - `compliance`
  - `privacy_zkdid`
  - `governance`
  - `economic_risk`
  - `devops`
  - `performance`
  - `data_sovereignty`
  - `api`
  - `ux_safety`
  - `testing`
  - `documentation`

  From the **PR Triage** workflow (optional but recommended so triage
  always runs):
  - `triage`

  > **Note:** The check names will only appear in the search box after the
  > workflow has run **at least once** on a PR. Open a no-op PR (e.g. a
  > whitespace change in `README.md`) if you need to seed them.

### Other recommended settings

- Require conversation resolution before merging: **on**
- Require signed commits: **on** if your team is set up for it
- Require linear history: **on** (optional; pairs well with merge queue)
- Block force pushes: **on**
- Restrict deletions: **on**

### Bypass list

Keep this empty. If you must allow emergency bypass, restrict it to a single
admin team and audit usage.

## 4. (Optional) Enable Merge Queue

If you want serialized merges with re-tested branches:

1. In the same rule/ruleset: **Require merge queue: on**
2. Choose the merge method (squash recommended).
3. Set max queue size and timeout to your preference.

The workflows already handle merge-queue events because both `pr-triage.yml`
and `pr-quality-gates.yml` include the `merge_group:` trigger. No further
workflow changes are needed.

## 5. Verify

1. Open a draft PR that touches a critical path (e.g. `contracts/`).
2. Confirm the PR Triage workflow posts a sticky comment classifying the PR
   as `critical` and listing required agents.
3. Confirm the **Checks** tab on the PR shows all 15 quality-gate jobs.
4. Confirm the **Merge** button is **disabled** until checks pass and a
   Code Owner approves.
5. Push a deliberate violation (e.g. add `eval(...)` somewhere) and confirm
   `security` reports BLOCKER and the PR cannot merge.

## 6. CODEOWNERS prerequisite

`.github/CODEOWNERS` references teams under the `@SOVEREIGN-NET/*` org. Each
team must exist in **Organization → Teams** before the Code Owner check
behaves correctly. Until the teams exist, GitHub will silently ignore the
mappings and Code Owner enforcement will be a no-op.

Required teams (create if missing):

- `@SOVEREIGN-NET/core-maintainers`
- `@SOVEREIGN-NET/protocol`
- `@SOVEREIGN-NET/security`
- `@SOVEREIGN-NET/tokenomics`
- `@SOVEREIGN-NET/compliance`
- `@SOVEREIGN-NET/privacy`
- `@SOVEREIGN-NET/governance`
- `@SOVEREIGN-NET/devops`
- `@SOVEREIGN-NET/api`
- `@SOVEREIGN-NET/ux`
- `@SOVEREIGN-NET/documentation`
- `@SOVEREIGN-NET/data`

Each team must have at least one member with `write` access to this repo,
otherwise GitHub treats CODEOWNERS approvals as unsatisfiable.

## 7. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Required checks don't appear in the dropdown | The workflow has never run yet. Open any PR to trigger it. |
| All checks show ⏭ "skipped" or pending forever | Workflow file has a YAML error or is on a branch other than `main`. |
| `triage` job runs but no PR comment appears | The workflow is running on a `merge_group` event (no PR exists), or the GitHub App lacks `pull-requests: write`. |
| `security` always BLOCKER even on tiny PRs | Likely a real secret leaked into a tracked file. Read the JSON output, then rotate the credential. |
| CODEOWNERS approvals not enforced | Teams don't exist yet, are private to the org but not granted repo access, or the file has a syntax error (run `git log --check`). |

## 8. References

- GitHub: [About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- GitHub: [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- GitHub: [Managing a merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
- GitHub: [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
