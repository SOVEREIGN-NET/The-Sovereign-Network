#!/usr/bin/env python3
"""
PR Triage Agent.

Reads the changed files in the PR, applies .github/review-policy.yml, and
emits a triage report (Markdown + JSON). This script never fails the build;
its only job is to summarize and recommend.

Outputs (in the working directory):
  - triage_result.md
  - triage_result.json

Outputs (env-driven):
  - GITHUB_STEP_SUMMARY    : Markdown summary appended for the Actions UI
  - GITHUB_OUTPUT          : key=value pairs (risk_level, required_agents)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Allow running as `python .github/agents/pr_triage.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CRITICAL_DOMAINS = {
    "smart_contracts",
    "chain_core",
    "tokenomics_treasury",
    "identity_zk",
    "governance",
    "production_infra",
    "migrations",
}


def classify_domain(path: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith("contracts/") or p.startswith("smart-contracts/") or p.endswith((".sol", ".cairo", ".vy")):
        return "smart-contracts"
    if p.startswith(("chain/", "blockchain/", "consensus/", "node/")):
        return "chain"
    if p.startswith(("tokenomics/", "treasury/")):
        return "tokenomics"
    if p.startswith(("identity/", "zk/")) or "/zkdid/" in p or "zkproof" in p:
        return "identity-zk"
    if p.startswith(("governance/", "dao/")):
        return "governance"
    if p.startswith("infra/"):
        return "infra"
    if p.startswith("migrations/") or "/migrations/" in p:
        return "migrations"
    if p.startswith(("api/", "sdk/")) or p.endswith(".proto"):
        return "api"
    if p.startswith("mobile/") or "/wallet/" in p:
        return "mobile-wallet"
    if p.startswith(("frontend/", "web/")):
        return "frontend"
    if p.startswith(".github/"):
        return "ci"
    if p.startswith("docs/") or p.endswith(".md") or p.startswith("README"):
        return "docs"
    if "/tests/" in p or p.startswith("tests/") or "test_" in os.path.basename(p):
        return "tests"
    return "other"


def build_reasons(files: list[str], rules: list[dict]) -> list[str]:
    reasons: list[str] = []
    for r in rules:
        name = r.get("name") or "rule"
        risk = r.get("risk_level") or "low"
        sample = next(
            (f for f in files if common.match_any(f, r.get("match") or [])),
            None,
        )
        if sample:
            reasons.append(f"`{name}` (**{risk}**) matched — e.g. `{sample}`")
    return reasons


def merge_policy(risk_level: str, has_critical_domain: bool) -> str:
    if has_critical_domain or risk_level == "critical":
        return (
            "🔴 **Critical change.** Code Owner approval is required, all PR "
            "Quality Gates must pass, and override is **not** allowed."
        )
    if risk_level == "high":
        return (
            "🟠 **High-risk change.** Code Owner approval is required and all "
            "applicable PR Quality Gates must pass before merge."
        )
    if risk_level == "medium":
        return (
            "🟡 **Medium-risk change.** Standard review applies. PR Quality "
            "Gates must pass; override is allowed with documented justification."
        )
    return (
        "🟢 **Low-risk change.** Standard review applies. Most agents will "
        "report `not applicable`."
    )


def render_markdown(
    files: list[str],
    rules: list[dict],
    risk_level: str,
    domains: list[str],
    required_agents: list[str],
    reviewers: list[str],
    requires_tests: bool,
    has_tests: bool,
    has_docs: bool,
    has_migrations: bool,
    reasons: list[str],
) -> str:
    badges = {
        "low": "🟢 LOW",
        "medium": "🟡 MEDIUM",
        "high": "🟠 HIGH",
        "critical": "🔴 CRITICAL",
    }
    badge = badges.get(risk_level, risk_level.upper())
    lines = [
        "## 🔍 PR Triage Report",
        "",
        f"**Risk level:** {badge}",
        f"**Files changed:** {len(files)}",
        f"**Affected domains:** {', '.join(f'`{d}`' for d in domains) if domains else '_none_'}",
        "",
        "### Required review agents",
    ]
    if required_agents:
        for a in required_agents:
            lines.append(f"- `{a}`")
    else:
        lines.append("_None — defaults will apply._")
    lines += ["", "### Recommended human reviewers"]
    if reviewers:
        for r in reviewers:
            lines.append(f"- {r}")
    else:
        lines.append("_None._")

    lines += ["", "### Why this classification"]
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("- No specific policy rule matched. Defaults applied.")

    lines += ["", "### Pre-merge checklist", ""]
    lines.append(f"- [{'x' if has_tests or not requires_tests else ' '}] Tests touched"
                 + (" _(required for this risk level)_" if requires_tests else ""))
    lines.append(f"- [{'x' if has_docs else ' '}] Docs touched")
    if has_migrations:
        lines.append("- [ ] Migration includes rollback notes (verify in description)")

    lines += ["", "### Merge policy", "", merge_policy(risk_level, any(r.get("name") in CRITICAL_DOMAINS for r in rules))]
    lines += ["", "### Next steps for reviewers", "",
              "1. Wait for **PR Quality Gates** to finish — every required agent must report `PASS`, `INFO`, or be non-applicable.",
              "2. Resolve any `MAJOR` or `BLOCKER` findings before requesting re-review.",
              "3. Confirm Code Owner approval is in place per `.github/CODEOWNERS`.",
              "4. For `critical` PRs, verify ADRs / specs / runbooks are updated in this same PR.",
              ""]
    if files:
        preview = files[:30]
        lines += ["<details><summary>Changed files</summary>", ""]
        for f in preview:
            lines.append(f"- `{f}`")
        if len(files) > len(preview):
            lines.append(f"- … and {len(files) - len(preview)} more")
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def main() -> int:
    files = common.get_changed_files()
    policy = common.load_policy()
    rules = common.applicable_rules(files, policy)
    risk_level = common.aggregate_risk_level(rules)
    required_agents = common.required_agents_for(files, policy)
    reviewers = common.recommended_reviewers_for(files, policy)
    needs_tests = common.requires_tests(files, policy)
    has_tests = common.has_test_changes(files)
    has_docs = common.has_doc_changes(files)
    has_migrations = common.has_migration_changes(files)

    domain_set: list[str] = []
    seen: set[str] = set()
    for f in files:
        d = classify_domain(f)
        if d not in seen and d != "other":
            seen.add(d)
            domain_set.append(d)

    reasons = build_reasons(files, rules)

    md = render_markdown(
        files=files,
        rules=rules,
        risk_level=risk_level,
        domains=domain_set,
        required_agents=required_agents,
        reviewers=reviewers,
        requires_tests=needs_tests,
        has_tests=has_tests,
        has_docs=has_docs,
        has_migrations=has_migrations,
        reasons=reasons,
    )

    payload = {
        "risk_level": risk_level,
        "files_changed": len(files),
        "files": files,
        "domains": domain_set,
        "required_agents": required_agents,
        "recommended_reviewers": reviewers,
        "requires_tests": needs_tests,
        "has_tests": has_tests,
        "has_docs": has_docs,
        "has_migrations": has_migrations,
        "reasons": reasons,
        "applicable_rules": [r.get("name") for r in rules],
    }

    out_dir = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    (out_dir / "triage_result.md").write_text(md, encoding="utf-8")
    (out_dir / "triage_result.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(md)
        except OSError as e:
            print(f"[pr_triage] could not write step summary: {e}", file=sys.stderr)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        try:
            with open(output_path, "a", encoding="utf-8") as fh:
                fh.write(f"risk_level={risk_level}\n")
                fh.write(f"required_agents={','.join(required_agents)}\n")
                fh.write(f"files_changed={len(files)}\n")
        except OSError as e:
            print(f"[pr_triage] could not write GITHUB_OUTPUT: {e}", file=sys.stderr)

    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
