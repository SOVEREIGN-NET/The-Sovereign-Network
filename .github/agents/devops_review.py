#!/usr/bin/env python3
"""
DevOps review agent.

Rules:
- BLOCKER if production deployment config changes without rollback notes.
- BLOCKER if secrets are printed or exposed in shell/CI output.
- MAJOR if observability/alerting is missing for a production-impacting change.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

PROD_INFRA_PATTERNS = [
    "infra/prod/**", "infra/production/**",
    "infra/**/prod/**", "infra/**/production/**",
    "**/k8s/prod/**", "**/kubernetes/prod/**",
    "**/terraform/prod/**", "**/helm/**/prod/**",
    "**/values.prod.yaml", "**/values-prod.yaml",
    "**/values.production.yaml",
]

NONPROD_INFRA_PATTERNS = [
    "infra/**", "**/k8s/**", "**/terraform/**", "**/helm/**",
    "**/Dockerfile*", "**/docker-compose*.yml",
    ".github/workflows/**",
]

ROLLBACK_DOC_HINTS = [
    "rollback", "revert", "fallback",
]

# Patterns that indicate secret exposure in shell/CI
SECRET_EXPOSURE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Secret echoed to stdout",
        re.compile(r"\b(?:echo|printf)\s+[^|;\n]*\$\{?\s*(?:SECRET|TOKEN|PASSWORD|API_KEY|KEY|CREDENTIAL)[A-Z_0-9]*\}?", re.IGNORECASE),
        "BLOCKER",
    ),
    (
        "GITHUB_TOKEN echoed",
        re.compile(r"\becho\s+[^|;\n]*\$\{?\s*GITHUB_TOKEN\}?"),
        "BLOCKER",
    ),
    (
        "set -x with sensitive env",
        re.compile(r"^\s*set\s+-x\s*$.*?(?:SECRET|TOKEN|PASSWORD|API_KEY)", re.IGNORECASE | re.DOTALL | re.MULTILINE),
        "MAJOR",
    ),
    (
        "::set-output with secret",
        re.compile(r"::set-output[^\n]*::[^\n]*\$\{?\s*(?:SECRET|TOKEN|PASSWORD|API_KEY)", re.IGNORECASE),
        "BLOCKER",
    ),
]

OBSERVABILITY_HINTS = [
    r"\bprometheus\b", r"\bmetrics?\b", r"\balert(?:ing|manager)?\b",
    r"\bgrafana\b", r"\bdatadog\b", r"\bsentry\b",
    r"\bopentelemetry\b", r"\botel\b",
    r"\bservicemonitor\b", r"\bPrometheusRule\b",
    r"\blog(?:ging)?\b", r"\btrace\b", r"\bspan\b",
]


def has_rollback_notes(files: list[str]) -> bool:
    # 1) any docs file mentioning rollback
    doc_files = common.filter_files(files, ["docs/**", "**/*.md"])
    for f in doc_files:
        text = (common.read_file_safe(f) or "").lower()
        if any(hint in text for hint in ROLLBACK_DOC_HINTS):
            return True
    # 2) RUNBOOK or ROLLBACK files
    if common.filter_files(files, ["**/RUNBOOK*", "**/ROLLBACK*", "**/runbook*.md"]):
        return True
    return False


def has_observability(files: list[str]) -> bool:
    obs_pat = re.compile("|".join(OBSERVABILITY_HINTS), re.IGNORECASE)
    for f in common.filter_files(files, NONPROD_INFRA_PATTERNS):
        text = common.read_file_safe(f) or ""
        if obs_pat.search(text):
            return True
    return False


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="devops",
        status=common.Status.PASS,
        risk_level="medium",
    )

    if not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    prod_files = common.filter_files(files, PROD_INFRA_PATTERNS)
    nonprod_files = common.filter_files(files, NONPROD_INFRA_PATTERNS)

    if not prod_files and not nonprod_files:
        result.applicable = False
        result.summary = "No infra/CI files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    if prod_files:
        result.risk_level = "critical"
        if not has_rollback_notes(files):
            result.add(common.Finding(
                severity=common.Severity.BLOCKER,
                title="Production deploy config changed without rollback notes",
                description=(
                    f"{len(prod_files)} production infra file(s) changed but "
                    "no rollback / revert / fallback note is present in any "
                    "doc, runbook, or RUNBOOK/ROLLBACK file in this PR."
                ),
                recommendation=(
                    "Add a `RUNBOOK.md` (or update `docs/runbooks/`) with "
                    "explicit rollback steps, blast radius, and verification "
                    "commands."
                ),
                file=prod_files[0],
            ))
        if not has_observability(files):
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="Production change without observability/alerting hooks",
                description=(
                    "Production infra was modified but no metrics, alerts, "
                    "logging, or tracing references appear in the touched "
                    "files."
                ),
                recommendation=(
                    "Wire up Prometheus rules, alerts, logs, or traces to "
                    "this change so production behavior is observable."
                ),
                file=prod_files[0],
            ))

    # Secret exposure scan across infra + CI text files
    scan_files = list(set(nonprod_files + prod_files + common.filter_files(files, [
        "**/*.sh", "**/*.bash", "**/*.zsh", "**/Makefile*",
        "**/*.yaml", "**/*.yml",
    ])))
    for f in scan_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        for title, pat, sev in SECRET_EXPOSURE_PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                result.add(common.Finding(
                    severity=common.Severity(sev),
                    title=title,
                    description=(
                        "A pattern that exposes a secret to stdout/CI logs "
                        "was detected. CI logs are durable and often visible "
                        "to forks."
                    ),
                    recommendation=(
                        "Never echo secret env vars. Use GitHub Actions' "
                        "`::add-mask::` for runtime values, and load secrets "
                        "via `${{ secrets.* }}` only inside steps that need "
                        "them."
                    ),
                    file=f,
                    line=line,
                ))

    if not result.findings:
        result.summary = (
            f"{len(prod_files)} prod and {len(nonprod_files) - len(prod_files)} "
            "non-prod infra/CI file(s) inspected; no DevOps issues detected."
        )
    else:
        result.summary = (
            f"{len(result.findings)} DevOps concern(s) raised across "
            f"{len(prod_files) + len(nonprod_files)} infra/CI file(s)."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
