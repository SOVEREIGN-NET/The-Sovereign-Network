#!/usr/bin/env python3
"""
Architecture review agent.

Rules:
- BLOCKER if critical files changed without an ADR/docs update.
- MAJOR if a new top-level service/module is added with no owner or
  documented boundary.
- MAJOR if infra, chain, identity, and tokenomics directories appear
  coupled in the same change without an explanation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CRITICAL_PATTERNS = [
    "contracts/**",
    "smart-contracts/**",
    "**/*.sol",
    "chain/**",
    "blockchain/**",
    "consensus/**",
    "tokenomics/**",
    "treasury/**",
    "identity/**",
    "zk/**",
    "governance/**",
    "dao/**",
    "infra/prod/**",
    "infra/production/**",
    "migrations/**",
]

ADR_PATTERNS = [
    "docs/adr/**",
    "docs/architecture/**",
    "docs/specs/**",
    "ADR-*",
    "**/ADR-*",
    "**/*adr*.md",
    "docs/**/architecture*.md",
    "docs/**/spec*.md",
]

CODEOWNERS_FILE = ".github/CODEOWNERS"

DOMAIN_PREFIXES = {
    "chain": ("chain/", "blockchain/", "consensus/", "node/"),
    "identity": ("identity/", "zk/"),
    "tokenomics": ("tokenomics/", "treasury/"),
    "infra": ("infra/",),
    "governance": ("governance/", "dao/"),
}


def detect_new_top_level_modules(files: list[str]) -> list[str]:
    """Return added directories that look like new top-level services."""
    candidates: set[str] = set()
    for f in files:
        if not common.file_added(f):
            continue
        parts = f.replace("\\", "/").split("/")
        if len(parts) >= 2 and parts[0] not in {"docs", ".github", "tests", "test"}:
            candidates.add(parts[0])
    # Only flag top-level directories whose creation is part of this PR
    # (heuristic: at least one file inside is newly added). The Path test
    # below is best-effort — codeowners check is what really catches it.
    return sorted(candidates)


def has_codeowner_entry(module: str, codeowners_text: str) -> bool:
    needle = f"/{module}/"
    return any(needle in line for line in codeowners_text.splitlines() if not line.lstrip().startswith("#"))


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="architecture",
        status=common.Status.PASS,
        risk_level="low",
    )

    critical_hits = common.filter_files(files, CRITICAL_PATTERNS)
    if not critical_hits and not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    if critical_hits:
        result.risk_level = "critical"
        adr_hits = common.filter_files(files, ADR_PATTERNS)
        if not adr_hits:
            result.add(common.Finding(
                severity=common.Severity.BLOCKER,
                title="Critical change without ADR/spec/docs update",
                description=(
                    "Files in critical paths (smart contracts, chain, identity, "
                    "tokenomics, governance, production infra, or migrations) "
                    "were modified but no ADR, spec, or architecture document "
                    "was updated in this PR."
                ),
                recommendation=(
                    "Add or update an ADR under `docs/adr/`, a spec under "
                    "`docs/specs/`, or another architecture document describing "
                    "the rationale, alternatives considered, and impact."
                ),
                file=critical_hits[0],
            ))

    # Coupling check: more than two distinct critical domains in one PR.
    touched_domains: list[str] = []
    for domain, prefixes in DOMAIN_PREFIXES.items():
        if any(f.startswith(prefixes) for f in files):
            touched_domains.append(domain)
    if len(touched_domains) >= 3:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title=f"PR couples {len(touched_domains)} critical domains: {', '.join(touched_domains)}",
            description=(
                "A single PR is touching multiple critical subsystems at once. "
                "This makes review and rollback difficult and increases blast "
                "radius."
            ),
            recommendation=(
                "Split this PR into one PR per subsystem, or document the "
                "cross-cutting rationale in an ADR included in this PR."
            ),
        ))

    # New module without owner check
    codeowners_text = common.read_file_safe(CODEOWNERS_FILE) or ""
    new_modules = detect_new_top_level_modules(files)
    for mod in new_modules:
        if mod in {"docs", ".github", "tests", "test", "scripts"}:
            continue
        if not has_codeowner_entry(mod, codeowners_text):
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title=f"New top-level module `{mod}/` has no CODEOWNERS entry",
                description=(
                    f"This PR adds files under a new top-level path `{mod}/` "
                    "but no ownership rule is declared in `.github/CODEOWNERS`."
                ),
                recommendation=(
                    f"Add a line to `.github/CODEOWNERS` mapping `/{mod}/` to "
                    "the responsible team, and document the module's boundary "
                    "in a README or ADR."
                ),
                file=f"{mod}/",
            ))

    if not result.findings:
        result.summary = (
            f"No architecture concerns detected across {len(files)} changed file(s)."
        )
    else:
        result.summary = f"Inspected {len(files)} changed file(s)."

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
