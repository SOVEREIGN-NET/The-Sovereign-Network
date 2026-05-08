#!/usr/bin/env python3
"""
Documentation review agent.

Rules:
- MAJOR if architecture/protocol/tokenomics/compliance/governance behavior
  changes without any docs updates (docs/, *.md, ADR-*, README*).
- MINOR if a README or runbook in a touched module looks stale (code in a
  directory changed and a README/RUNBOOK exists in that directory but was
  not updated in this PR).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

# Domain prefixes whose behavior changes are expected to be reflected in docs.
BEHAVIOR_DOMAIN_PREFIXES: tuple[str, ...] = (
    "contracts/",
    "smart-contracts/",
    "chain/",
    "blockchain/",
    "tokenomics/",
    "treasury/",
    "identity/",
    "zk/",
    "governance/",
    "dao/",
    "protocol/",
)

DOC_FILE_PATTERNS = [
    "docs/**",
    "**/*.md",
    "**/ADR-*",
    "**/adr-*",
    "**/README*",
    "**/CHANGELOG*",
    "**/CHANGES*",
]

STALE_DOC_NAMES = ("README.md", "README", "RUNBOOK.md", "RUNBOOK", "ARCHITECTURE.md")


def _module_dir(path: str) -> str:
    """Return the immediate parent directory of a path (or '' for root files)."""
    if "/" not in path:
        return ""
    return path.rsplit("/", 1)[0]


def _existing_doc_in_dir(repo_root: Path, directory: str) -> str | None:
    """If a stale-doc-candidate file exists in `directory`, return its repo path."""
    base = repo_root / directory if directory else repo_root
    if not base.is_dir():
        return None
    for name in STALE_DOC_NAMES:
        if (base / name).is_file():
            return f"{directory}/{name}" if directory else name
    return None


def main() -> int:
    changed = common.get_changed_files()
    result = common.AgentResult(
        agent="documentation",
        status=common.Status.PASS,
        risk_level="medium",
    )

    if not changed:
        result.applicable = False
        result.summary = "No changed files; documentation review not applicable."
        common.emit_result(result, changed)
        return common.exit_for_status(result)

    behavior_changes = [
        f for f in changed
        if f.startswith(BEHAVIOR_DOMAIN_PREFIXES)
    ]
    doc_changes = [f for f in changed if common.match_any(f, DOC_FILE_PATTERNS)]

    if not behavior_changes and not doc_changes:
        # No domain we care about and no docs touched — nothing to assert.
        result.applicable = False
        result.summary = "No behavior-domain or documentation changes detected."
        common.emit_result(result, changed)
        return common.exit_for_status(result)

    result.applicable = True

    # --- Rule 1: behavior change with zero documentation updates -> MAJOR ---
    if behavior_changes and not doc_changes:
        domains_touched = sorted({
            p.split("/", 1)[0] for p in behavior_changes if "/" in p
        })
        domains_str = ", ".join(domains_touched) if domains_touched else "core"
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Behavior change without documentation update",
            description=(
                f"Changes were detected in domains that affect protocol behavior "
                f"({domains_str}), but no documentation files were updated in this "
                f"PR (no docs/**, *.md, ADR-*, or README* updates). Material "
                f"changes to architecture, protocol, tokenomics, compliance, or "
                f"governance must be reflected in documentation so reviewers and "
                f"future maintainers can understand the new behavior."
            ),
            recommendation=(
                "Update the relevant documentation: add or revise an ADR under "
                "docs/, update the module README, or extend protocol/tokenomics/"
                "governance docs to describe the change. If this PR truly has no "
                "behavior impact (e.g., pure refactor), say so explicitly in the "
                "PR description."
            ),
        ))
        result.risk_level = "high"

    # --- Rule 2: stale README/RUNBOOK in a touched module -> MINOR ---
    repo_root = Path.cwd()
    touched_dirs = sorted({_module_dir(p) for p in changed})
    doc_changes_set = set(doc_changes)

    stale_candidates: list[tuple[str, str]] = []  # (touched_dir, doc_path)
    for d in touched_dirs:
        # Skip directories that are themselves under docs/ (they're docs already).
        if d.startswith("docs/") or d == "docs":
            continue
        doc_path = _existing_doc_in_dir(repo_root, d)
        if doc_path and doc_path not in doc_changes_set:
            stale_candidates.append((d, doc_path))

    # Cap at 5 to limit noise.
    for touched_dir, doc_path in stale_candidates[:5]:
        result.add(common.Finding(
            severity=common.Severity.MINOR,
            title="Possibly stale documentation alongside code change",
            file=doc_path,
            description=(
                f"Code under '{touched_dir or '<root>'}' changed in this PR, but "
                f"the local '{doc_path}' was not updated. If the change affects "
                f"behavior, configuration, or operational steps documented there, "
                f"this README/runbook may now be stale."
            ),
            recommendation=(
                f"Review '{doc_path}' against the changes in this PR. If it is "
                f"still accurate, no action is needed. Otherwise update it as "
                f"part of this PR rather than leaving it for later."
            ),
        ))

    if len(stale_candidates) > 5:
        result.add(common.Finding(
            severity=common.Severity.INFO,
            title="Additional possibly-stale docs not listed",
            description=(
                f"{len(stale_candidates) - 5} additional README/runbook files in "
                f"touched directories were not updated; only the first 5 are "
                f"listed individually to limit noise."
            ),
            recommendation=(
                "Spot-check the remaining module docs for accuracy."
            ),
        ))

    if not result.findings:
        result.summary = (
            "Documentation review passed: behavior-domain changes are accompanied "
            "by documentation updates, and no obviously-stale module docs were "
            "detected."
        )
    else:
        result.summary = (
            f"Documentation review produced {len(result.findings)} finding(s). "
            f"See details above."
        )

    common.emit_result(result, changed)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
