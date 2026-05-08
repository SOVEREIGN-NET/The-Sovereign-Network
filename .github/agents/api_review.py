#!/usr/bin/env python3
"""
API review agent.

Rules:
- MAJOR if public API/schema changes without versioning or docs.
- MAJOR if error responses leak internals (stack traces, SQL errors, paths).
- MINOR if API docs are not updated.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

API_PATTERNS = [
    "api/**", "sdk/**",
    "**/openapi*.yaml", "**/openapi*.yml", "**/openapi*.json",
    "**/*.proto",
    "**/schema.graphql", "**/*.graphql",
]

VERSION_HINTS = re.compile(
    r"(?:^|/)v[0-9]+(?:[._-]?[0-9]+)?(?:/|$)|"
    r"\bversion\s*[:=]\s*[\"']?\d+\.\d+",
    re.IGNORECASE,
)

DOC_PATTERNS = [
    "docs/api/**", "docs/**/api*.md",
    "**/CHANGELOG*", "**/CHANGES*",
    "**/openapi*.yaml", "**/openapi*.yml", "**/openapi*.json",
]

INTERNAL_LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Stack trace returned in response",
        re.compile(r"\b(?:traceback|stack[_ ]?trace|stackTrace)\b.*\b(?:return|res(?:ponse)?\.|json\(|jsonify\()", re.IGNORECASE),
    ),
    (
        "Raw exception serialized to client",
        re.compile(r"(?:return|res(?:ponse)?\.send|res\.json)\s*\([^)]*\b(?:str|repr)\s*\(\s*(?:e|err|exc|exception)\s*\)"),
    ),
    (
        "Internal path leaked in error",
        re.compile(r"(?:return|raise|throw)[^;\n]*['\"](?:/(?:home|root|var|etc|usr)|C:\\\\)[^'\"\n]*['\"]"),
    ),
    (
        "SQL error string returned",
        re.compile(r"(?:return|jsonify|json\()\s*\([^)]*(?:psycopg|MySQLdb|sqlite3|SQLAlchemy)Error", re.IGNORECASE),
    ),
]


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="api",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, API_PATTERNS)
    if not relevant:
        result.applicable = False
        result.summary = "No API/SDK files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    result.risk_level = "high"

    # Versioning check: at least one of the touched API files (or its dir)
    # carries a version marker. We also accept a CHANGELOG update.
    has_version_marker = False
    for f in relevant:
        if VERSION_HINTS.search(f):
            has_version_marker = True
            break
        text = common.read_file_safe(f) or ""
        if VERSION_HINTS.search(text):
            has_version_marker = True
            break

    has_docs_update = bool(common.filter_files(files, DOC_PATTERNS))

    if not has_version_marker and not has_docs_update:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Public API change without versioning or docs update",
            description=(
                f"{len(relevant)} API/SDK file(s) changed but no version "
                "marker (e.g. `/v1/`, `version: 1.x`) is visible AND no "
                "docs/CHANGELOG/openapi spec was updated."
            ),
            recommendation=(
                "Either bump the API version, update `docs/api/`, or update "
                "the OpenAPI/proto spec to reflect the change. Breaking "
                "changes require a new version path."
            ),
            file=relevant[0],
        ))
    elif not has_docs_update:
        result.add(common.Finding(
            severity=common.Severity.MINOR,
            title="API change without docs update",
            description=(
                "API/SDK files were modified but no docs file under "
                "`docs/api/`, no CHANGELOG, and no OpenAPI/proto spec was "
                "updated."
            ),
            recommendation=(
                "Update the corresponding docs so consumers learn about the "
                "change at the same time as it ships."
            ),
            file=relevant[0],
        ))

    # Internal-leak scan across handler-ish files
    handler_files = [f for f in relevant if f.endswith((".py", ".ts", ".js", ".go", ".rs", ".java", ".kt"))]
    for f in handler_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        for label, pat in INTERNAL_LEAK_PATTERNS:
            m = pat.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                result.add(common.Finding(
                    severity=common.Severity.MAJOR,
                    title=f"API error response may leak internals: {label}",
                    description=(
                        "Detected a pattern that returns stack traces, raw "
                        "exception strings, internal filesystem paths, or "
                        "raw SQL errors in an HTTP response. This leaks "
                        "implementation details to attackers."
                    ),
                    recommendation=(
                        "Return generic, structured errors (`{ code, "
                        "message }`) and log full details server-side only. "
                        "Map known exceptions to safe error codes."
                    ),
                    file=f,
                    line=line,
                ))

    if not result.findings:
        result.summary = (
            f"{len(relevant)} API/SDK file(s) inspected; versioning and docs "
            "appear in order."
        )
    else:
        result.summary = (
            f"{len(relevant)} API/SDK file(s) inspected; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
