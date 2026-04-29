"""
Common helpers shared across PR triage and review agents.

This module is intentionally dependency-free (stdlib only) so the agents
can run in a minimal CI image without `pip install`. It provides:

- get_changed_files()      : list of paths changed vs. base ref
- read_file_safe()         : tolerant file reader (None on miss / decode error)
- match_any()              : glob-pattern matcher over a list
- load_policy()            : minimal YAML loader for review-policy.yml
- Severity / Status enums  : ordered severity levels
- Finding / AgentResult    : data containers
- emit_result()            : write JSON + GITHUB_STEP_SUMMARY markdown
- exit_for_status()        : convert AgentResult.status into a process exit code

Python 3.11+. No external deps.
"""

from __future__ import annotations

import dataclasses
import enum
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
POLICY_PATH = REPO_ROOT / ".github" / "review-policy.yml"


# --------------------------------------------------------------------------- #
# Severity / Status
# --------------------------------------------------------------------------- #


class Severity(str, enum.Enum):
    INFO = "INFO"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    BLOCKER = "BLOCKER"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "MINOR": 1, "MAJOR": 2, "BLOCKER": 3}[self.value]


class Status(str, enum.Enum):
    PASS = "PASS"
    INFO = "INFO"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    BLOCKER = "BLOCKER"

    @property
    def rank(self) -> int:
        return {"PASS": 0, "INFO": 1, "MINOR": 2, "MAJOR": 3, "BLOCKER": 4}[self.value]


# --------------------------------------------------------------------------- #
# Data containers
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    recommendation: str
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclasses.dataclass
class AgentResult:
    agent: str
    status: Status
    risk_level: str
    findings: list[Finding] = dataclasses.field(default_factory=list)
    summary: str = ""
    applicable: bool = True

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        # Bump status to match worst finding
        if finding.severity.rank + 1 > self.status.rank:
            self.status = Status(finding.severity.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "status": self.status.value,
            "risk_level": self.risk_level,
            "applicable": self.applicable,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Git / changed-files detection
# --------------------------------------------------------------------------- #


def _run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    return proc.returncode, proc.stdout, proc.stderr


def _resolve_base_ref() -> str | None:
    """
    Determine the base ref to diff against.

    Order of preference:
      1. PR_BASE_SHA env var (set by workflow)
      2. GITHUB_BASE_REF env var (pull_request events)
      3. origin/main, origin/master fallbacks
    """
    base_sha = os.environ.get("PR_BASE_SHA")
    if base_sha:
        return base_sha

    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        # Make sure we have it locally
        rc, _, _ = _run(["git", "rev-parse", "--verify", f"origin/{base_ref}"])
        if rc == 0:
            return f"origin/{base_ref}"
        rc, _, _ = _run(["git", "rev-parse", "--verify", base_ref])
        if rc == 0:
            return base_ref

    for candidate in ("origin/main", "origin/master", "main", "master"):
        rc, _, _ = _run(["git", "rev-parse", "--verify", candidate])
        if rc == 0:
            return candidate

    return None


def get_changed_files() -> list[str]:
    """
    Return repo-relative paths changed vs. the base ref.

    Falls back to an empty list (rather than raising) so agents can run
    locally without a configured base. Use FORCE_CHANGED_FILES env var
    (newline- or comma-separated) to override for local testing.
    """
    forced = os.environ.get("FORCE_CHANGED_FILES")
    if forced:
        sep = "\n" if "\n" in forced else ","
        return [p.strip() for p in forced.split(sep) if p.strip()]

    base = _resolve_base_ref()
    if not base:
        # Last-ditch: list everything tracked. Useful for first-PR scenarios.
        rc, out, _ = _run(["git", "ls-files"])
        if rc == 0:
            return [line for line in out.splitlines() if line.strip()]
        return []

    rc, out, err = _run(["git", "diff", "--name-only", f"{base}...HEAD"])
    if rc != 0:
        # Try non-three-dot diff
        rc, out, err = _run(["git", "diff", "--name-only", base, "HEAD"])
    if rc != 0:
        print(f"[common] git diff failed: {err}", file=sys.stderr)
        return []

    return [line for line in out.splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# File / pattern helpers
# --------------------------------------------------------------------------- #


def read_file_safe(path: str | Path, max_bytes: int = 2_000_000) -> str | None:
    """Return file contents as text, or None on miss/decode error/oversize."""
    p = (REPO_ROOT / path) if not Path(path).is_absolute() else Path(path)
    try:
        if not p.is_file():
            return None
        if p.stat().st_size > max_bytes:
            with p.open("rb") as fh:
                return fh.read(max_bytes).decode("utf-8", errors="replace")
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def match_any(path: str, patterns: Iterable[str]) -> bool:
    """True if `path` matches any glob pattern."""
    norm = path.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(norm, pat):
            return True
        # Allow bare-prefix conveniences like "contracts/" matching "contracts/x"
        if pat.endswith("/") and norm.startswith(pat):
            return True
    return False


def filter_files(files: Iterable[str], patterns: Iterable[str]) -> list[str]:
    return [f for f in files if match_any(f, patterns)]


# --------------------------------------------------------------------------- #
# Minimal YAML loader for review-policy.yml
#
# We avoid a PyYAML dependency. The policy file is intentionally written
# in a restricted YAML subset: mappings, sequences, strings, integers,
# booleans, comments, and `-` list items. This loader covers that subset.
# --------------------------------------------------------------------------- #


def _yaml_scalar(s: str) -> Any:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    if s in ("null", "~", ""):
        return None
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


def _parse_yaml(text: str) -> Any:
    """Tiny indentation-based YAML parser for the policy subset."""
    # Strip comments and blank lines but preserve indentation.
    raw_lines: list[tuple[int, str]] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        raw_lines.append((indent, stripped.lstrip(" ")))

    pos = 0

    def parse_block(indent: int) -> Any:
        nonlocal pos
        # Decide whether this block is a list or mapping.
        if pos >= len(raw_lines):
            return None
        cur_indent, cur = raw_lines[pos]
        if cur_indent < indent:
            return None
        if cur.startswith("- "):
            return parse_list(indent)
        return parse_map(indent)

    def parse_list(indent: int) -> list[Any]:
        nonlocal pos
        out: list[Any] = []
        while pos < len(raw_lines):
            cur_indent, cur = raw_lines[pos]
            if cur_indent < indent or not cur.startswith("- "):
                break
            item_text = cur[2:].strip()
            pos += 1
            if ":" in item_text and not item_text.endswith(":"):
                # Inline mapping start: "- key: value" — treat as a one-key mapping
                # whose siblings live at indent + 2.
                key, _, val = item_text.partition(":")
                key = key.strip()
                val = val.strip()
                node: dict[str, Any] = {key: _yaml_scalar(val) if val else None}
                # Continue collecting children for this mapping at indent+2.
                child_indent = indent + 2
                while pos < len(raw_lines):
                    ni, _ = raw_lines[pos]
                    if ni < child_indent:
                        break
                    sub = parse_map(child_indent)
                    if isinstance(sub, dict):
                        node.update(sub)
                    else:
                        break
                if val == "":
                    # The mapping's first value was empty → child block holds it.
                    val_block = node[key]
                    if val_block is None and key in node:
                        # Already filled by parse_map merge; nothing to do.
                        pass
                out.append(node)
            elif item_text.endswith(":"):
                # "- key:" with mapping below
                key = item_text[:-1].strip()
                child_indent = indent + 2
                node = {key: parse_block(child_indent)}
                # Pick up siblings at indent+2 (more keys of same mapping)
                while pos < len(raw_lines):
                    ni, _ = raw_lines[pos]
                    if ni < child_indent:
                        break
                    sub = parse_map(child_indent)
                    if isinstance(sub, dict):
                        node.update(sub)
                    else:
                        break
                out.append(node)
            else:
                # Bare scalar list item
                out.append(_yaml_scalar(item_text))
        return out

    def parse_map(indent: int) -> dict[str, Any]:
        nonlocal pos
        out: dict[str, Any] = {}
        while pos < len(raw_lines):
            cur_indent, cur = raw_lines[pos]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                # Shouldn't happen at this level — skip defensively.
                pos += 1
                continue
            if cur.startswith("- "):
                break
            if ":" not in cur:
                pos += 1
                continue
            key, _, val = cur.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val == "":
                # Child block follows
                child_indent = indent + 2
                # Detect the actual child indent (could be deeper)
                if pos < len(raw_lines):
                    child_indent = max(child_indent, raw_lines[pos][0])
                if pos < len(raw_lines) and raw_lines[pos][0] > indent:
                    out[key] = parse_block(raw_lines[pos][0])
                else:
                    out[key] = None
            else:
                out[key] = _yaml_scalar(val)
        return out

    if not raw_lines:
        return {}
    first_indent = raw_lines[0][0]
    return parse_block(first_indent)


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load .github/review-policy.yml. Returns {} if missing or unparseable."""
    p = path or POLICY_PATH
    txt = read_file_safe(p)
    if txt is None:
        return {}
    try:
        data = _parse_yaml(txt)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as e:  # noqa: BLE001 — parser is intentionally tolerant
        print(f"[common] policy parse failed: {e}", file=sys.stderr)
        return {}


def applicable_rules(files: list[str], policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return policy rules whose `match` patterns hit any changed file."""
    rules = policy.get("rules") or []
    hits: list[dict[str, Any]] = []
    for rule in rules:
        patterns = rule.get("match") or []
        if not patterns:
            continue
        if any(match_any(f, patterns) for f in files):
            hits.append(rule)
    return hits


def aggregate_risk_level(rules: list[dict[str, Any]], default: str = "low") -> str:
    """Take the highest risk level across applicable rules."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best = default
    for r in rules:
        rl = (r.get("risk_level") or "low").lower()
        if order.get(rl, 0) > order.get(best, 0):
            best = rl
    return best


def required_agents_for(files: list[str], policy: dict[str, Any]) -> list[str]:
    rules = applicable_rules(files, policy)
    union: list[str] = []
    seen: set[str] = set()
    if not rules:
        defaults = (policy.get("defaults") or {}).get("required_agents") or []
        for a in defaults:
            if a not in seen:
                seen.add(a)
                union.append(a)
        return union
    for r in rules:
        for a in r.get("required_agents") or []:
            if a not in seen:
                seen.add(a)
                union.append(a)
    return union


def recommended_reviewers_for(files: list[str], policy: dict[str, Any]) -> list[str]:
    rules = applicable_rules(files, policy)
    union: list[str] = []
    seen: set[str] = set()
    if not rules:
        defaults = (policy.get("defaults") or {}).get("recommended_reviewers") or []
        for r in defaults:
            if r not in seen:
                seen.add(r)
                union.append(r)
        return union
    for r in rules:
        for rv in r.get("recommended_reviewers") or []:
            if rv not in seen:
                seen.add(rv)
                union.append(rv)
    return union


def requires_tests(files: list[str], policy: dict[str, Any]) -> bool:
    for r in applicable_rules(files, policy):
        if r.get("requires_tests"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Result emission
# --------------------------------------------------------------------------- #


def _result_to_markdown(result: AgentResult, files: list[str]) -> str:
    if not result.applicable:
        return (
            f"### ✅ {result.agent} — not applicable\n\n"
            f"_No changed files fall under this agent's scope._\n"
        )
    icon = {
        "PASS": "✅",
        "INFO": "ℹ️",
        "MINOR": "🟡",
        "MAJOR": "🟠",
        "BLOCKER": "🔴",
    }.get(result.status.value, "•")

    lines = [
        f"### {icon} {result.agent} — {result.status.value}",
        f"**Risk:** `{result.risk_level}`  |  **Findings:** {len(result.findings)}",
        "",
    ]
    if result.summary:
        lines += [result.summary, ""]
    if result.findings:
        lines.append("| Severity | Title | File |")
        lines.append("| --- | --- | --- |")
        for f in result.findings:
            file_disp = f"`{f.file}`" if f.file else "—"
            title = f.title.replace("|", "\\|")
            lines.append(f"| **{f.severity.value}** | {title} | {file_disp} |")
        lines.append("")
        for i, f in enumerate(result.findings, 1):
            lines.append(f"#### {i}. {f.severity.value}: {f.title}")
            if f.file:
                loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
                lines.append(f"_Location:_ {loc}")
            lines.append("")
            lines.append(f.description)
            lines.append("")
            lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append("")
    else:
        lines.append("_No findings._")
        lines.append("")

    if files:
        preview = files[:25]
        lines.append("<details><summary>Changed files inspected</summary>\n")
        for f in preview:
            lines.append(f"- `{f}`")
        if len(files) > len(preview):
            lines.append(f"- … and {len(files) - len(preview)} more")
        lines.append("\n</details>")

    return "\n".join(lines) + "\n"


def emit_result(result: AgentResult, files: list[str]) -> None:
    """Print JSON to stdout, append markdown to GITHUB_STEP_SUMMARY (if set)."""
    print(json.dumps(result.to_dict(), indent=2))
    md = _result_to_markdown(result, files)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(md)
        except OSError as e:
            print(f"[common] could not write step summary: {e}", file=sys.stderr)
    else:
        # Local run — print readable markdown too.
        print("\n" + md, file=sys.stderr)


def exit_for_status(result: AgentResult) -> int:
    """
    Return process exit code from result.
      - BLOCKER or MAJOR  -> 1 (fail the job)
      - PASS / INFO / MINOR -> 0
      - non-applicable     -> 0
    """
    if not result.applicable:
        return 0
    if result.status in (Status.BLOCKER, Status.MAJOR):
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Convenience text scanners used by multiple agents
# --------------------------------------------------------------------------- #


def file_added(path: str) -> bool:
    """Best-effort check that a file was newly added in this PR."""
    base = _resolve_base_ref()
    if not base:
        return False
    rc, out, _ = _run(["git", "diff", "--name-status", f"{base}...HEAD"])
    if rc != 0:
        return False
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].startswith("A") and parts[-1] == path:
            return True
    return False


def diff_for_file(path: str) -> str:
    """Return the unified diff for one file, or '' on failure."""
    base = _resolve_base_ref()
    if not base:
        return ""
    rc, out, _ = _run(["git", "diff", f"{base}...HEAD", "--", path])
    if rc != 0:
        return ""
    return out


def has_test_changes(files: list[str]) -> bool:
    test_patterns = [
        "**/tests/**",
        "**/test_*.py",
        "**/*_test.go",
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.test.js",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "**/*.spec.js",
        "**/*.t.sol",
        "**/test/**",
    ]
    return any(match_any(f, test_patterns) for f in files)


def has_doc_changes(files: list[str]) -> bool:
    return any(match_any(f, ["docs/**", "**/*.md", "README*", "**/ADR-*", "**/adr/**"]) for f in files)


def has_migration_changes(files: list[str]) -> bool:
    return any(match_any(f, ["migrations/**", "**/migrations/**", "**/*.migration.sql"]) for f in files)
