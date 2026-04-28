#!/usr/bin/env python3
"""
Performance review agent.

Rules:
- MAJOR if loops over unbounded state are introduced in chain/contract/API
  code.
- MAJOR if large files / unbounded on-chain storage patterns are introduced.
- MINOR if no benchmark exists for a performance-sensitive change.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

PERF_SENSITIVE_PATTERNS = [
    "contracts/**", "smart-contracts/**", "**/*.sol",
    "chain/**", "blockchain/**", "consensus/**", "node/**",
    "api/**", "sdk/**",
]

# Solidity unbounded loop heuristics
SOL_UNBOUNDED_LOOP_RE = re.compile(
    r"for\s*\(\s*[^;]*;\s*[^;]*<\s*(?:[a-zA-Z_][\w.]*\.length|[a-zA-Z_][\w.]*\.size\(\))\s*;",
)
SOL_DYNAMIC_PUSH_RE = re.compile(r"\.push\s*\(")
SOL_STATE_ARRAY_RE = re.compile(r"^\s*[a-zA-Z_]\w*\s*\[\]\s+(?:public|private|internal)?\s+\w+\s*;", re.MULTILINE)

# Generic loop-over-collection without explicit bound
GENERIC_UNBOUNDED_LOOP_PATTERNS = [
    re.compile(r"for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length\s*;"),  # JS/Java/Go-ish
    re.compile(r"for\s+\w+\s+in\s+\w+\s*:"),  # Python for-in
    re.compile(r"\.forEach\s*\(\s*"),
    re.compile(r"\.map\s*\(\s*"),
]

LARGE_STORAGE_HINTS = [
    r"\bbytes\s+(?:public|private|internal)?\s*\w+\s*;",  # raw bytes state
    r"\bmapping\s*\(\s*\w+\s*=>\s*\w+\[\]\s*\)",  # mapping to dynamic arrays
    r"\bnew\s+bytes\s*\(\s*\d{4,}",  # new bytes(>=1000)
]

BENCH_PATTERNS = [
    "**/bench/**", "**/benchmarks/**",
    "**/*.bench.ts", "**/*.bench.js", "**/*_bench.go",
    "**/criterion/**", "**/*.benchmark.*",
    "**/perf/**", "**/test*/perf/**",
]

# Files we consider "performance sensitive" for the bench-presence check
HOTPATH_HINT_RE = re.compile(
    r"\b(?:hotpath|hot[_ ]?path|critical[_ ]?path|"
    r"benchmark|optimi[sz]e|throughput|latency)\b",
    re.IGNORECASE,
)


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="performance",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, PERF_SENSITIVE_PATTERNS)
    if not relevant:
        result.applicable = False
        result.summary = "No performance-sensitive files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    sol_files = [f for f in relevant if f.endswith(".sol")]

    unbounded_loops: list[tuple[str, int]] = []
    storage_concerns: list[tuple[str, int]] = []
    generic_loops_in_chain: list[tuple[str, int]] = []
    hotpath_files_without_bench: list[str] = []

    storage_pat = re.compile("|".join(LARGE_STORAGE_HINTS))
    has_bench_change = bool(common.filter_files(files, BENCH_PATTERNS))

    for f in sol_files:
        text = common.read_file_safe(f) or ""
        # Solidity unbounded loop = iterating over a state array's length
        for m in SOL_UNBOUNDED_LOOP_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            # Best-effort filter: only flag if state-arrays are present in this file
            if SOL_STATE_ARRAY_RE.search(text):
                unbounded_loops.append((f, line))
                break
        for m in storage_pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            storage_concerns.append((f, line))
            break
        # `.push()` directly on state is an unbounded growth signal
        if SOL_STATE_ARRAY_RE.search(text) and SOL_DYNAMIC_PUSH_RE.search(text):
            # Only escalate if no length cap pattern is present
            if not re.search(r"require\([^)]*\.length\s*<", text):
                m = SOL_DYNAMIC_PUSH_RE.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    storage_concerns.append((f, line))

    # Generic unbounded loops in chain/api/sdk code
    chain_api_files = [f for f in relevant if not f.endswith(".sol")]
    for f in chain_api_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        for pat in GENERIC_UNBOUNDED_LOOP_PATTERNS:
            m = pat.search(text)
            if m:
                # Heuristic: only flag if the function or file mentions a
                # state container (db/storage/list/array) so we don't fire
                # on pure utility loops.
                if re.search(r"\b(?:state|storage|db|repo|collection|array|list)\b", text, re.IGNORECASE):
                    line = text.count("\n", 0, m.start()) + 1
                    generic_loops_in_chain.append((f, line))
                    break

    # Bench presence for files mentioning hotpath/optimize keywords
    for f in relevant:
        text = common.read_file_safe(f) or ""
        if HOTPATH_HINT_RE.search(text) and not has_bench_change:
            hotpath_files_without_bench.append(f)

    if unbounded_loops:
        f, line = unbounded_loops[0]
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Loop over unbounded on-chain state introduced",
            description=(
                f"In {len(unbounded_loops)} Solidity file(s), a `for` loop "
                "iterates over a state-array's `.length`. As the array grows, "
                "gas costs grow linearly until the call exceeds the block "
                "gas limit, denial-of-servicing the contract."
            ),
            recommendation=(
                "Either bound the array, paginate the operation, or process "
                "off-chain and submit a Merkle proof. Add an explicit "
                "`require` on `.length` to make the bound visible."
            ),
            file=f,
            line=line,
        ))

    if storage_concerns:
        f, line = storage_concerns[0]
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Unbounded on-chain storage growth pattern",
            description=(
                "Detected dynamic state arrays, mappings to dynamic arrays, "
                "or large `bytes(N)` allocations without an explicit length "
                "cap."
            ),
            recommendation=(
                "Add a hard length cap, paginate writes, or store off-chain "
                "with a commitment on-chain."
            ),
            file=f,
            line=line,
        ))

    if generic_loops_in_chain:
        f, line = generic_loops_in_chain[0]
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Loop over unbounded collection in chain/API code",
            description=(
                "A loop iterates over a collection that appears to be backed "
                "by state/storage/database. Without an explicit bound this "
                "scales with state size."
            ),
            recommendation=(
                "Paginate the operation, add an explicit upper bound, or "
                "move the work off the request path."
            ),
            file=f,
            line=line,
        ))

    if hotpath_files_without_bench:
        result.add(common.Finding(
            severity=common.Severity.MINOR,
            title="No benchmark for performance-sensitive change",
            description=(
                f"{len(hotpath_files_without_bench)} file(s) reference "
                "hotpath / optimize / throughput / latency, but no benchmark "
                "files were touched."
            ),
            recommendation=(
                "Add or update a benchmark under `benchmarks/` or `bench/` "
                "to track regressions over time."
            ),
            file=hotpath_files_without_bench[0],
        ))

    if not result.findings:
        result.summary = (
            f"{len(relevant)} performance-sensitive file(s) inspected; no "
            "obvious performance regressions detected."
        )
    else:
        result.summary = (
            f"{len(relevant)} performance-sensitive file(s) inspected; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
