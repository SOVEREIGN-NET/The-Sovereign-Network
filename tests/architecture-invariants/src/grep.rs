//! Thin wrapper around `grep` for workspace-source scans.
//!
//! Tests are written against `grep -rn -E ...` on a chosen set of paths
//! relative to the workspace root. The wrapper resolves the workspace
//! root from `CARGO_MANIFEST_DIR` (the test crate sits at
//! `tests/architecture-invariants/` so the workspace is two levels up).
//!
//! Output is a `Vec<String>` of "PATH:LINE: CONTENT" matches. Tests
//! assert `matches.is_empty()` to enforce the invariant.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the workspace root from this crate's Cargo manifest dir.
/// `tests/architecture-invariants/` is two levels deep from the root.
pub fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
}

/// Run `grep -rn -E <pattern>` over the listed paths (relative to the
/// workspace root). Returns each matching line as a String, with file
/// path and line number prefix.
///
/// Excludes the typical noise sources: `target/`, `.qwen/tmp/`,
/// `.git/`, plus any `.md` and `Cargo.lock` files (doc comments and
/// lock-file artefacts shouldn't be scanned by code-pattern ratchets).
pub fn grep_workspace(pattern: &str, paths: &[&str]) -> Vec<String> {
    let root = workspace_root();
    let mut cmd = Command::new("grep");
    cmd.current_dir(&root)
        .arg("-rn")
        .arg("-E")
        .arg("--include=*.rs")
        .arg("--exclude-dir=target")
        .arg("--exclude-dir=.git")
        .arg("--exclude-dir=.qwen")
        .arg("--exclude-dir=node_modules")
        .arg(pattern);
    if paths.is_empty() {
        cmd.arg(".");
    } else {
        for p in paths {
            cmd.arg(p);
        }
    }
    let output = cmd
        .output()
        .expect("`grep` must be on PATH for architecture-invariants tests");
    // grep exit code: 0 = match, 1 = no match, 2+ = error.
    if !output.status.success() && output.status.code() != Some(1) {
        panic!(
            "grep failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string())
        .collect()
}

/// Filter out lines that match any of the given substrings. Used to
/// drop doc-comment mentions of forbidden patterns (a comment saying
/// "the foo trait was deleted" would otherwise trip its own ratchet).
pub fn drop_lines_containing(matches: Vec<String>, drops: &[&str]) -> Vec<String> {
    matches
        .into_iter()
        .filter(|line| !drops.iter().any(|d| line.contains(d)))
        .collect()
}

/// Filter out matches that are inside line comments (`//`) or block
/// comments. Conservative: only checks for `//` before the match
/// position and lines starting with `*` or `///`. Caller responsible
/// for false positives in string literals.
pub fn drop_comment_only_matches(matches: Vec<String>) -> Vec<String> {
    matches
        .into_iter()
        .filter(|line| {
            // Format from grep -n: "PATH:LINE:CONTENT"
            let content = line
                .splitn(3, ':')
                .nth(2)
                .map(str::trim_start)
                .unwrap_or("");
            !(content.starts_with("//")
                || content.starts_with("*")
                || content.starts_with("/*"))
        })
        .collect()
}
