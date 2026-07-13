use std::process::Command;

fn main() {
    let hash = git_head_hash();
    let dirty = git_is_dirty();
    let revision = if dirty {
        format!("{hash}-dirty")
    } else {
        hash
    };
    println!("cargo:rustc-env=BUILD_REVISION={revision}");
    // Re-run on every build so dirty-tree detection stays accurate.
    println!("cargo:rerun-if-changed=build.rs");
}

fn git_head_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|hash| !hash.is_empty() && *hash != "unknown")
        .unwrap_or_else(|| {
            panic!(
                "CONSENSUS build requires a git checkout — cannot embed BUILD_REVISION"
            );
        })
}

fn git_is_dirty() -> bool {
    // diff-index compares the working tree AND index against HEAD.
    Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map(|status| !status.success())
        .unwrap_or(true)
}