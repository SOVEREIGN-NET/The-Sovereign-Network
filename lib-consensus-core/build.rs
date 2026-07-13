use std::process::Command;

fn main() {
    let hash = git_head_hash();
    let dirty = git_is_dirty();
    let build_id = if dirty {
        format!("{hash}-dirty")
    } else {
        hash
    };
    println!("cargo:rustc-env=CONSENSUS_BUILD_ID={build_id}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
}

fn git_head_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|hash| !hash.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|output| !String::from_utf8_lossy(&output.stdout).is_empty())
        .unwrap_or(false)
}