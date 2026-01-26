use std::process::Command;

fn main() {
    // Attempt to capture git information
    capture_git_info();

    // Capture build timestamp
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", chrono::Utc::now().to_rfc3339());

    // Capture build profile
    println!("cargo:rustc-env=BUILD_PROFILE={}", std::env::var("PROFILE").unwrap_or_default());
}

fn capture_git_info() {
    // Git commit hash
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(".")
        .output()
    {
        if output.status.success() {
            let hash = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=GIT_HASH={}", hash.trim());
        } else {
            println!("cargo:rustc-env=GIT_HASH=unknown");
        }
    } else {
        println!("cargo:rustc-env=GIT_HASH=unknown");
    }

    // Git branch
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(".")
        .output()
    {
        if output.status.success() {
            let branch = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=GIT_BRANCH={}", branch.trim());
        } else {
            println!("cargo:rustc-env=GIT_BRANCH=unknown");
        }
    } else {
        println!("cargo:rustc-env=GIT_BRANCH=unknown");
    }

    // Git dirty status
    if let Ok(output) = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(".")
        .output()
    {
        let dirty = !String::from_utf8_lossy(&output.stdout).is_empty();
        println!("cargo:rustc-env=GIT_DIRTY={}", if dirty { "true" } else { "false" });
    } else {
        println!("cargo:rustc-env=GIT_DIRTY=unknown");
    }
}
