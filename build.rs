use std::process::Command;

fn main() {
    // Get git commit count
    let output = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .expect("Failed to run git rev-list");
    let patch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("cargo:rustc-env=API_PATCH_VERSION={}", patch);
} 