use std::process::Command;

fn main() {
    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_HASH={hash}");
    // Re-run when HEAD changes (new commits, branch switches, etc.)
    println!("cargo:rerun-if-changed=.git/HEAD");

    // Forward the host target triple so iroh-ota's receiver can match it
    // against incoming manifests.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=TARGET={target}");

    // Operator-supplied artifact verifying key, hex-encoded (32 bytes / 64
    // hex chars). Absent at build time -> OTA stays disabled at runtime.
    println!("cargo:rerun-if-env-changed=PIGEONS_OTA_PUBKEY");
}
