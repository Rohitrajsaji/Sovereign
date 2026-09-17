use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=idna_uts46_helper.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        println!("cargo:rustc-env=SOVEREIGN_IDNA_UTS46_HELPER=");
        return;
    }

    let Some(out_dir) = env::var_os("OUT_DIR") else {
        panic!("Cargo did not supply OUT_DIR");
    };
    let out_dir = PathBuf::from(out_dir);
    let helper = out_dir.join("sovereign-idna-uts46");
    let status = Command::new("/usr/bin/clang")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            "idna_uts46_helper.c",
            "-licucore",
            "-o",
        ])
        .arg(&helper)
        .status()
        .unwrap_or_else(|error| {
            panic!("failed to launch /usr/bin/clang for UTS #46 helper: {error}")
        });
    assert!(status.success(), "failed to build macOS UTS #46 helper");
    println!(
        "cargo:rustc-env=SOVEREIGN_IDNA_UTS46_HELPER={}",
        helper.display()
    );
}
