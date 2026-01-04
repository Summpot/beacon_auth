use std::process::Command;

fn main() {
    // Rebuild frontend only when frontend inputs change.
    println!("cargo:rerun-if-changed=../../src");
    println!("cargo:rerun-if-changed=../../public");
    println!("cargo:rerun-if-changed=../../rsbuild.config.ts");
    println!("cargo:rerun-if-changed=../../postcss.config.mjs");
    println!("cargo:rerun-if-changed=../../tsconfig.json");
    println!("cargo:rerun-if-changed=../../package.json");
    println!("cargo:rerun-if-changed=../../pnpm-lock.yaml");

    let (program, args) = if let Ok(bun_path) = which::which("bun") {
        println!(
            "cargo:warning=Building frontend with bun at {:?}...",
            bun_path
        );
        (bun_path, vec!["run", "build"])
    } else {
        let pnpm_path = which::which("pnpm").expect(
            "Neither bun nor pnpm executable found in PATH. Please ensure one of them is installed.",
        );
        println!(
            "cargo:warning=Building frontend with pnpm at {:?}...",
            pnpm_path
        );
        (pnpm_path, vec!["build"])
    };

    let status = Command::new(&program)
        .args(&args)
        .current_dir("../../")
        .status()
        .expect("Failed to execute frontend build command");

    if !status.success() {
        panic!("Frontend build failed with exit code: {:?}", status.code());
    }

    println!("cargo:warning=Frontend build completed successfully");
}
