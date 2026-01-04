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

    let pnpm_path = which::which("pnpm").expect(
        "pnpm executable not found in PATH. Please ensure pnpm is installed and available in your PATH.",
    );

    println!(
        "cargo:warning=Building frontend with pnpm at {:?}...",
        pnpm_path
    );

    let status = Command::new(&pnpm_path)
        .arg("build")
        .current_dir("../../")
        .status()
        .expect("Failed to execute pnpm build");

    if !status.success() {
        panic!("pnpm build failed with exit code: {:?}", status.code());
    }

    println!("cargo:warning=Frontend build completed successfully");
}
