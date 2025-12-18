#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

/// This crate is intended to be built for Cloudflare Workers (wasm32).
///
/// We keep a tiny non-wasm surface so `cargo check --all-targets` on typical dev machines
/// doesn't fail when the workspace includes this crate.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_target_hint() -> &'static str {
    "beacon-worker is intended for wasm32-unknown-unknown (Cloudflare Workers)"
}
