//! Embedded frontend assets (built into the server binary).
//!
//! This crate exists to isolate the (potentially large) embedded `dist/` payload from the main
//! backend crate, improving incremental build and CI cache efficiency.

use rust_embed::RustEmbed;
use std::borrow::Cow;

#[derive(RustEmbed)]
#[folder = "../../dist/"]
pub struct BeaconFrontendAssets;

/// Get an embedded asset by path.
///
/// `path` should be relative (e.g. `index.html`, `static/app.js`).
pub fn get(path: &str) -> Option<Cow<'static, [u8]>> {
    BeaconFrontendAssets::get(path).map(|f| f.data)
}
