// Back-compat shim: keep `crate::models::*` working in the server crate,
// but host the actual types in `beacon-core`.
pub use beacon_core::models::*;
