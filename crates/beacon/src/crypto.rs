// Back-compat shim: keep `crate::crypto::*` working in the server crate,
// but host the actual implementation in `beacon-core`.
pub use beacon_core::crypto::*;
