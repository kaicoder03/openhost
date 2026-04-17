//! C FFI surface for openhost-client. Consumed by Swift via a generated XCFramework.
//!
//! Populated in M6. Each exported function must be `extern "C"`, must not panic
//! across the FFI boundary, and must expose a plain C-compatible type signature.
