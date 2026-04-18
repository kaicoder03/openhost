//! Bundled default list of public Pkarr HTTP relays.
//!
//! End-users are expected to edit this list; implementations **MUST NOT**
//! hard-code relay trust decisions against these URLs. The list is
//! informational: the openhost protocol treats every relay as adversarial —
//! records are only trusted via their Ed25519 signature, never by source.
//!
//! Sourced from `spec/03-pkarr-records.md §2.1`. Keep this in sync with the
//! spec.

/// Default Pkarr HTTP relays bundled with `openhost-pkarr`.
///
/// The first entry is also carried in `pkarr::DEFAULT_RELAYS`; the second is
/// operated by the Iroh project. Both are informational examples — consumers
/// **MUST** allow the end-user to override this list at runtime.
pub const DEFAULT_RELAYS: &[&str] = &["https://pkarr.pubky.app", "https://relay.iroh.network"];
