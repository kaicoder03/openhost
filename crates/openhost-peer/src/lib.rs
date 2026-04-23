//! Ephemeral-peer pairing primitives for openhost.
//!
//! Two peers that want to move bytes between themselves — e.g. `oh
//! send foo.pdf` on a laptop and `oh recv` on a phone — first agree
//! on a short-lived shared secret, then use that secret to find each
//! other via pkarr and encrypt a WebRTC session. This crate ships
//! the foundational pieces of that flow:
//!
//! - [`code`] — [`PairingCode`]: 128 bits of entropy with two
//!   human-readable renderings ([`PairingCode::to_words`] for
//!   voice/typing, [`PairingCode::to_uri`] for QR codes). Either
//!   rendering round-trips losslessly via [`PairingCode::parse`].
//!
//! - [`mailbox`] — [`MailboxKey`]: HKDF-SHA256 derivation from a
//!   [`PairingCode`] into (a) an Ed25519 keypair that names the
//!   pkarr rendezvous mailbox and (b) a ChaCha20-Poly1305 AEAD key
//!   for envelope-encrypting the mailbox records.
//!
//! ## Transport paths (informational)
//!
//! PR-A is transport-agnostic — it only produces the primitives the
//! subsequent PRs layer a WebRTC handshake and a file-transfer
//! protocol on top of. That said, the design already accommodates
//! three connectivity paths ranked by how reliable we expect them
//! to be:
//!
//! 1. **Same LAN / same NAT.** ICE host candidates in each peer's
//!    SDP list the LAN IPs. Connectivity checks succeed without any
//!    external server; the data channel flows directly over the
//!    local network at wire speed. No mDNS / Bonjour required.
//!
//! 2. **Direct peer-to-peer across the internet.** STUN-discovered
//!    srflx candidates hole-punch when both peers are behind cone
//!    NATs — the common case for residential broadband.
//!
//! 3. **TURN relay fallback.** When hole-punching fails (symmetric
//!    NAT, corporate egress), either peer's embedded TURN server
//!    can carry the bytes.
//!
//! ## Security sketch
//!
//! - The raw 16-byte secret is wrapped in [`zeroize::Zeroize`]d
//!   containers and never logged; [`PairingCode::fmt`] redacts.
//! - Mailbox identity and AEAD key derive from the same IKM via
//!   distinct HKDF `info` tags, so knowledge of one does not give
//!   up the other.
//! - Mailbox records are AEAD-sealed — anyone can fetch the pkarr
//!   zone (it is public by design), but only the two peers who
//!   share the pairing code can decrypt the contents.
//! - This crate does NOT run a PAKE (SPAKE2 / OPAQUE). A passive
//!   attacker who captures the pkarr traffic can therefore mount
//!   an offline dictionary attack against the pairing secret; 128
//!   bits is chosen to keep that attack infeasible (10^38 trials).
//!   A follow-up PR may add SPAKE2 to enable shorter codes.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod code;
pub mod error;
pub mod mailbox;
pub mod roles;

pub use code::{PairingCode, PAIRING_SECRET_BYTES, PAIRING_URI_SCHEME};
pub use error::{PeerError, Result};
pub use mailbox::{MailboxKey, MAILBOX_NONCE_LEN};
pub use roles::Roles;
