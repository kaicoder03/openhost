// Client-side TURN credential derivation (PR #42.3, JS mirror of
// `openhost-client::turn_creds`). The password is a public function
// of the daemon's Ed25519 identity — anyone with the `oh://<pk>/`
// URL can compute it. TURN long-term auth needs MESSAGE-INTEGRITY
// HMAC with matching inputs on both peers; this provides that
// matching input without a shared secret.

export const TURN_REALM = "openhost";
export const TURN_USERNAME = "openhost";

// Decode the 52-char z-base-32 daemon pubkey to the raw 32 Ed25519 bytes.
// Minimal zbase32 decoder — the alphabet is openhost's 52-char canonical
// form "ybndrfg8ejkmcpqxot1uwisza345h769".
const ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

function zbase32Decode(s) {
  const bits = [];
  for (const ch of s.toLowerCase()) {
    const idx = ZBASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid zbase32 char: ${ch}`);
    for (let i = 4; i >= 0; i--) bits.push((idx >> i) & 1);
  }
  // We encoded 32 bytes = 256 bits into 52 chars * 5 = 260 bits;
  // the trailing 4 bits are padding zeros — drop them.
  const trimmed = bits.slice(0, 256);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | trimmed[i * 8 + j];
    out[i] = byte;
  }
  return out;
}

function hexEncode(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Match `openhost-daemon::turn_server::password_for_daemon` byte-for-byte:
// `lower_hex(sha256("openhost-turn-v1" || daemon_pk))[..32]`.
export async function passwordForDaemon(daemonPkZbase32) {
  const pkBytes = zbase32Decode(daemonPkZbase32);
  const prefix = new TextEncoder().encode("openhost-turn-v1");
  const msg = new Uint8Array(prefix.length + pkBytes.length);
  msg.set(prefix, 0);
  msg.set(pkBytes, prefix.length);
  const digest = await crypto.subtle.digest("SHA-256", msg);
  return hexEncode(new Uint8Array(digest).slice(0, 16));
}

// Build the `RTCIceServer` entry to append to the `iceServers` list
// when the resolved host record carries a v3 `turn_endpoint`. Returns
// `null` if no TURN endpoint was advertised.
export async function turnIceServerFor(daemonPkZbase32, turnEndpoint) {
  if (!turnEndpoint) return null;
  const password = await passwordForDaemon(daemonPkZbase32);
  return {
    urls: [`turn:${turnEndpoint.ip}:${turnEndpoint.port}`],
    username: TURN_USERNAME,
    credential: password,
  };
}
