// Dev-only probe for PR #28.2.
//
// Not imported from the production service worker path. Operators who
// want to exercise the four WASM exports uncomment a single line in
// extension/src/background.js and reload the extension.
//
// The probe fetches a signed pkarr packet from a public relay for the
// pubkey passed in, then hands the bytes to each of the four shim
// functions and logs the results to the service-worker devtools
// console. Failures are caught and printed — a 404 from the relay
// for a nonexistent pubkey is the routine "no record here" case.

import init, {
  decode_host_record,
  verify_record,
  decode_offer,
  decode_answer_fragments,
} from "../../wasm/pkg/openhost_pkarr.js";

// Default list mirrors `openhost_pkarr::DEFAULT_RELAYS`. Keep in sync
// when the Rust side's list changes. Dynamic lookup is PR #28.4 work.
const DEFAULT_RELAYS = [
  "https://relay.pkarr.org",
  "https://pkarr.pubky.app",
  "https://pkarr.pubky.org",
];

/**
 * Run the full four-export probe against one pubkey. Returns nothing;
 * observable output lands on the devtools console.
 *
 * @param {string} pubkeyZbase32 - 52-char zbase32 Ed25519 pubkey.
 * @param {object} [opts]
 * @param {string[]} [opts.relays] - override the default relay list.
 * @param {Uint8Array} [opts.daemonSalt] - salt for answer reassembly.
 *        Without this, decode_answer_fragments is skipped.
 * @param {string} [opts.clientPubkey] - zbase32 pubkey of the client
 *        whose answer fragment to look for.
 */
export async function runResolverProbe(pubkeyZbase32, opts = {}) {
  await init();

  const relays = opts.relays ?? DEFAULT_RELAYS;
  const nowTs = Math.floor(Date.now() / 1000);

  console.log("[probe] relays:", relays);
  console.log("[probe] pubkey:", pubkeyZbase32);

  let bytes = null;
  for (const relay of relays) {
    const url = `${relay}/${pubkeyZbase32}`;
    try {
      const resp = await fetch(url);
      if (!resp.ok) {
        console.warn(`[probe] ${relay} -> ${resp.status} ${resp.statusText}`);
        continue;
      }
      bytes = new Uint8Array(await resp.arrayBuffer());
      console.log(`[probe] ${relay} -> ${bytes.byteLength} bytes`);
      break;
    } catch (e) {
      console.warn(`[probe] ${relay} -> network error: ${e.message}`);
    }
  }
  if (!bytes) {
    console.error("[probe] no relay returned a packet — bailing");
    return;
  }

  try {
    const record = decode_host_record(bytes, pubkeyZbase32, nowTs);
    console.log("[probe] decode_host_record:", record);
  } catch (e) {
    console.error("[probe] decode_host_record threw:", e);
  }

  try {
    const verified = verify_record(bytes, pubkeyZbase32, nowTs);
    console.log(`[probe] verify_record: ${verified}`);
  } catch (e) {
    console.error("[probe] verify_record threw:", e);
  }

  try {
    const offer = decode_offer(bytes, pubkeyZbase32);
    console.log("[probe] decode_offer:", offer);
  } catch (e) {
    console.error("[probe] decode_offer threw:", e);
  }

  if (opts.daemonSalt && opts.clientPubkey) {
    try {
      const ans = decode_answer_fragments(
        bytes,
        opts.daemonSalt,
        opts.clientPubkey,
      );
      console.log("[probe] decode_answer_fragments:", ans);
    } catch (e) {
      console.error("[probe] decode_answer_fragments threw:", e);
    }
  } else {
    console.log(
      "[probe] decode_answer_fragments: skipped (supply opts.daemonSalt + opts.clientPubkey to run)",
    );
  }
}
