/* tslint:disable */
/* eslint-disable */

/**
 * Assemble a serialized Pkarr `SignedPacket` carrying the client's
 * offer TXT, ready for `PUT https://<relay>/<client-pk-zbase32>`.
 */
export function build_offer_packet(client_sk_bytes: Uint8Array, daemon_pk_zbase32: string, sealed_offer: Uint8Array, now_ts: bigint): Uint8Array;

/**
 * Given a raw offer SDP, return the canonical reconstructed SDP the
 * daemon will build from the extracted v3 blob. Use this on the JS
 * side to compute an `offer_sdp_hash` that matches what the daemon
 * will hash on its end — the answer's binding hash is over the
 * reconstructed form, not the browser's raw SDP.
 */
export function canonicalize_offer_sdp(offer_sdp: string, binding_mode_u8: number): string;

/**
 * Derive the client's zbase32 Ed25519 pubkey from its 32-byte seed.
 */
export function client_pubkey_from_seed(seed_bytes: Uint8Array): string;

/**
 * Compute 32 AUTH bytes for a browser dial's CertFp channel binding.
 * Feeds [`sign_auth_client`] + [`verify_auth_host`].
 */
export function compute_cert_fp_binding(cert_der: Uint8Array, host_pk_zbase32: string, client_pk_zbase32: string, nonce_bytes: Uint8Array): Uint8Array;

/**
 * Decode + verify a pkarr packet in one pass.
 *
 * Runs the same decode as [`parse_host_record`], then the Ed25519
 * signature check + 2-hour freshness window. Returns the decoded
 * record on success. On failure, the returned `JsError` message
 * distinguishes structural-parse failures (malformed TXT, base64
 * error) from verification failures ("record verify failed: ...") so
 * JS can branch on the message prefix today; a structured error
 * union is planned for PR #28.3.
 *
 * `now_ts` is the caller's current Unix timestamp (seconds). Use
 * `Math.floor(Date.now() / 1000)` on the JS side; the shim enforces
 * the spec's 2-hour window around this value.
 */
export function decode_and_verify(packet_bytes: Uint8Array, pubkey_zbase32: string, now_ts: bigint): any;

/**
 * Reassemble + return the fragmented answer record addressed to
 * `client_pk_zbase32` from inside a daemon's pkarr packet.
 *
 * See `spec/01-wire-format.md §3.3` for the fragment envelope. This
 * function does NOT unseal — it returns the raw sealed ciphertext
 * (concatenated across fragments) so the caller can run sealed-box
 * open with the client's X25519 private key, which the WASM
 * extension is not trusted to see. Returns `Ok(null)` when no
 * fragment set for this client is present.
 */
export function decode_answer_fragments(packet_bytes: Uint8Array, daemon_salt: Uint8Array, client_pk_zbase32: string, daemon_pk_zbase32: string): any;

/**
 * Try to decode one frame from the front of `buf`. Returns JS `null`
 * on incomplete buffer; a `DecodedFrame` object otherwise.
 */
export function decode_frame(buf: Uint8Array): any;

/**
 * Look up the sealed offer record (if any) inside a daemon's pkarr
 * packet. Returns `Ok(null)` when the packet carries no offer TXT
 * for this daemon — the routine "no new offer yet" case for dialer
 * poll loops.
 */
export function decode_offer(packet_bytes: Uint8Array, daemon_pk_zbase32: string): any;

/**
 * Encode one wire frame for the data channel.
 */
export function encode_frame(frame_type_u8: number, payload: Uint8Array): Uint8Array;

/**
 * Open an answer ciphertext with the client's 32-byte secret key and
 * return a reconstructed SDP ready for
 * `RTCPeerConnection.setRemoteDescription`. Handles both v1 and v2
 * answer shapes transparently — see [`core::open_answer`] for the
 * format description.
 *
 * `host_dtls_fp_hex` is the lowercase-hex 64-char encoding of the
 * host's SHA-256 DTLS certificate fingerprint, derived from the
 * already-resolved pkarr `_openhost` record on the JS side
 * (`record.dtls_fingerprint_hex`). Ignored for legacy v1 answers;
 * required for v2.
 */
export function open_answer(client_sk_bytes: Uint8Array, sealed_base64url: string, host_dtls_fp_hex: string): any;

/**
 * Generate a fresh pairing code (128 bits of OS-RNG entropy) and
 * return its words + URI + derived roles. Used by the "send from
 * browser" flow (PR-D follow-up) — receive-only web app doesn't
 * need this.
 */
export function pairing_generate(): any;

/**
 * Parse a pairing code (12 BIP-39 words OR a `oh+pair://` URI) and
 * derive both role keys + their zbase32 pubkeys.
 *
 * Errors if the code fails to parse. All returned seeds are 32-byte
 * Ed25519 private-key seeds; the browser converts them to signing
 * keys via the existing `client_pubkey_from_seed` path on the wire,
 * but the web app never needs to hold them in JS — every seal /
 * answer-decrypt step runs in WASM.
 */
export function pairing_roles(code_str: string): any;

/**
 * Structurally decode a pkarr packet into its `_openhost` main
 * record.
 *
 * `packet_bytes` — raw bytes returned by a relay (the HTTP response
 * body from `GET /<zbase32-pubkey>` against a public Pkarr relay).
 * `pubkey_zbase32` — the zbase32 form of the host's Ed25519 pubkey
 * the caller asked about. Returned back on the record for
 * convenience.
 *
 * **Does not verify the signature or freshness.** Use
 * [`decode_and_verify`] whenever the returned record will be trusted
 * to pick a connection endpoint. Returns a JS object matching
 * [`core::HostRecord`].
 */
export function parse_host_record(packet_bytes: Uint8Array, pubkey_zbase32: string): any;

/**
 * Seal a client offer plaintext to the daemon's X25519 pubkey.
 * Returns the raw sealed bytes; JS base64url-encodes them for the
 * Pkarr relay PUT.
 *
 * Internally extracts the compact v3 offer blob from the raw SDP
 * `RTCPeerConnection.createOffer()` produced — JS never sees the
 * blob structure. The v3 blob reduces a Chrome-generated ~1100-byte
 * SDP to a ~130-byte body so the sealed packet fits under BEP44's
 * 1000-byte cap.
 *
 * `binding_mode_u8` MUST be `0x02` (CertFp) for browser calls.
 */
export function seal_offer(daemon_pk_zbase32: string, client_pk_zbase32: string, offer_sdp: string, binding_mode_u8: number): Uint8Array;

/**
 * Produce the AUTH_CLIENT payload (96 bytes: 32B client_pk ||
 * 64B Ed25519 sig over `auth_bytes`).
 */
export function sign_auth_client(client_sk_bytes: Uint8Array, auth_bytes: Uint8Array): Uint8Array;

/**
 * Verify the daemon's AUTH_HOST 64-byte signature against
 * `auth_bytes` under `host_pk`. Returns a `bool`.
 */
export function verify_auth_host(host_pk_zbase32: string, auth_bytes: Uint8Array, signature_64b: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly parse_host_record: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly decode_and_verify: (a: number, b: number, c: number, d: number, e: number, f: bigint) => void;
    readonly decode_offer: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly decode_answer_fragments: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly seal_offer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly canonicalize_offer_sdp: (a: number, b: number, c: number, d: number) => void;
    readonly open_answer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly compute_cert_fp_binding: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly sign_auth_client: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly verify_auth_host: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly encode_frame: (a: number, b: number, c: number, d: number) => void;
    readonly decode_frame: (a: number, b: number, c: number) => void;
    readonly client_pubkey_from_seed: (a: number, b: number, c: number) => void;
    readonly build_offer_packet: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint) => void;
    readonly pairing_roles: (a: number, b: number, c: number) => void;
    readonly pairing_generate: (a: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
