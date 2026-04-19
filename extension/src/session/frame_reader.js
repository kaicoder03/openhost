// Per-DataChannel frame buffer. Chrome delivers RTCDataChannel.onmessage
// as arbitrary-sized chunks; openhost frames can span chunks.
//
// Storage is a chunk list, not a single growing Uint8Array: a 10 MB
// response body arriving in 256 KB chunks would be O(N²) under a
// copy-on-append design. We concatenate lazily when `decode_frame`
// demands a contiguous prefix.
import { decode_frame } from "../../wasm/pkg/openhost_pkarr.js";

export class FrameReader {
  constructor() {
    this._chunks = []; // Uint8Array[]
    this._total = 0;
    this._waiters = []; // { resolve, reject }
  }

  push(chunk) {
    const bytes = chunk instanceof ArrayBuffer ? new Uint8Array(chunk)
                : chunk instanceof Uint8Array ? chunk
                : new Uint8Array(chunk);
    this._chunks.push(bytes);
    this._total += bytes.length;
    this._pump();
  }

  fail(err) {
    this._waiters.forEach(w => w.reject(err));
    this._waiters = [];
  }

  next(timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this._waiters.findIndex(w => w.resolve === resolve);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`frame read timeout after ${timeoutMs}ms`));
      }, timeoutMs);
      this._waiters.push({
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
      this._pump();
    });
  }

  _flatView() {
    if (this._chunks.length === 1) return this._chunks[0];
    const out = new Uint8Array(this._total);
    let off = 0;
    for (const c of this._chunks) { out.set(c, off); off += c.length; }
    this._chunks = [out]; // cache the flattened view
    return out;
  }

  _drop(n) {
    // Advance past `n` bytes of frontmost data. Keeps the chunk list
    // coherent by slicing or popping frontmost chunks as needed.
    while (n > 0 && this._chunks.length > 0) {
      const head = this._chunks[0];
      if (head.length <= n) { n -= head.length; this._total -= head.length; this._chunks.shift(); }
      else { this._chunks[0] = head.subarray(n); this._total -= n; n = 0; }
    }
  }

  _pump() {
    while (this._waiters.length > 0 && this._total > 0) {
      const view = this._flatView();
      let decoded;
      try { decoded = decode_frame(view); }
      catch (e) { const w = this._waiters.shift(); w.reject(e); continue; }
      if (!decoded) return; // partial; wait for more bytes
      this._drop(decoded.consumed);
      const w = this._waiters.shift();
      w.resolve(decoded);
    }
  }
}
