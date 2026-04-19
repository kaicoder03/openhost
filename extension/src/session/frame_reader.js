// Per-DataChannel frame buffer. Chrome delivers RTCDataChannel.onmessage
// as arbitrary-sized chunks; openhost frames can span chunks.
import { decode_frame } from "../../wasm/pkg/openhost_pkarr.js";

export class FrameReader {
  constructor() {
    this._buf = new Uint8Array(0);
    this._waiters = []; // { resolve, reject }
  }

  push(chunk) {
    const bytes = chunk instanceof ArrayBuffer ? new Uint8Array(chunk)
                : chunk instanceof Uint8Array ? chunk
                : new Uint8Array(chunk);
    const grown = new Uint8Array(this._buf.length + bytes.length);
    grown.set(this._buf, 0);
    grown.set(bytes, this._buf.length);
    this._buf = grown;
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

  _pump() {
    while (this._waiters.length > 0 && this._buf.length > 0) {
      let decoded;
      try { decoded = decode_frame(this._buf); }
      catch (e) { const w = this._waiters.shift(); w.reject(e); continue; }
      if (!decoded) return; // partial; wait for more bytes
      this._buf = this._buf.slice(decoded.consumed);
      const w = this._waiters.shift();
      w.resolve(decoded);
    }
  }
}
