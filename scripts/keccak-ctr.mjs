import {keccak_256} from '@noble/hashes/sha3.js';
import {concatBytes} from '@noble/hashes/utils.js';

// Stream matches K(K(input) || uint64_be(counter)), starting at counter zero.
// Experimental construction: this does not implement SHAKE.
export class KeccakCTR {
  constructor(opts = {}) { this.parts = []; this.dkLen = opts.dkLen ?? 32; this.counter = 0n; this.pos = 32; }
  update(data) { if (this.seed) throw Error('already squeezing'); this.parts.push(data.slice()); return this; }
  xofInto(out) {
    if (!this.seed) this.seed = keccak_256(concatBytes(...this.parts));
    for (let i=0; i<out.length; i++) {
      if (this.pos === 32) {
        if (this.counter >= 1n << 64n) throw Error('counter exhausted');
        const ctr = new Uint8Array(8); new DataView(ctr.buffer).setBigUint64(0, this.counter++);
        this.pool = keccak_256(concatBytes(this.seed, ctr)); this.pos = 0;
      }
      out[i] = this.pool[this.pos++];
    }
    return out;
  }
  xof(n) { return this.xofInto(new Uint8Array(n)); }
  digest() { return this.xof(this.dkLen); }
  destroy() { for (const p of this.parts) p.fill(0); this.seed?.fill(0); this.pool?.fill(0); }
}
export const keccakCTR = Object.assign((input, opts) => new KeccakCTR(opts).update(input).digest(), {
  create: opts => new KeccakCTR(opts), blockLen: 32
});
