/* RUST-008: read-only browser parity adapter.
 * Loads no assets, accesses no live arcade state, and performs no game actions.
 * The caller supplies a compiled WASM instance and a copied 256-word fixture.
 * FNV-1a is a reproducibility checksum, NOT an authentication primitive.
 */
(function (root) {
  "use strict";
  const WORDS = 256;
  const MASK = (1n << 64n) - 1n;
  const OFFSET = 0xcbf29ce484222325n;
  const PRIME = 0x100000001b3n;
  function assert(condition, message) {
    if (!condition) throw new Error("RUST-008: " + message);
  }
  function digest(words) {
    assert(words.length === WORDS, "expected exactly 256 words");
    let hash = OFFSET;
    for (const word of words) {
      const v = word >>> 0;
      for (let k = 0; k < 4; ++k) {
        hash = ((hash ^ BigInt((v >>> (8 * k)) & 255)) * PRIME) & MASK;
      }
    }
    return hash;
  }
  function wasmDigest(exports, ptr) {
    const low = BigInt(exports.ns_evidence_digest_low(ptr) >>> 0);
    const high = BigInt(exports.ns_evidence_digest_high(ptr) >>> 0);
    return (high << 32n) | low;
  }
  function parity(wasm, copiedInitial, actions, oracle) {
    const ex = wasm.exports || wasm;
    for (const name of ["memory", "ns_match_alloc", "ns_match_step", "ns_match_free",
      "ns_evidence_digest_low", "ns_evidence_digest_high"]) {
      assert(ex[name], "missing WASM export " + name);
    }
    assert(copiedInitial.length === WORDS, "initial state size");
    assert(typeof oracle === "function", "independent JS oracle required");
    let rust = Int32Array.from(copiedInitial);
    let js = Int32Array.from(copiedInitial);
    const evidence = [];
    const ptr = ex.ns_match_alloc();
    assert(ptr !== 0, "WASM allocation failed");
    try {
      for (let i = 0; i < actions.length; i++) {
        assert(rust[4] === 0, "action after terminal at " + i);
        const a = actions[i];
        const before = digest(rust);
        rust[6] = a.code | 0; rust[7] = a.uid | 0; rust[8] = a.meter | 0;
        const view = new Int32Array(ex.memory.buffer, ptr, WORDS);
        view.set(rust);
        const result = ex.ns_match_step(ptr);
        assert(result === 0, "Rust rejected step " + i + ": " + result);
        rust = Int32Array.from(new Int32Array(ex.memory.buffer, ptr, WORDS));
        const calculated = digest(rust);
        const native = wasmDigest(ex, ptr);
        assert(native === calculated, "WASM digest mismatch at " + i);
        const next = oracle(Int32Array.from(js), a, i);
        assert(next && next.length === WORDS, "independent oracle returned invalid state");
        js = Int32Array.from(next);
        // Action descriptors are part of the canonical 256-word snapshot.
        js[6] = a.code | 0; js[7] = a.uid | 0; js[8] = a.meter | 0;
        assert(digest(js) === calculated, "JS/Rust state mismatch at " + i);
        evidence.push(Object.freeze({
          sequence: i, before: before.toString(16).padStart(16, "0"),
          after: calculated.toString(16).padStart(16, "0"),
          terminal: rust[4], winner: rust[230],
          released: [rust[231], rust[232]],
          removed: [rust[228], rust[229]]
        }));
      }
      return Object.freeze({ pass: true, steps: evidence.length, evidence });
    } finally {
      ex.ns_match_free(ptr);
    }
  }
  root.neuroscapeEvidenceParity = Object.freeze({ digest, parity });
})(typeof window !== "undefined" ? window : globalThis);
