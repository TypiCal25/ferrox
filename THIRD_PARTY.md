# Provenance and attribution

This project extends existing work. It does not claim authorship of the reused lattice kernels or reference signing algorithms.

| Source | Pinned version | Use |
|---|---|---|
| [ZKNoxHQ/ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON/tree/012e08074e8c1a2b79b046ac8eac740122ec3a73) | `012e08074e8c1a2b79b046ac8eac740122ec3a73`, `exp/pq-verifier-gas` | Eight-lane Falcon product/norm, standard and Keccak baselines, SHAKE helper |
| [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM/tree/f85ca80c446c2d59fcd68b5efe565275599bb1f9) | `f85ca80c446c2d59fcd68b5efe565275599bb1f9`, `exp/packed-verifier` | Packed z/hint parsing, fused NTT kernels, hint encoding, baseline verifiers |
| [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum) | npm `@noble/post-quantum@0.7.1`, package-lock integrity | Standard key generation/signing; generated custom hash-profile adaptations |
| [EthereumJS](https://github.com/ethereumjs/ethereumjs-monorepo) | Exact direct versions in package.json; transitive versions in package-lock | Local signed-transaction execution, EIP-170 enforcement, Prague gas accounting |
| [Solidity](https://github.com/ethereum/solidity) | solc 0.8.30 | Cancun via-IR compilation, optimizer runs 1,000,000 |

Upstream source trees retain their original MIT notices and license files. ETHDILITHIUM/ETHFALCON also credit Fireblocks' MIT Keccak-f[1600] helper and packed arithmetic work. The standard benchmark helper bytecode remains pinned by its runtime code hash in the upstream verifier constructors. `vendor/compat` supplies only the small interface and STOP-prefixed storage compatibility surfaces required to compile those baselines; it does not replace their arithmetic.

The custom signers are generated from the installed pinned noble sources into ignored `artifacts/signers/`. Generation preserves the original copyright/license headers and fails if the expected source anchors change. Alterations are explicit in `scripts/prepare-signers.mjs`. Source files in vendor are not edited. The build manifest records SHA-256 hashes of every compiled Solidity source and tests reject stale source artifacts.

Reference specifications: [ML-DSA / FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [Falcon round-3 specification](https://falcon-sign.info/falcon.pdf), [XMSS / RFC 8391](https://www.rfc-editor.org/rfc/rfc8391). Custom variants in this project are not those standards.
