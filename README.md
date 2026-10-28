# Ferrox

**Forged for the quantum era.**

Ferrox is an EVM-optimized research multisig with three direct on-chain post-quantum signature verifiers. It combines hash-based and lattice-based authorization with packed arithmetic, native Keccak hash profiles, and immutable public-key storage.

> **Research status:** unaudited, experimental cryptography. Do not fund with real assets. The custom hash profiles are distinct from standard ML-DSA, Falcon/FN-DSA, XMSS, and WOTS+; their security claims require independent review.

The wallet implements threshold approvals, optional per-algorithm minimums, arbitrary CALL batches, nonce/chain/wallet/configuration binding, expiry, key rotation, duplicate-key detection by content, and a transient reentrancy guard. It has no ECDSA authorization fallback, external signature oracle, proof service, or administrative upgrade key.

| ID | Verifier | Signature on the wire | Registered key |
|---|---|---|---|
| 1 | `KeccakWOTS` | 2,916 + 32 × tree height bytes | 32-byte Merkle root |
| 2 | `MLDSAKeccak` | 2,420 bytes | Immutable expanded key descriptor |
| 3 | `FalconKeccak` | 1,064 bytes | Immutable 1,024-byte transformed public key |

ML-DSA and Falcon are both lattice-based. Requiring a hash-based signature as well gives an authorization dependency on another family. Register each human/organization once: distinct cryptographic keys cannot establish distinct human identities.

## Measured performance

These are deterministic samples from signed transactions on a local Prague EVM, compiled with Solidity 0.8.30, via-IR, and 1,000,000 optimizer runs. Transaction gas includes the base cost and calldata; deployment and key registration are separate.

| Operation | Transaction gas | Pinned Keccak baseline | Reduction |
|---|---:|---:|---:|
| K-WOTS8, height 3 | 155,554 | — | — |
| ML-DSA-like Keccak | 775,146 | 896,389 | 13.5% |
| Falcon-like Keccak32 | 258,600 | 1,482,244 | 82.6% |
| Mixed 3-of-3 execution | 1,240,208 | — | — |

The Falcon comparison uses the specified existing Keccak path, not the fastest available standard Falcon implementation. Hash profiles, key representations, and ABI layouts differ. These results establish wins against the pinned baselines, not a universal ranking or standard-compatible speedup. The larger ML key costs more to deploy; key deployment alone breaks even after approximately 33 verifications against the local baseline.

See the [benchmark report](benchmarks/RESULTS.md), [raw measurements](benchmarks/latest.json), and [source attribution](THIRD_PARTY.md) for the complete comparison. The implementation builds on existing ZKNOX lattice kernels and noble reference signers.

## Quick start

Requires Node.js 24 and Python 3. Contracts require **Cancun or later**, including MCOPY and transient storage. Benchmarks use Prague transaction accounting.

```sh
git clone https://github.com/TypiCal25/ferrox.git
cd ferrox
git submodule update --init
npm ci
npm run build
npm test
npm run profile
```

The two submodules pin the exact upstream verifier sources used by the contracts and benchmarks. After cloning an existing checkout, run `git submodule update --init` before building. Their nested development submodules are not required by Ferrox's npm test harness.

`npm test` runs the arithmetic models, source freshness checks, integration/negative tests, and CLI state/concurrency tests. It writes [`benchmarks/latest.json`](benchmarks/latest.json). [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) explains the measured comparison and registration tradeoff. Build output includes ABI/bytecode artifacts and enforces the 24,576-byte runtime limit; test deployments enforce that limit too.

The recorded suite passes 37,052 arithmetic/integration assertions plus CLI persistence, permissions, and concurrency checks. This assertion count is not a count of distinct signature vectors or a cryptographic security proof.

## What makes it faster

- ML-DSA keys transpose the matrix so four rows occupy four 64-bit lanes. A multiplication by one coefficient computes four products. The expanded layout eliminates unpacking during matrix multiplication. The directly packed challenge sampler avoids a 256-word intermediate and the upstream byte-by-byte PRNG calls.
- Falcon uses the pinned eight-lane integer NTT, native Keccak counter expansion, unbiased 32-bit rejection sampling, and a common path that computes eight squared differences together. Rejection and unaligned tails have a separate checked path.
- K-WOTS uses native Keccak and 32-byte chain elements. Both base-8 and base-16 constructions are benchmarked. The main verifier uses base 8; `test/KeccakWOTS16.sol` is a compatible wallet-interface alternative with smaller signatures and more hashing. The best choice depends on tree height and calldata pricing.
- Keys live in immutable STOP-prefixed bytecode, outside wallet SSTORE slots. Signatures stay in calldata until the arithmetic needs them. Approvals arrive in one transaction; no proposals or individual approvals are persisted.

These are measured optimizations relative to pinned sources, not a proof of a global gas minimum. The standard baselines use SHAKE, while custom profiles change the cryptographic construction. Compare the custom ML result with the existing Keccak ML baseline to isolate the implementation gain more fairly.

The expanded ML key costs more to deploy. Its two data contracts total 40,960 data bytes; the descriptor is another 104 bytes. Both key deployment cost and the break-even number of uses are reported. Public-key expansion happens off-chain; **the expanded verification key itself is what the multisig authorizes**. Registration checks representation and arithmetic bounds, but does not prove its derivation from a compact standard key. Every signature acceptance decision, hash expansion, arithmetic check, and threshold decision runs on-chain.

## Signer tools

Use secure paths outside the repository. These are reference research signers, not hardware-wallet integrations.

```sh
node scripts/wots-cli.mjs keygen /secure/hash.key.json 4
node scripts/wots-cli.mjs sign /secure/hash.key.json 0xYOUR_32_BYTE_DIGEST

node scripts/pq-cli.mjs keygen mldsa44-keccak /secure/ml.key.json
node scripts/pq-cli.mjs sign /secure/ml.key.json 0xYOUR_32_BYTE_DIGEST

node scripts/pq-cli.mjs keygen falcon512-keccak32 /secure/falcon.key.json
node scripts/pq-cli.mjs sign /secure/falcon.key.json 0xYOUR_32_BYTE_DIGEST
```

The lattice key generator writes a private `0600` file and a separate public `.public.json` file. Use CSPRNG-generated keys; seeds in tests are public and deliberately insecure fixtures.

The WOTS signer locks its state file, increments and fsyncs its leaf allocation, atomically renames the new state, fsyncs the directory, and only then computes/releases the signature. Crashes can burn leaves. Never copy, restore, or concurrently maintain independent copies of a WOTS state file. **Signing two different messages with the same leaf can compromise that key even if neither transaction executes.** Failed transactions and abandoned proposals also consume an off-chain leaf. The low-level `signWotsAt` helper is for fixtures; use the stateful CLI for allocation.

The reference tree builder constructs the full tree in memory. Large heights need substantial offline computation and memory. A height-4 tree has only 16 signatures and is useful for demonstrations. Add a final `16` argument to WOTS key generation to use the base-16 variant; deploy the matching hash verifier.

## Wallet integration

1. Deploy `KeccakWOTS`, `MLDSAKeccak`, and `FalconKeccak`.
2. For ML, deploy `KeyData` twice with the public `parts`, then once with `part0Address[20] || part1Address[20] || tr[64]`. For Falcon deploy `KeyData` with the public `data`.
3. Deploy `PQWallet(verifierAddresses, owners, policy)`. Owner keys are the hash root or a data/descriptor address left-padded to bytes32. Owner IDs are zero-based array indices. Configuration rejects duplicate credentials stored at different addresses.
4. Call `wallet.digest(calls, deadline)` and have the required owners sign that exact bytes32 value. Sort approvals by owner ID.
5. Any relayer calls `execute(calls, deadline, approvals)`. Transaction sender identity does not authorize spending.

For a mixed 3-of-3 policy use `{threshold: 3, hashMin: 1, mlMin: 1, falconMin: 1}`. A normal threshold can set all three minima to zero. Changes to owners or policy must be an approved CALL to `wallet.configure(...)` from the wallet itself. A global configuration epoch invalidates outstanding approvals.

Hash leaf high-water marks survive removal and re-addition of roots. Executing a higher leaf invalidates all lower outstanding leaves. The global nonce and leaf allocation are separate counters. The full executable example is [`test/integration.mjs`](test/integration.mjs).

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for exact hash and encoding rules, [`docs/RESEARCH.md`](docs/RESEARCH.md) for the unselected transform experiment, and [`THIRD_PARTY.md`](THIRD_PARTY.md) for source provenance and attribution.

## Technical report

The 12-page report covers the implementation changes, equations, local and published comparisons, deployment costs, rejected experiments, and validation limits.

- [Compiled PDF](output/pdf/pq_multisig_report.pdf)
- [Standalone LaTeX source](docs/latex/pq_multisig_report.tex)
- [Report generation instructions](docs/latex/README.txt)

## Project layout

| Path | Contents |
|---|---|
| `src/` | Wallet, verifiers, immutable key data, and isolated transform research |
| `scripts/` | Reference signers, key preparation, build and report tools |
| `test/` | Local EVM harness, integration checks, signer checks, and profiling |
| `benchmarks/` | Recorded gas measurements and comparison report |
| `docs/` | Protocol specification, research notes, and LaTeX report |
| `vendor/` | Pinned upstream submodules and compilation compatibility surfaces |

## License and attribution

Ferrox is released under the [MIT License](LICENSE). Upstream components retain their own licenses and notices. [THIRD_PARTY.md](THIRD_PARTY.md) identifies the reused arithmetic, reference signers, exact commits, and project-specific contributions.
