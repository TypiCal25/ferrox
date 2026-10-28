# Measured results

Generated from [latest.json](latest.json). Compiler 0.8.30+commit.73712a01.Emscripten.clang; Cancun via-IR, 1,000,000 optimizer runs; signed transactions on a local Prague EVM. Gas includes transaction base, calldata, applicable refunds, and the calldata floor. The separate executionGas field is the EVM's gross execution counter, before transaction refunds/floor accounting.

| Operation | This implementation | Pinned existing Keccak baseline | Reduction |
|---|---:|---:|---:|
| K-WOTS8 | 155,554 | — | — |
| ML-DSA-like Keccak | 775,146 | 896,389 | 13.5% |
| Falcon-like Keccak32 | 258,600 | 1,482,244 | 82.6% |
| Mixed 3-of-3 execution | 1,240,208 | — | — |

The standard SHAKE baselines measured 1,248,061 gas for ML-DSA and 688,565 for the optimized eight-lane Falcon verifier. The custom variants change hashing; this is not a claim of standard-compatible verification at those lower costs or an exhaustive comparison with every published implementation. Falcon32 also changes candidate width and wire format relative to the existing Keccak baseline. Both profiles preserve unbiased rejection sampling.

The base-16 hash-chain comparison measured 161,764 gas. Both hash samples use a height-3 tree and the same test digest. Base 8 is not universally optimal: taller Merkle proofs and different calldata pricing can change the result.

## Setup cost

| Item | Deployment gas |
|---|---:|
| wallet | 2,508,682 |
| hashVerifier | 284,029 |
| mlVerifier | 3,823,338 |
| falconVerifier | 3,725,778 |
| mlKey | 8,779,908 |
| baselineMLKey | 4,836,510 |
| falconKey | 281,092 |

The ML key's two expanded data contracts plus descriptor cost 3,943,398 more gas than the pinned baseline's key contract. At 121,243 saved per verification, key deployment alone breaks even after **33 verifications**. Wallet registration validation and verifier deployment costs are additional; this is not a complete lifetime break-even calculation. Immutable data may be shared by multiple wallets.

## Evidence and limits

- 37,052 integration assertions, including coefficient-level checks on fixed/random/saturated arithmetic inputs. This assertion count is not a count of distinct signatures or cryptographic security tests.
- Additional Python arithmetic models and CLI persistence/concurrency/permission tests run under <code>npm test</code>.
- Baseline key/signature inputs are checked for acceptance before measuring their transactions. Direct verification benchmarks use the same message and source-pinned key converters. Hash profiles and ABI/data layouts differ as documented.
- Test keys, salts, and seeded signing randomness are public fixtures. Values in this report are deterministic samples, not worst-case gas bounds. Unusual Falcon rejection paths are verified separately.
- A standard verification baseline is a mathematical verifier with its own ABI/expanded-key encoding; this does not assert wire compatibility with every signature API.
- See [source provenance](../THIRD_PARTY.md). No external network deployment or funded transaction was performed.

Reproduce with <code>npm ci && npm run build && npm test</code>. <code>npm run profile</code> isolates matrix/transform components. These implementations and custom hash constructions remain unaudited.
