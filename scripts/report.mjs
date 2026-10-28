import fs from 'node:fs';
const r=JSON.parse(fs.readFileSync('benchmarks/latest.json'));
const m=r.measurements,fmt=n=>n.toLocaleString('en-US');
const rows=[['K-WOTS8', 'wots', null],['ML-DSA-like Keccak', 'mldsa', 'mldsaUpstreamKeccak'],['Falcon-like Keccak32', 'falcon', 'falconUpstreamKeccak'],['Mixed 3-of-3 execution','multisig3of3',null]];
const saving=m.mldsaUpstreamKeccak.transactionGas-m.mldsa.transactionGas;
const extra=r.deployments.mlKey-r.deployments.baselineMLKey;
const text=`# Measured results

Generated from [latest.json](latest.json). Compiler ${r.compiler}; Cancun via-IR, 1,000,000 optimizer runs; signed transactions on a local Prague EVM. Gas includes transaction base, calldata, applicable refunds, and the calldata floor. The separate executionGas field is the EVM's gross execution counter, before transaction refunds/floor accounting.

| Operation | This implementation | Pinned existing Keccak baseline | Reduction |
|---|---:|---:|---:|
${rows.map(([label,key,base])=>`| ${label} | ${fmt(m[key].transactionGas)} | ${base?fmt(m[base].transactionGas):'—'} | ${base?((1-m[key].transactionGas/m[base].transactionGas)*100).toFixed(1)+'%':'—'} |`).join('\n')}

The standard SHAKE baselines measured ${fmt(m.mldsaUpstreamStandard.transactionGas)} gas for ML-DSA and ${fmt(m.falconUpstreamStandard.transactionGas)} for the optimized eight-lane Falcon verifier. The custom variants change hashing; this is not a claim of standard-compatible verification at those lower costs or an exhaustive comparison with every published implementation. Falcon32 also changes candidate width and wire format relative to the existing Keccak baseline. Both profiles preserve unbiased rejection sampling.

The base-16 hash-chain comparison measured ${fmt(m.wots16.transactionGas)} gas. Both hash samples use a height-3 tree and the same test digest. Base 8 is not universally optimal: taller Merkle proofs and different calldata pricing can change the result.

## Setup cost

| Item | Deployment gas |
|---|---:|
${Object.entries(r.deployments).map(([name,value])=>`| ${name} | ${fmt(value)} |`).join('\n')}

The ML key's two expanded data contracts plus descriptor cost ${fmt(extra)} more gas than the pinned baseline's key contract. At ${fmt(saving)} saved per verification, key deployment alone breaks even after **${Math.ceil(extra/saving)} verifications**. Wallet registration validation and verifier deployment costs are additional; this is not a complete lifetime break-even calculation. Immutable data may be shared by multiple wallets.

## Evidence and limits

- ${fmt(r.checks)} integration assertions, including coefficient-level checks on fixed/random/saturated arithmetic inputs. This assertion count is not a count of distinct signatures or cryptographic security tests.
- Additional Python arithmetic models and CLI persistence/concurrency/permission tests run under <code>npm test</code>.
- Baseline key/signature inputs are checked for acceptance before measuring their transactions. Direct verification benchmarks use the same message and source-pinned key converters. Hash profiles and ABI/data layouts differ as documented.
- Test keys, salts, and seeded signing randomness are public fixtures. Values in this report are deterministic samples, not worst-case gas bounds. Unusual Falcon rejection paths are verified separately.
- A standard verification baseline is a mathematical verifier with its own ABI/expanded-key encoding; this does not assert wire compatibility with every signature API.
- See [source provenance](../THIRD_PARTY.md). No external network deployment or funded transaction was performed.

Reproduce with <code>npm ci && npm run build && npm test</code>. <code>npm run profile</code> isolates matrix/transform components. These implementations and custom hash constructions remain unaudited.
`;
fs.writeFileSync('benchmarks/RESULTS.md',text);
console.log('Wrote benchmarks/RESULTS.md');
