# Protocol v1

All custom schemes are experimental and unaudited. Keeping the original lattice parameters does not establish the security of substituted hashes. Tests establish implementation agreement, not cryptographic security or standard compliance. No claim of a uniform NIST security category is made across these custom schemes.

## Authorization

The exact authorization digest is Solidity `keccak256(abi.encode(DOMAIN, block.chainid, address(wallet), uint32(epoch), uint64(nonce), uint64(deadline), keccak256(abi.encode(calls))))`, where `DOMAIN=keccak256(UTF8("PQWALLET/EXECUTE/v1"))` and `calls` is an array of `(address target,uint256 value,bytes data)` tuples. Use the contract's `digest` function or identical ABI encoding. No personal-sign prefix applies.

Each owner approves that digest with its registered algorithm. Approvals must have strictly increasing owner IDs, meet the total threshold, and meet all per-algorithm minima. Every supplied approval is verified. Configuration changes increment the epoch. The nonce increments before external calls; a failed call reverts the entire batch, nonce, and on-chain leaf update. Targets receive CALL, never DELEGATECALL. Success means EVM call success; token-specific returned booleans are not interpreted by the wallet.

The policy is ordinary multisignature verification, not a cryptographically aggregated threshold signature. Validation cost grows with the approvals supplied. Distinct keys are not evidence of distinct people.

## Common Keccak counter stream

`seed = keccak256(input)`; block `j = keccak256(seed || uint64_be(j))`, starting at zero. Concatenate blocks, consuming bytes in displayed order. This construction is not SHAKE. Counters must never wrap; the reference stream rejects exhaustion.

## K-WOTS8-Merkle

`n=32`, `w=8`, height `0..20`. Interpret the digest as an unsigned big-endian integer D. Its 86 message digits are `(D >> (255 - 3*i)) & 7`, `i=0..85`; two leading zero bits pad the 258-bit representation. The first digit therefore contains only one message bit. Compute `S=sum(7-digit[i])`, then append four checksum digits `(S >> 9)&7`, `(S >> 6)&7`, `(S >> 3)&7`, `S&7`. There are 90 chains, each with seven steps.

Domains are Keccak of the UTF-8 strings `PQWALLET/KWOTS8/CHAIN/v1`, `PQWALLET/KWOTS8/LEAF/v1`, and `PQWALLET/KWOTS8/NODE/v1`. All numbers below occupy 32 big-endian bytes unless indicated otherwise.

- Chain step: `K(CHAIN || publicSeed[32] || address || value[32])`; `address=(leafIndex<<32)|(chainIndex<<8)|step`. A signature reveals the chain at its corresponding message/checksum digit; verify completes through step 6.
- Leaf: `K(LEAF || publicSeed || leafIndex || endpoint[0] || ... || endpoint[89])`.
- Parent at level L: `K(NODE || L || left || right)`; leaf level is zero. Sibling order is determined by bit L of the leaf index.
- Wire: `uint32_be(leafIndex) || publicSeed[32] || chainValues[90*32] || siblings[height*32]`. Exact length is `2916+32*height`, and `leafIndex < 2^height`.

The signer derives each chain secret as `K(SECRET || secretSeed || publicSeed || leafIndex || chainIndex)`, with domain `PQWALLET/KWOTS8/SECRET/v1`. On-chain verification does not require knowledge of that derivation.

This construction uses addressed hash chains and a checksum. It does not implement the WOTS+ masking construction and is not presented as standard XMSS. The root is the complete registered verification key. The wallet enforces monotonically increasing leaf use; the signer must enforce persistent allocation before any disclosure.

The base-16 benchmark variant uses domains with `KWOTS16`, 64 four-bit message digits, three high-to-low four-bit checksum digits, 67 chains of 15 steps, and a wire length of `2180+32*height`.

## ML-DSA-44-KeccakCTR

The mathematical parameters, signature encoding, z norm checks, hint canonicalization, challenge weight 39, polynomial arithmetic modulo `q=8380417`, and NTT dimension 256 follow the ML-DSA-44 core used by the pinned ETHDILITHIUM source. The hash profile matches its existing ETHDilithium variant:

1. `mPrime = 0x00 || 0x00 || digest[32]` (empty context).
2. `mu = CTR(tr[64] || mPrime, 64)`.
3. Challenge positions/signs are SampleInBall with the common counter stream on `cTilde[32]`, preserving rejection, little-endian sign bits, and weight 39.
4. Reconstruct w1 with the lattice equation and canonical hints.
5. Accept only if `CTR(mu || w1Encoded[768],32) == cTilde`.

The 2420-byte signature is `cTilde[32] || z[2304] || h[84]`. The standard signing key's `tr` remains SHAKE256 of the original compact public key, 64 bytes. Reference key generation, secret sampling, and matrix expansion remain unchanged. The generated signer changes message/challenge hashing and SampleInBall only; it does not change sampling of secret keys or signing masks.

The expanded key consists of five columns of 256 words. Each word has row 0 in bits 0..63, row 1 in 64..127, row 2 in 128..191, row 3 in 192..255. Columns 0..3 contain the corresponding column of A-hat; column 4 contains `NTT(2^13*t1)`. Every field is canonical `<q`. Split these 40,960 bytes into two consecutive 20,480-byte data contracts. The registered descriptor is `part0Address[20] || part1Address[20] || tr[64]` in another STOP-prefixed data contract.

Registration validates data lengths, STOP prefixes, and canonical coefficients. It does not recompute A-hat or tr from a compact public key. Owners authorize the expanded key, whose identity is `K(tr || expandedColumns)`. This prevents duplicate content at different descriptor/data addresses from acquiring extra votes. Matrix inputs after the upstream transforms are `<17q`; the four-row accumulator adds `q*2^28` to each lane to prevent subtraction borrow. Each lane stays nonnegative and below `q*2^30`, within 64 bits. Scalar-reference tests include the maximum assumed inputs.

## Falcon-512-KeccakCTR32

Retains Falcon-512's `n=512`, `q=12289`, and squared norm bound `34034726`. It substitutes hash-to-point and uses a separate wire representation.

`input = K(UTF8("PQWALLET/FALCON512/POINT32/v1")) || salt[40] || digest[32]`. Consume the common counter stream four bytes at a time, interpreting each as uint32 big endian. Reject candidates `>=4294956344 = floor(2^32/q)*q`; reduce accepted candidates modulo q. Take the first 512 accepted coefficients. Rejection is essential: unconditional modulo would be biased.

The compact wire is `salt[40] || packedS2[1024]`. Pack 16 canonical residues modulo q in each 256-bit word, low field first, then serialize each word big endian. Negative coefficients use their canonical mod-q representatives. The transformed public key has the same 16-bit-field packing. It is the **full ordinary NTT of h** for the pinned kernel, not an unvalidated caller-provided transform. The matching key converter is `falconKey` in `scripts/keys.mjs`.

The verifier rejects out-of-range signature fields and checks the exact sum `||center(c-s2*h)||² + ||center(s2)||² <= 34034726`. The eight-lane arithmetic, normalization, and full NTT key conventions come from the pinned ETHFALCON branch. Public key identity is the immutable data contract's code hash. The generated reference signer changes only HashToPoint; key generation and floating-point Gaussian signing machinery remain from the pinned noble package. This custom verification wire is not the round-3 compressed signature encoding.

The common sampler path is used only when the output index is eight-aligned, eight outputs remain, and every candidate has its upper 16 bits below 65535. A bit-run detector establishes that sufficient condition. All exceptional blocks use explicit rejection checks, index bounds, and individual norm accumulation. Tests force a real rejection at candidate 471, followed by unaligned and tail handling.
