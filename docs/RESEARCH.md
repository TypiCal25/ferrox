# Unselected parallel-transform experiment

`ParallelNTT.sol`, generated `FusedParallelNTT.sol` / `NTTTables.sol`, the Python generators/model, and `ResearchNTTHarness` are research artifacts. **The shipping MLDSAKeccak verifier does not use them.** They retain the lattice mathematics and pass scalar coefficient comparisons, but were slower in the measured compiler profile.

Five polynomials fit in five 51-bit lanes. Montgomery R=2^26 has the particularly small 23-bit correction constant 8380415 for q=8380417, allowing the correction product to fit in each lane. Forward bounds grow through 3q,5q,7q,9q,12q,15q,18q,22q; the model checks positivity and lane-locality. Four inverse polynomials use 64-bit lanes and R=2^32. Generators emit fused radix-8/8/4 schedules.

The experiment reduced arithmetic code duplication but lost execution gas to lane conversion and compiler stack traffic. The selected implementation uses the existing fused NTT kernels and spends the larger key representation on a four-row matrix multiplication instead. `npm run profile` measures the selected matrix against the upstream matrix under the same local compiler/EVM.

The Python model tests 253 scalar forward/inverse cases, 100 arbitrary raw-accumulator inverses, and 10,000 packed five-lane Montgomery operations. EVM tests compare generated transforms against independently written scalar transforms, including saturated cases. These are implementation checks, not formal proofs or a cryptographic audit.
