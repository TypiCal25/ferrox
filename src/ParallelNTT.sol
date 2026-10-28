// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {REP64, MASK32X4, FW26, IV32, SCALE32} from "./NTTTables.sol";

import {fusedForward5, fusedInverse4} from "./FusedParallelNTT.sol";

/// @dev Five polynomials in parallel: five 51-bit lanes in each coefficient word.
///      Montgomery R=2^26 has an unusually small QINV=8380415 (23 bits).
///      Thus the correction multiplication fits each 51-bit lane. No modulus,
///      lattice dimension, transform order, or challenge distribution is changed.
///      Canonical inputs; output <22q, congruent to ordinary forward NTT.
function forward5(uint256[][] memory z, uint256[] memory c) pure returns (uint256[] memory a) {
    require(z.length == 4 && c.length == 64, "forward shape");
    for (uint256 i; i < 4; ++i) require(z[i].length == 64, "forward shape");
    a = new uint256[](256);
    bytes memory tw = FW26;
    assembly ("memory-safe") {
        let z0p := add(mload(add(z, 32)), 32)
        let z1p := add(mload(add(z, 64)), 32)
        let z2p := add(mload(add(z, 96)), 32)
        let z3p := add(mload(add(z, 128)), 32)
        let cp := add(c, 32)
        let ap := add(a, 32)
        for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
            let off := shl(5, i)
            let z0 := mload(add(z0p, off))
            let z1 := mload(add(z1p, off))
            let z2 := mload(add(z2p, off))
            let z3 := mload(add(z3p, off))
            let cw := mload(add(cp, off))
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                let s := shl(6, j)
                let v := or(or(and(shr(s, z0), 0xffffffffffffffff), shl(51, and(shr(s, z1), 0xffffffffffffffff))),
                    or(shl(102, and(shr(s, z2), 0xffffffffffffffff)), or(shl(153, and(shr(s, z3), 0xffffffffffffffff)), shl(204, and(shr(s, cw), 0xffffffffffffffff)))))
                mstore(add(ap, shl(5, add(shl(2, i), j))), v)
            }
        }

    }
    uint256 tb;
    assembly ("memory-safe") { tb := add(tw, 32) }
    fusedForward5(a, tb);
}

/// @dev Four rows in parallel in 64-bit lanes. Input raw lanes <q*2^30.
///      Reduces once, then runs an ordinary inverse NTT with Montgomery R=2^32.
///      Exact canonical output, transposed into the upstream hint encoder's layout.
function inverse4(uint256[] memory a) pure returns (uint256[][] memory w) {
    require(a.length == 256, "inverse shape");
    bytes memory tw = IV32;
    w = new uint256[][](4);
    for (uint256 i; i < 4; ++i) w[i] = new uint256[](64);
    assembly ("memory-safe") {
        let ap := add(a, 32)
        let mask := 0xffffffffffffffff
        for { let p := ap } lt(p, add(ap, 8192)) { p := add(p, 32) } {
            let x := mload(p)
            mstore(p, or(or(mod(and(x, mask), 8380417), shl(64, mod(and(shr(64, x), mask), 8380417))),
                or(shl(128, mod(and(shr(128, x), mask), 8380417)), shl(192, mod(shr(192, x), 8380417)))))
        }
    }
    uint256 tb;
    assembly ("memory-safe") { tb := add(tw, 32) }
    fusedInverse4(a, tb);
    assembly ("memory-safe") {
        let ap := add(a, 32)
        let mask := 0xffffffffffffffff
        for { let p := ap } lt(p, add(ap, 8192)) { p := add(p, 32) } {
            let x := mul(mload(p), SCALE32)
            let m := and(mul(and(x, MASK32X4), 4236238847), MASK32X4)
            let r := shr(32, add(x, mul(m, 8380417)))
            let ge := and(shr(24, add(r, mul(8396799, REP64))), REP64)
            mstore(p, sub(r, mul(ge, 8380417)))
        }
        let w0p := add(mload(add(w, 32)), 32)
        let w1p := add(mload(add(w, 64)), 32)
        let w2p := add(mload(add(w, 96)), 32)
        let w3p := add(mload(add(w, 128)), 32)
        for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
            let p := add(ap, shl(7, i))
            let a0 := mload(p)
            let b := mload(add(p, 32))
            let c := mload(add(p, 64))
            let d := mload(add(p, 96))
            let off := shl(5, i)
            mstore(add(w0p, off), or(or(and(a0, mask), shl(64, and(b, mask))), or(shl(128, and(c, mask)), shl(192, d))))
            mstore(add(w1p, off), or(or(and(shr(64, a0), mask), and(b, shl(64, mask))), or(shl(128, and(shr(64, c), mask)), shl(192, and(shr(64, d), mask)))))
            mstore(add(w2p, off), or(or(and(shr(128, a0), mask), shl(64, and(shr(128, b), mask))), or(and(c, shl(128, mask)), shl(192, and(shr(128, d), mask)))))
            mstore(add(w3p, off), or(or(shr(192, a0), shl(64, shr(192, b))), or(shl(128, shr(192, c)), and(d, shl(192, mask)))))
        }
    }
}
