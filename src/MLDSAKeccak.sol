// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {IPQVerifier} from "./IPQVerifier.sol";
import {Signature} from "../vendor/ethdilithium/src/ZKNOX_dilithium_utils.sol";
import {dilithiumCore1Packed, useHintPacked} from "../vendor/ethdilithium/src/ZKNOX_dilithium_core_packed.sol";
import {nttFwMontPackedFusedTb, nttInvMontPackedRawFusedTb, _tablesMont} from "../vendor/ethdilithium/src/ZKNOX_NTT_dilithium_mont.sol";

/// @notice EXPERIMENTAL ML-DSA-44-KeccakCTR (ETHDilithium hash profile).
/// @dev Key descriptor: part0[20] || part1[20] || tr[64]. Each part is 20,480 bytes.
///      Expanded columns contain four rows per word, in 64-bit lanes.
///      A_hat is in standard NTT order; t1_hat includes the 2^13 factor.
contract MLDSAKeccak is IPQVerifier {
    function keyIdentity(bytes32 key) external view returns (bytes32) {
        (bytes memory blob, bytes memory tr) = _key(key);
        return keccak256(abi.encodePacked(tr, blob));
    }
    function _key(bytes32 key) internal view returns (bytes memory blob, bytes memory tr) {
        require(uint256(key) >> 160 == 0, "key address");
        address pointer = address(uint160(uint256(key)));
        require(pointer.code.length == 105, "descriptor length");
        bytes memory descriptor = new bytes(105);
        assembly ("memory-safe") { extcodecopy(pointer, add(descriptor, 32), 0, 105) }
        require(descriptor[0] == 0, "descriptor prefix");
        address part0; address part1;
        tr = new bytes(64);
        assembly ("memory-safe") {
            part0 := shr(96, mload(add(descriptor, 33)))
            part1 := shr(96, mload(add(descriptor, 53)))
            mcopy(add(tr, 32), add(descriptor, 73), 64)
        }
        require(part0.code.length == 20481 && part1.code.length == 20481, "key part length");
        blob = new bytes(40960);
        assembly ("memory-safe") {
            extcodecopy(part0, add(blob, 32), 1, 20480)
            extcodecopy(part1, add(blob, 20512), 1, 20480)
        }
        // STOP prefixes make the key parts non-executable and immutable.
        bytes memory prefixes = new bytes(2);
        assembly ("memory-safe") {
            extcodecopy(part0, add(prefixes, 32), 0, 1)
            extcodecopy(part1, add(prefixes, 33), 0, 1)
        }
        require(prefixes[0] == 0 && prefixes[1] == 0, "key part prefix");
    }

    function validateKey(bytes32 key) external view returns (bool) {
        (bytes memory blob,) = _key(key);
        for (uint256 j; j < 1280; ++j) {
            uint256 w;
            assembly ("memory-safe") { w := mload(add(add(blob, 32), mul(j, 32))) }
            for (uint256 k; k < 4; ++k) if (((w >> (64 * k)) & 0xffffffffffffffff) >= 8380417) return false;
        }
        return true;
    }

    /// @dev Each key word has four matrix ROWS in 64-bit lanes. One scalar
    ///      multiplication computes four products. No per-verification unpacking.
    ///      Key fields <q; transformed z/c <17q; raw lanes remain <q*2^30.
    function _matrix(bytes memory key, uint256[][] memory z, uint256[] memory c)
        internal pure returns (uint256[][] memory w)
    {
        w = new uint256[][](4);
        for (uint256 r; r < 4; ++r) w[r] = new uint256[](64);
        assembly ("memory-safe") {
            let p0 := add(key, 32)
            let p1 := add(p0, 8192)
            let p2 := add(p1, 8192)
            let p3 := add(p2, 8192)
            let pt := add(p3, 8192)
            let z0p := add(mload(add(z, 32)), 32)
            let z1p := add(mload(add(z, 64)), 32)
            let z2p := add(mload(add(z, 96)), 32)
            let z3p := add(mload(add(z, 128)), 32)
            let cp := add(c, 32)
            let w0p := add(mload(add(w, 32)), 32)
            let w1p := add(mload(add(w, 64)), 32)
            let w2p := add(mload(add(w, 96)), 32)
            let w3p := add(mload(add(w, 128)), 32)
            let temp := mload(0x40)
            mstore(0x40, add(temp, 128))
            let mask := 0xffffffffffffffff
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let off := shl(5, i)
                let z0 := mload(add(z0p, off))
                let z1 := mload(add(z1p, off))
                let z2 := mload(add(z2p, off))
                let z3 := mload(add(z3p, off))
                let cw := mload(add(cp, off))
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    let kp := add(shl(7, i), shl(5, j))
                    let zs := shl(6, j)
                    let acc := add(0x0007fe00100000000007fe00100000000007fe00100000000007fe0010000000,
                        add(add(mul(mload(add(p0, kp)), and(shr(zs, z0), mask)), mul(mload(add(p1, kp)), and(shr(zs, z1), mask))),
                            add(mul(mload(add(p2, kp)), and(shr(zs, z2), mask)), mul(mload(add(p3, kp)), and(shr(zs, z3), mask)))))
                    mstore(add(temp, shl(5, j)), sub(acc, mul(mload(add(pt, kp)), and(shr(zs, cw), mask))))
                }
                let a := mload(temp)
                let b := mload(add(temp, 32))
                let cc := mload(add(temp, 64))
                let d := mload(add(temp, 96))
                mstore(add(w0p, off), or(or(and(a, mask), shl(64, and(b, mask))), or(shl(128, and(cc, mask)), shl(192, d))))
                mstore(add(w1p, off), or(or(and(shr(64, a), mask), and(b, shl(64, mask))), or(shl(128, and(shr(64, cc), mask)), shl(192, and(shr(64, d), mask)))))
                mstore(add(w2p, off), or(or(and(shr(128, a), mask), shl(64, and(shr(128, b), mask))), or(and(cc, shl(128, mask)), shl(192, and(shr(128, d), mask)))))
                mstore(add(w3p, off), or(or(shr(192, a), shl(64, shr(192, b))), or(shl(128, shr(192, cc)), and(d, shl(192, mask)))))
            }
        }
    }

    function _core(bytes memory key, uint256[][] memory z, uint256[] memory c, uint256[4] memory hints) internal pure returns (bytes memory) {
        (uint256 tb, uint256 ti) = _tablesMont();
        for (uint256 j; j < 4; ++j) nttFwMontPackedFusedTb(z[j], tb);
        nttFwMontPackedFusedTb(c, tb);
        uint256[][] memory w = _matrix(key, z, c);
        for (uint256 j; j < 4; ++j) w[j] = nttInvMontPackedRawFusedTb(w[j], ti);
        return useHintPacked(hints, w);
    }

    /// @dev SampleInBall directly into 64 words of four 64-bit lanes; avoids
    ///      the upstream 256-word temporary, PRNG struct, byte calls and packing.
    function challenge(bytes32 ct) public pure returns (uint256[] memory c) {
        c = new uint256[](64);
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, ct)
            let seed := keccak256(p, 32)
            mstore(p, seed)
            mstore(add(p, 32), 0)
            let pool := keccak256(p, 40)
            let signs := 0
            for { let k := 0 } lt(k, 8) { k := add(k, 1) } {
                signs := or(signs, shl(mul(k, 8), byte(k, pool)))
            }
            let pos := 8
            let counter := 1
            for { let i := 217 } lt(i, 256) { i := add(i, 1) } {
                let j := 256
                for {} gt(j, i) {} {
                    if eq(pos, 32) {
                        mstore(add(p, 32), shl(192, counter))
                        pool := keccak256(p, 40)
                        counter := add(counter, 1)
                        pos := 0
                    }
                    j := byte(pos, pool)
                    pos := add(pos, 1)
                }
                let jp := add(add(c, 32), mul(shr(2, j), 32))
                let js := mul(and(j, 3), 64)
                let ip := add(add(c, 32), mul(shr(2, i), 32))
                let is := mul(and(i, 3), 64)
                let previous := and(shr(js, mload(jp)), 0xffffffffffffffff)
                mstore(ip, or(and(mload(ip), not(shl(is, 0xffffffffffffffff))), shl(is, previous)))
                let value := add(1, mul(and(signs, 1), 8380415))
                mstore(jp, or(and(mload(jp), not(shl(js, 0xffffffffffffffff))), shl(js, value)))
                signs := shr(1, signs)
            }
        }
    }

    function verify(bytes32 key, bytes32 digest, bytes calldata sig) external view returns (bool) {
        if (sig.length != 2420 || uint256(key) >> 160 != 0) return false;
        address pointer = address(uint160(uint256(key)));
        if (pointer.code.length != 105) return false;
        Signature memory parsed = Signature(sig[:32], sig[32:2336], sig[2336:]);
        (bool ok, uint256[][] memory z, uint256[4] memory hints) = dilithiumCore1Packed(parsed);
        if (!ok) return false;
        (bytes memory expandedKey, bytes memory tr) = _key(key);
        bytes32 ct = bytes32(sig[:32]);
        bytes memory w = _core(expandedKey, z, challenge(ct), hints);
        bytes32 seed = keccak256(abi.encodePacked(tr, hex"0000", digest));
        bytes32 mu0 = keccak256(abi.encodePacked(seed, uint64(0)));
        bytes32 mu1 = keccak256(abi.encodePacked(seed, uint64(1)));
        seed = keccak256(abi.encodePacked(mu0, mu1, w));
        return keccak256(abi.encodePacked(seed, uint64(0))) == ct;
    }
}
