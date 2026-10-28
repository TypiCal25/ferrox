// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {IPQVerifier} from "./IPQVerifier.sol";
import {falconProduct8} from "../vendor/ethfalcon/src/ZKNOX_NTT_falcon8.sol";
import {_s2NormCompact} from "../vendor/ethfalcon/src/ZKNOX_NTT_falcon_fused.sol";

/// @notice EXPERIMENTAL Falcon-512-KeccakCTR32-v1. NOT standard Falcon/FN-DSA.
/// @dev Keeps Falcon-512's lattice parameters and exact squared-norm bound.
contract FalconKeccak is IPQVerifier {
    bytes32 internal constant DOMAIN = keccak256("PQWALLET/FALCON512/POINT32/v1");
    function keyIdentity(bytes32 key) external view returns (bytes32) {
        return address(uint160(uint256(key))).codehash;
    }

    function validateKey(bytes32 key) external view returns (bool) {
        if (uint256(key) >> 160 != 0) return false;
        address pointer = address(uint160(uint256(key)));
        if (pointer.code.length != 1025) return false;
        bytes memory blob = new bytes(1025);
        assembly ("memory-safe") { extcodecopy(pointer, add(blob, 32), 0, 1025) }
        if (blob[0] != 0) return false;
        // Each packed field must be canonical: product arithmetic assumes this bound.
        for (uint256 i; i < 32; ++i) {
            uint256 w;
            assembly ("memory-safe") { w := mload(add(add(blob, 33), mul(i, 32))) }
            for (uint256 j; j < 16; ++j) if (((w >> (16 * j)) & 65535) >= 12289) return false;
        }
        return true;
    }

    function verify(bytes32 key, bytes32 digest, bytes calldata sig) external view returns (bool) {
        // Salt is 40 bytes; s2 is 32 words of sixteen canonical mod-q coefficients.
        if (sig.length != 1064 || uint256(key) >> 160 != 0) return false;
        address pointer = address(uint160(uint256(key)));
        if (pointer.code.length != 1025) return false;
        uint256[] memory s2 = new uint256[](32);
        uint256[] memory pk = new uint256[](32);
        assembly ("memory-safe") {
            calldatacopy(add(s2, 32), add(sig.offset, 40), 1024)
            extcodecopy(pointer, add(pk, 32), 1, 1024)
        }
        (uint256 bad, uint256 norm) = _s2NormCompact(s2);
        if (bad != 0 || norm > 34034726) return false;
        uint256[] memory s1 = falconProduct8(s2, pk);
        // seed = K(domain || salt[40] || digest), blocks = K(seed || uint64_be(counter)).
        bytes32 seed = keccak256(abi.encodePacked(DOMAIN, sig[:40], digest));
        assembly ("memory-safe") {
            function norm8(b, s) -> n {
                let d := sub(mod(add(shr(224, b), and(s, 0xffffffff)), 12289), 6144)
                n := mul(d, d)
                d := sub(mod(add(and(shr(192, b), 0xffffffff), and(shr(32, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(shr(160, b), 0xffffffff), and(shr(64, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(shr(128, b), 0xffffffff), and(shr(96, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(shr(96, b), 0xffffffff), and(shr(128, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(shr(64, b), 0xffffffff), and(shr(160, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(shr(32, b), 0xffffffff), and(shr(192, s), 0xffffffff)), 12289), 6144)
                n := add(n, mul(d, d))
                d := sub(mod(add(and(b, 0xffffffff), shr(224, s)), 12289), 6144)
                n := add(n, mul(d, d))
            }
            let p := mload(0x40)
            mstore(p, seed)
            let i := 0
            for { let counter := 0 } lt(i, 512) { counter := add(counter, 1) } {
                mstore(add(p, 32), shl(192, counter))
                let blockValue := keccak256(p, 40)
                // All 32-bit draws below 0xffff0000 are below the rejection limit.
                // A SWAR run-of-16-ones detector selects the common eight-at-once path.
                let ones := and(blockValue, shr(8, blockValue))
                ones := and(ones, shr(4, ones))
                ones := and(ones, shr(2, ones))
                ones := and(ones, shr(1, ones))
                switch and(and(iszero(and(i, 7)), lt(i, 505)), iszero(and(ones, 0x0001000000010000000100000001000000010000000100000001000000010000)))
                case 1 {
                    norm := add(norm, norm8(blockValue, mload(add(add(s1, 32), mul(shr(3, i), 32)))))
                    i := add(i, 8)
                }
                default {
                    for { let k := 0 } and(lt(k, 8), lt(i, 512)) { k := add(k, 1) } {
                        let candidate := and(shr(sub(224, mul(k, 32)), blockValue), 0xffffffff)
                        // floor(2^32 / 12289) * 12289. Modulo alone would be biased.
                        if lt(candidate, 4294956344) {
                            let complement := and(shr(mul(and(i, 7), 32), mload(add(add(s1, 32), mul(shr(3, i), 32)))), 0xffffffff)
                            let d := sub(mod(add(candidate, complement), 12289), 6144)
                            norm := add(norm, mul(d, d))
                            i := add(i, 1)
                        }
                    }
                }
            }
        }
        return norm <= 34034726;
    }
}
