// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {IPQVerifier} from "./IPQVerifier.sol";

/// @notice EXPERIMENTAL K-WOTS8-Merkle; not XMSS or WOTS+.
/// @dev n=32, w=8, 86 message digits + 4 checksum digits. See docs/PROTOCOL.md.
///      State enforcement belongs to the wallet and persistent off-chain signer.
contract KeccakWOTS is IPQVerifier {
    bytes32 internal constant CHAIN = keccak256("PQWALLET/KWOTS8/CHAIN/v1");
    bytes32 internal constant LEAF = keccak256("PQWALLET/KWOTS8/LEAF/v1");
    bytes32 internal constant NODE = keccak256("PQWALLET/KWOTS8/NODE/v1");

    function validateKey(bytes32 key) external pure returns (bool) { return key != bytes32(0); }
    function keyIdentity(bytes32 key) external pure returns (bytes32) { return key; }

    function verify(bytes32 root, bytes32 digest, bytes calldata sig) external pure returns (bool valid) {
        // uint32 leaf index, bytes32 public seed, 90 chain values, 0..20 tree siblings.
        if (sig.length < 2916 || sig.length > 3556 || (sig.length - 2916) % 32 != 0) return false;
        uint256 height = (sig.length - 2916) / 32;
        uint256 leaf;
        assembly ("memory-safe") { leaf := shr(224, calldataload(sig.offset)) }
        if (leaf >= 1 << height) return false;
        bytes32 chainDomain = CHAIN;
        bytes32 leafDomain = LEAF;
        bytes32 nodeDomain = NODE;
        assembly ("memory-safe") {
            let p := mload(0x40)
            let ends := add(p, 128)
            mstore(p, chainDomain)
            mstore(add(p, 32), calldataload(add(sig.offset, 4)))
            let checksum := 0
            for { let i := 0 } lt(i, 86) { i := add(i, 1) } {
                checksum := add(checksum, sub(7, and(shr(sub(255, mul(i, 3)), digest), 7)))
            }
            for { let i := 0 } lt(i, 90) { i := add(i, 1) } {
                let digit := 0
                switch lt(i, 86)
                case 1 { digit := and(shr(sub(255, mul(i, 3)), digest), 7) }
                default { digit := and(shr(mul(sub(89, i), 3), checksum), 7) }
                let value := calldataload(add(add(sig.offset, 36), mul(i, 32)))
                let addr := or(shl(32, leaf), shl(8, i))
                for { let j := digit } lt(j, 7) { j := add(j, 1) } {
                    mstore(add(p, 64), or(addr, j))
                    mstore(add(p, 96), value)
                    value := keccak256(p, 128)
                }
                mstore(add(ends, mul(i, 32)), value)
            }
            // Reuse the chain buffer's last 96 bytes as the leaf hash prefix.
            let lp := add(p, 32)
            mstore(lp, leafDomain)
            mstore(add(lp, 32), calldataload(add(sig.offset, 4)))
            mstore(add(lp, 64), leaf)
            let node := keccak256(lp, 2976)
            mstore(p, nodeDomain)
            for { let level := 0 } lt(level, height) { level := add(level, 1) } {
                let sibling := calldataload(add(add(sig.offset, 2916), mul(level, 32)))
                mstore(add(p, 32), level)
                switch and(shr(level, leaf), 1)
                case 0 { mstore(add(p, 64), node) mstore(add(p, 96), sibling) }
                default { mstore(add(p, 64), sibling) mstore(add(p, 96), node) }
                node := keccak256(p, 128)
            }
            valid := eq(node, root)
            mstore(0x40, add(p, 3008))
        }
    }
}
