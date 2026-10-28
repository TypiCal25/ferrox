// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IPQVerifier {
    function validateKey(bytes32 key) external view returns (bool);
    function keyIdentity(bytes32 key) external view returns (bytes32);
    function verify(bytes32 key, bytes32 digest, bytes calldata signature) external view returns (bool);
}
