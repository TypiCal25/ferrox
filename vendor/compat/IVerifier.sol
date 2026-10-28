// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
interface ISigVerifier {
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
