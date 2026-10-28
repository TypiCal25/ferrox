// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Immutable STOP-prefixed key data. No owner, upgrade path, or callable code.
contract KeyData {
    constructor(bytes memory data) {
        require(data.length <= 24575, "key too large");
        bytes memory runtime = abi.encodePacked(hex"00", data);
        assembly ("memory-safe") { return(add(runtime, 32), mload(runtime)) }
    }
}
