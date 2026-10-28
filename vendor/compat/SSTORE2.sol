// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {KeyData} from "../../src/KeyData.sol";
/// @dev Compatibility surface for the unmodified upstream benchmark contracts.
library SSTORE2 {
    function write(bytes memory data) internal returns (address) { return address(new KeyData(data)); }
    function read(address pointer) internal view returns (bytes memory data) {
        uint256 len = pointer.code.length;
        require(len > 0);
        data = new bytes(len - 1);
        assembly ("memory-safe") { extcodecopy(pointer, add(data, 32), 1, sub(len, 1)) }
    }
}
