// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {sampleInBallKeccakPrng} from "../vendor/ethdilithium/src/ZKNOX_SampleInBall.sol";
import {packPoly} from "../vendor/ethdilithium/src/ZKNOX_dilithium_core_packed.sol";
import {falconProduct8} from "../vendor/ethfalcon/src/ZKNOX_NTT_falcon8.sol";
import {forward5, inverse4} from "../src/ParallelNTT.sol";
import {MLDSAKeccak} from "../src/MLDSAKeccak.sol";
import {readPubKeyPacked, _matvecRowPacked} from "../vendor/ethdilithium/src/ZKNOX_dilithium_core_packed.sol";
import {PubKey} from "../vendor/ethdilithium/src/ZKNOX_dilithium_utils.sol";
import {nttFwMontPackedFusedTb, nttInvMontPackedRawFusedTb, _tablesMont} from "../vendor/ethdilithium/src/ZKNOX_NTT_dilithium_mont.sol";

contract ReferenceChallenge {
    function challenge(bytes32 ct) external pure returns (uint256[] memory) {
        return packPoly(sampleInBallKeccakPrng(abi.encodePacked(ct), 39, 8380417));
    }
}
contract NTTTestHarness is MLDSAKeccak {
    function profile(bytes memory key, uint256[][] memory z, uint256[] memory c) external view returns (uint256[3] memory g) {
        (uint256 tb, uint256 ti) = _tablesMont();
        uint256 before = gasleft();
        for (uint256 i; i < 4; ++i) nttFwMontPackedFusedTb(z[i], tb);
        nttFwMontPackedFusedTb(c, tb);
        g[0] = before - gasleft();
        before = gasleft();
        uint256[][] memory w = _matrix(key, z, c);
        g[1] = before - gasleft();
        before = gasleft();
        for (uint256 i; i < 4; ++i) nttInvMontPackedRawFusedTb(w[i], ti);
        g[2] = before - gasleft();
    }
    function matvec(bytes memory key, uint256[][] memory z, uint256[] memory c) external pure returns (uint256[][] memory) {
        return _matrix(key, z, c);
    }
}
/// @dev Research-only kernels; deliberately excluded from the shipping ML verifier.
contract ResearchNTTHarness {
    function forward(uint256[][] memory z, uint256[] memory c) external pure returns (uint256[] memory) {
        return forward5(z, c);
    }
    function inverse(uint256[] memory a) external pure returns (uint256[][] memory) {
        return inverse4(a);
    }
}
contract ReferenceProfile {
    function profile(address key, uint256[][] memory z, uint256[] memory c) external view returns (uint256[3] memory g) {
        PubKey memory pk = readPubKeyPacked(key);
        (uint256 tb, uint256 ti) = _tablesMont();
        uint256 before = gasleft();
        for (uint256 i; i < 4; ++i) nttFwMontPackedFusedTb(z[i], tb);
        nttFwMontPackedFusedTb(c, tb);
        g[0] = before - gasleft();
        before = gasleft();
        uint256[][] memory w = new uint256[][](4);
        for (uint256 i; i < 4; ++i) w[i] = _matvecRowPacked(pk.aHat[i], z, c, pk.t1[i]);
        g[1] = before - gasleft();
        before = gasleft();
        for (uint256 i; i < 4; ++i) nttInvMontPackedRawFusedTb(w[i], ti);
        g[2] = before - gasleft();
    }
}
contract Target {
    uint256 public value;
    function set(uint256 v) external payable { value = v; }
    function fail() external pure { revert("expected failure"); }
    function reenter(address wallet, bytes calldata input) external {
        (bool ok,) = wallet.call(input);
        require(!ok, "reentrancy succeeded");
        value = 99;
    }
}
