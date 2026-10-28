// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {IPQVerifier} from "./IPQVerifier.sol";

/// @notice Mixed-algorithm t-of-n multisig with optional per-algorithm minima.
/// @dev Each owner entry is one independently counted identity. Register an identity once.
contract PQWallet {
    struct OwnerInit { bytes32 key; uint8 algorithm; }
    struct Owner { bytes32 key; uint8 algorithm; }
    struct Policy { uint16 threshold; uint8 hashMin; uint8 mlMin; uint8 falconMin; }
    struct Call { address target; uint256 value; bytes data; }
    struct Approval { uint16 owner; bytes signature; }

    bytes32 public constant DOMAIN = keccak256("PQWALLET/EXECUTE/v1");
    IPQVerifier public immutable hashVerifier;
    IPQVerifier public immutable mlVerifier;
    IPQVerifier public immutable falconVerifier;
    Owner[] public owners;
    uint64 public nonce;
    uint32 public epoch;
    Policy public policy;
    bool transient private entered;

    error InvalidConfiguration();
    error Unauthorized();
    error Expired();
    error InvalidApprovals();
    error InvalidSignature(uint256 owner);
    error LeafAlreadyUsed();
    error Reentrant();
    error CallFailed(uint256 index, bytes reason);
    event Executed(bytes32 indexed digest, uint64 indexed nonce);
    event Configured(uint32 indexed epoch, bytes32 ownersHash, Policy policy);

    constructor(address[3] memory verifiers, OwnerInit[] memory initialOwners, Policy memory initialPolicy) payable {
        for (uint256 i; i < 3; ++i) if (verifiers[i].code.length == 0) revert InvalidConfiguration();
        hashVerifier = IPQVerifier(verifiers[0]);
        mlVerifier = IPQVerifier(verifiers[1]);
        falconVerifier = IPQVerifier(verifiers[2]);
        _configure(initialOwners, initialPolicy);
    }
    receive() external payable {}

    function ownerCount() external view returns (uint256) { return owners.length; }

    function _verifier(uint8 algorithm) internal view returns (IPQVerifier) {
        if (algorithm == 1) return hashVerifier;
        if (algorithm == 2) return mlVerifier;
        if (algorithm == 3) return falconVerifier;
        revert InvalidConfiguration();
    }

    function _configure(OwnerInit[] memory newOwners, Policy memory p) internal {
        uint256 n = newOwners.length;
        if (n == 0 || n > 256 || p.threshold == 0 || p.threshold > n) revert InvalidConfiguration();
        uint256[3] memory counts;
        bytes32[] memory identities = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            OwnerInit memory o = newOwners[i];
            if (!_verifier(o.algorithm).validateKey(o.key)) revert InvalidConfiguration();
            identities[i] = _verifier(o.algorithm).keyIdentity(o.key);
            // Duplicate credentials must not acquire two votes, including keys re-added
            // with a different algorithm identifier.
            for (uint256 j; j < i; ++j) {
                if (newOwners[j].key == o.key || (newOwners[j].algorithm == o.algorithm && identities[j] == identities[i])) revert InvalidConfiguration();
            }
            counts[o.algorithm - 1]++;
        }
        if (p.hashMin > counts[0] || p.mlMin > counts[1] || p.falconMin > counts[2]) revert InvalidConfiguration();
        // Preserve a hash root's high-water mark across every removal/re-addition.
        delete owners;
        for (uint256 i; i < n; ++i) owners.push(Owner(newOwners[i].key, newOwners[i].algorithm));
        policy = p;
        epoch++;
        emit Configured(epoch, keccak256(abi.encode(newOwners)), p);
    }

    // Root use survives configuration changes, so re-registering an old tree cannot reset it.
    mapping(bytes32 => uint64) public nextLeafForRoot;

    function configure(OwnerInit[] calldata newOwners, Policy calldata p) external {
        if (msg.sender != address(this)) revert Unauthorized();
        _configure(newOwners, p);
    }

    function digest(Call[] calldata calls, uint64 deadline) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), epoch, nonce, deadline, keccak256(abi.encode(calls))));
    }

    function execute(Call[] calldata calls, uint64 deadline, Approval[] calldata approvals) external payable {
        if (entered) revert Reentrant();
        if (block.timestamp > deadline) revert Expired();
        if (calls.length == 0 || calls.length > 256) revert InvalidApprovals();
        Policy memory p = policy;
        if (approvals.length < p.threshold || approvals.length > owners.length) revert InvalidApprovals();
        entered = true;
        bytes32 d = digest(calls, deadline);
        uint256 previous;
        uint256[3] memory counts;
        for (uint256 i; i < approvals.length; ++i) {
            Approval calldata a = approvals[i];
            uint256 id = uint256(a.owner) + 1;
            if (id <= previous || id > owners.length) revert InvalidApprovals();
            previous = id;
            Owner storage o = owners[a.owner];
            if (o.algorithm == 1) {
                if (a.signature.length < 4) revert InvalidSignature(a.owner);
                uint32 leaf = uint32(bytes4(a.signature[:4]));
                if (leaf < nextLeafForRoot[o.key]) revert LeafAlreadyUsed();
                nextLeafForRoot[o.key] = uint64(leaf) + 1;
            }
            if (!_verifier(o.algorithm).verify(o.key, d, a.signature)) revert InvalidSignature(a.owner);
            counts[o.algorithm - 1]++;
        }
        if (counts[0] < p.hashMin || counts[1] < p.mlMin || counts[2] < p.falconMin) revert InvalidApprovals();
        uint64 usedNonce = nonce;
        nonce++;
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, result);
        }
        entered = false;
        emit Executed(d, usedNonce);
    }
}
