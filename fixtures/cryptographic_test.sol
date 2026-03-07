// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Cryptographic Test Cases
/// @notice Exercises both Cryptographic detectors (CR-01 and CR-02).

contract CryptographicTests {

    mapping(bytes32 => bool) public usedSignatures;
    address public owner;
    address public trustedSigner;

    constructor(address _signer) {
        owner = msg.sender;
        trustedSigner = _signer;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CR-01  Lack of Proper Signature Verification
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger CR-01 (sub-pattern A): ecrecover is called but the
    /// returned address is never compared against address(0) NOR against
    /// an expected signer.  An attacker can supply garbage (v, r, s) that
    /// makes ecrecover return address(0) and bypass authentication.
    function unsafeRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        // Bug: return value is not validated at all.
        address signer = ecrecover(hash, v, r, s);
        return signer;
    }

    /// Should trigger CR-01 (sub-pattern B): the function accepts
    /// signature-related parameters but uses msg.sender for auth
    /// instead of ecrecover — unsafe with proxies / meta-tx forwarders.
    function relayAction(
        bytes32 hash,
        bytes memory signature
    ) public {
        // Bug: relying on msg.sender instead of verifying the signature.
        require(msg.sender == owner, "not owner");
        usedSignatures[hash] = true;
    }

    /// Should NOT trigger CR-01: ecrecover result IS compared to address(0).
    function safeRecoverWithZeroCheck(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "invalid signature");
        return signer;
    }

    /// Should NOT trigger CR-01: ecrecover result IS compared to the
    /// expected signer address.
    function safeRecoverWithSignerCheck(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (bool) {
        address recovered = ecrecover(hash, v, r, s);
        return recovered == trustedSigner;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CR-02  Signature Malleability
    // ═══════════════════════════════════════════════════════════════════════

    /// Should trigger CR-02: raw ecrecover is used without enforcing the
    /// s-value lower half-order constraint.  An attacker can create a
    /// second valid (v', r, s') and replay a previously used signature.
    function processSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad sig");
        require(signer == trustedSigner, "wrong signer");

        // Use the raw signature hash as a nonce guard — malleable!
        bytes32 sigHash = keccak256(abi.encodePacked(v, r, s));
        require(!usedSignatures[sigHash], "replayed");
        usedSignatures[sigHash] = true;
    }

    /// Should NOT trigger CR-02: the s-value is manually bounded to the
    /// lower half of the secp256k1 order.
    function processSignatureSafe(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid s"
        );
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad sig");
        require(signer == trustedSigner, "wrong signer");

        bytes32 sigHash = keccak256(abi.encodePacked(v, r, s));
        require(!usedSignatures[sigHash], "replayed");
        usedSignatures[sigHash] = true;
    }

    /// Should NOT trigger CR-02: no ecrecover call at all.
    function noSignature() public pure returns (uint256) {
        return 42;
    }
}
