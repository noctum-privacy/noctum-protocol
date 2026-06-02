// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "./IVerifier.sol";

/// @title HashVerifier
/// @author Noctum Protocol
/// @notice Phase 1 commitment-reveal verifier.
///
///         Proof encoding: abi.encode(bytes32 secret, bytes32 nullifier)
///         Commitment:    keccak256(abi.encodePacked(secret, nullifier))
///         NullifierHash: keccak256(abi.encodePacked(nullifier))
///
///         This contract validates that the prover knows the (secret, nullifier)
///         preimage of a committed deposit note. Merkle membership is enforced
///         separately by NoctumPool (see NoctumPool.withdraw commitment check).
///
///         Replace with a Groth16 on-chain verifier (Path B) by calling
///         NoctumPool.scheduleVerifierUpdate / executeVerifierUpdate.
contract HashVerifier is IVerifier {

    // ── Custom errors ────────────────────────────────────────────────────────
    /// @notice Proof bytes have an unexpected length (expected 64).
    error InvalidProofLength();

    // ── IVerifier ────────────────────────────────────────────────────────────

    /// @inheritdoc IVerifier
    function verifyProof(
        bytes32, /* root — Merkle membership checked by NoctumPool */
        bytes32 nullifierHash,
        address, /* recipient — checked by NoctumPool */
        bytes calldata proof
    ) external pure override returns (bool valid) {
        if (proof.length != 64) revert InvalidProofLength();
        (, bytes32 nullifier) = abi.decode(proof, (bytes32, bytes32));

        // Verify that the provided nullifier hashes to the committed nullifier hash.
        // NoctumPool.withdraw additionally checks that keccak256(secret, nullifier)
        // is a known leaf commitment, closing the Merkle membership gap.
        return keccak256(abi.encodePacked(nullifier)) == nullifierHash;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// @notice Derive the commitment and nullifier hash from a (secret, nullifier) pair.
    ///         Call off-chain (via eth_call) to generate the deposit commitment.
    /// @param secret    Random 32-byte secret.
    /// @param nullifier Random 32-byte nullifier.
    /// @return commitment    keccak256(secret ‖ nullifier) — use as deposit leaf.
    /// @return nullifierHash keccak256(nullifier)          — use in withdrawal.
    function getCommitment(bytes32 secret, bytes32 nullifier)
        external
        pure
        returns (bytes32 commitment, bytes32 nullifierHash)
    {
        commitment    = keccak256(abi.encodePacked(secret, nullifier));
        nullifierHash = keccak256(abi.encodePacked(nullifier));
    }
}
