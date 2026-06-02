// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVerifier
/// @author Noctum Protocol
/// @notice Interface for the ZK proof verifier.
///         Implementations may range from a simple commitment-reveal hash check
///         (Phase 1) to a full Groth16 on-chain verifier (Phase 2, Path B).
interface IVerifier {
    /// @notice Verify a withdrawal proof.
    /// @param root     Merkle root asserted by the prover.
    /// @param nullifierHash  keccak256 / Poseidon hash of the nullifier.
    /// @param recipient      Address that will receive the withdrawn ETH.
    /// @param proof          Encoded proof bytes (scheme-specific).
    /// @return valid  True if the proof is cryptographically valid.
    function verifyProof(
        bytes32 root,
        bytes32 nullifierHash,
        address recipient,
        bytes calldata proof
    ) external view returns (bool valid);
}
