// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPoseidonHasher
/// @author Noctum Protocol
/// @notice Interface for the on-chain Poseidon(2) hasher. The implementation is
///         deployed from circomlibjs-generated EVM bytecode, so its output is
///         bit-for-bit identical to the circomlib Poseidon used by the withdraw
///         circuit and the `poseidon-lite` library on the client. This shared
///         hash is what lets the on-chain Merkle tree, the in-circuit Merkle
///         check, and the client-side tree all agree on the same root.
interface IPoseidonHasher {
    /// @notice Poseidon hash of two field elements.
    /// @param input The two BN254 field elements [left, right].
    /// @return The Poseidon(left, right) field element.
    function poseidon(uint256[2] calldata input) external pure returns (uint256);
}
