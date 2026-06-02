// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IPoseidonHasher } from "./IPoseidonHasher.sol";

/// @title PoseidonMerkleTreeWithHistory
/// @author Noctum Protocol
/// @notice Incremental fixed-depth Merkle tree over the Poseidon hash, retaining
///         the last ROOT_HISTORY_SIZE roots so a withdrawal may reference any
///         recent root. This is the on-chain counterpart of the client-side
///         MerkleTree in the workspace zk library and the MerkleTreeChecker
///         template in withdraw.circom. All three share ZERO_VALUE and the
///         Poseidon hasher, so the roots they compute are identical.
contract PoseidonMerkleTreeWithHistory {

    // ── Constants ──────────────────────────────────────────────────────────────

    /// @notice BN254 scalar field prime. All leaves must be strictly less.
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Empty-leaf value, pinned to keccak256("noctum") reduced into the
    ///         field. Must match ZERO_VALUE in the workspace zk constants.
    uint256 public constant ZERO_VALUE =
        21663839004416932945382355908790599225266501822907911457504978515578255421292;

    /// @notice Number of historic roots retained in the circular buffer.
    uint32 public constant ROOT_HISTORY_SIZE = 100;

    // ── State ──────────────────────────────────────────────────────────────────

    /// @notice The Poseidon(2) hasher contract (circomlib-compatible).
    IPoseidonHasher public immutable hasher;

    /// @notice Depth of the Merkle tree (max 32).
    uint32 public immutable levels;

    /// @notice Filled left-sibling hashes per level (updated on each insert).
    uint256[32] public filledSubtrees;

    /// @notice Pre-computed zero subtree roots per level: zeros[i] = H(zeros[i-1], zeros[i-1]).
    uint256[32] public zeros;

    /// @notice Circular buffer of the last ROOT_HISTORY_SIZE roots.
    uint256[100] public roots;

    /// @notice Index of the most recently written root in the circular buffer.
    uint32 public currentRootIndex;

    /// @notice Number of leaves inserted so far (= next available index).
    uint32 public nextIndex;

    // ── Custom errors ──────────────────────────────────────────────────────────

    /// @notice Tree depth must be between 1 and 32 inclusive.
    error InvalidLevels();

    /// @notice All 2^levels leaf slots are occupied.
    error MerkleTreeFull();

    // ── Constructor ────────────────────────────────────────────────────────────

    /// @param _levels Depth of the tree (1–32). Capacity = 2^_levels leaves.
    /// @param _hasher Address of the deployed Poseidon(2) hasher.
    constructor(uint32 _levels, IPoseidonHasher _hasher) {
        if (_levels == 0 || _levels > 32) revert InvalidLevels();
        levels = _levels;
        hasher = _hasher;

        // zeros[0] = ZERO_VALUE; zeros[i] = H(zeros[i-1], zeros[i-1])
        uint256 currentZero = ZERO_VALUE;
        zeros[0] = currentZero;
        filledSubtrees[0] = currentZero;

        for (uint32 i = 1; i < _levels; ++i) {
            currentZero = _hashLeftRight(_hasher, currentZero, currentZero);
            zeros[i] = currentZero;
            filledSubtrees[i] = currentZero;
        }

        // Root of an empty tree = H(zeros[levels-1], zeros[levels-1]).
        roots[0] = _hashLeftRight(_hasher, currentZero, currentZero);
    }

    // ── Internal ───────────────────────────────────────────────────────────────

    /// @notice Hash a left-right sibling pair with Poseidon.
    /// @dev `view` (not `pure`): the hash is computed by an external STATICCALL.
    /// @param _hasher The Poseidon hasher to call.
    /// @param _left   Left child field element.
    /// @param _right  Right child field element.
    /// @return The Poseidon(left, right) parent node.
    function _hashLeftRight(
        IPoseidonHasher _hasher,
        uint256 _left,
        uint256 _right
    ) internal view returns (uint256) {
        return _hasher.poseidon([_left, _right]);
    }

    /// @notice Insert a leaf and update the root history.
    /// @param _leaf The leaf value to insert (must be < FIELD_SIZE).
    /// @return index The leaf index assigned to this insertion.
    function _insert(uint256 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        if (_nextIndex == uint32(2) ** levels) revert MerkleTreeFull();

        uint32 currentIndex = _nextIndex;
        uint256 currentLevelHash = _leaf;

        for (uint32 i = 0; i < levels; ++i) {
            uint256 left;
            uint256 right;
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros[i];
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = _hashLeftRight(hasher, left, right);
            currentIndex /= 2;
        }

        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    // ── Views ──────────────────────────────────────────────────────────────────

    /// @notice Check whether a root exists in the recent history buffer.
    /// @param _root The Merkle root to look up.
    /// @return True if _root is among the last ROOT_HISTORY_SIZE roots.
    function isKnownRoot(uint256 _root) public view returns (bool) {
        if (_root == 0) return false;
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (_root == roots[i]) return true;
            if (i == 0) i = ROOT_HISTORY_SIZE;
            --i;
        } while (i != _currentRootIndex);
        return false;
    }

    /// @notice Returns the most recently computed Merkle root.
    /// @return The latest root field element.
    function getLastRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }
}
