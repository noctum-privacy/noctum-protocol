// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleTreeWithHistory
/// @author Noctum Protocol
/// @notice Incremental keccak256 Merkle tree that retains the last
///         ROOT_HISTORY_SIZE roots so withdrawals can use any recent root.
contract MerkleTreeWithHistory {

    // ── State ────────────────────────────────────────────────────────────────

    /// @notice Depth of the Merkle tree (max 32).
    uint32 public immutable levels;

    /// @notice Number of historic roots retained in the circular buffer.
    uint32 public constant ROOT_HISTORY_SIZE = 100;

    /// @notice Filled left-sibling hashes per level (updated on each insert).
    bytes32[32] public filledSubtrees;

    /// @notice Pre-computed zero hashes per level: zeros[i] = H(zeros[i-1], zeros[i-1]).
    bytes32[32] public zeros;

    /// @notice Circular buffer of the last ROOT_HISTORY_SIZE roots.
    bytes32[100] public roots;

    /// @notice Index of the most recently written root in the circular buffer.
    uint32 public currentRootIndex;

    /// @notice Number of leaves inserted so far (= next available index).
    uint32 public nextIndex;

    // ── Custom errors ────────────────────────────────────────────────────────

    /// @notice Tree depth must be between 1 and 32 inclusive.
    error InvalidLevels();

    /// @notice All 2^levels leaf slots are occupied.
    error MerkleTreeFull();

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @param _levels Depth of the tree (1–32). Capacity = 2^_levels leaves.
    constructor(uint32 _levels) {
        if (_levels == 0 || _levels > 32) revert InvalidLevels();
        levels = _levels;

        // Build zero values: zeros[0] = keccak256(0), zeros[i] = H(zeros[i-1], zeros[i-1])
        bytes32 currentZero = keccak256(abi.encodePacked(uint256(0)));
        zeros[0] = currentZero;
        for (uint32 i = 1; i < _levels; ++i) {
            currentZero = keccak256(abi.encodePacked(currentZero, currentZero));
            zeros[i] = currentZero;
        }

        for (uint32 i = 0; i < _levels; ++i) {
            filledSubtrees[i] = zeros[i];
        }

        roots[0] = keccak256(abi.encodePacked(currentZero, currentZero));
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// @notice Hash a left-right sibling pair.
    /// @param _left  Left child hash.
    /// @param _right Right child hash.
    /// @return Hash of the parent node.
    function hashLeftRight(bytes32 _left, bytes32 _right) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_left, _right));
    }

    /// @notice Insert a leaf and update the root history.
    /// @param _leaf The leaf value to insert.
    /// @return index The leaf index assigned to this insertion.
    function _insert(bytes32 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        if (_nextIndex == uint32(2) ** levels) revert MerkleTreeFull();

        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;

        for (uint32 i = 0; i < levels; ++i) {
            bytes32 left;
            bytes32 right;
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros[i];
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = hashLeftRight(left, right);
            currentIndex /= 2;
        }

        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /// @notice Check whether a root exists in the recent history buffer.
    /// @param _root The Merkle root to look up.
    /// @return True if _root is among the last ROOT_HISTORY_SIZE roots.
    function isKnownRoot(bytes32 _root) public view returns (bool) {
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
    /// @return The latest root hash.
    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }
}
