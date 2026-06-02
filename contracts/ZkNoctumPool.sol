// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PoseidonMerkleTreeWithHistory } from "./PoseidonMerkleTreeWithHistory.sol";
import { IPoseidonHasher } from "./IPoseidonHasher.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IGroth16Verifier
/// @notice Interface for the snarkjs-generated Groth16 verifier. The signature
///         matches the auto-generated `Groth16Verifier.verifyProof`. Public
///         signal order is fixed by the circuit: [root, nullifierHash, recipient].
interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[3] calldata _pubSignals
    ) external view returns (bool);
}

/// @title ZkNoctumPool
/// @author Noctum Protocol
/// @notice Path B: fully trustless privacy pool. ETH is custodied by this
///         contract and released only when a valid Groth16 zero-knowledge proof
///         is verified ON-CHAIN by `Groth16Verifier`. No relayer or backend can
///         move funds; the only spend path is a sound proof of membership.
///
///         Privacy / security properties:
///           - Membership: proof attests the commitment is a leaf under a known
///             root, without revealing which leaf (unlinkability).
///           - Double-spend: each nullifierHash is recorded and spendable once.
///           - Front-running: `recipient` is bound inside the proof, so a copied
///             proof cannot be redirected to a different address.
///           - Reentrancy: OpenZeppelin ReentrancyGuard on deposit/withdraw.
///           - ETH transfer: low-level call (no 2300-gas restriction).
///
///         Flow:
///           1. Off-chain: pick nullifier + secret. commitment = Poseidon(nullifier, secret).
///           2. deposit(commitment) — send exactly `denomination` wei.
///           3. Wait for the anonymity set to grow.
///           4. From any wallet: generate a Groth16 proof in-browser and call
///              withdraw(...). The contract verifies it and pays `recipient`.
contract ZkNoctumPool is PoseidonMerkleTreeWithHistory, ReentrancyGuard {

    // ── Custom errors ──────────────────────────────────────────────────────────

    /// @notice msg.value must equal the pool denomination exactly.
    error WrongETHAmount();

    /// @notice Commitment must be a valid field element (< FIELD_SIZE).
    error CommitmentOutOfField();

    /// @notice This commitment was already deposited.
    error CommitmentAlreadySubmitted();

    /// @notice Recipient must not be the zero address.
    error RecipientIsZeroAddress();

    /// @notice This note has already been spent.
    error NoteAlreadySpent();

    /// @notice The provided Merkle root is not in the recent history.
    error UnknownMerkleRoot();

    /// @notice The Groth16 withdrawal proof failed on-chain verification.
    error InvalidProof();

    /// @notice ETH transfer to recipient failed.
    error TransferFailed();

    // ── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a commitment is deposited into the pool.
    /// @param commitment The Poseidon leaf commitment (field element).
    /// @param leafIndex  Position in the Merkle tree (insertion order).
    /// @param timestamp  Block timestamp of the deposit.
    event Deposit(uint256 indexed commitment, uint32 leafIndex, uint256 timestamp);

    /// @notice Emitted when a note is withdrawn via a valid ZK proof.
    /// @param to            Recipient address that received the ETH.
    /// @param nullifierHash The spent nullifier hash (field element).
    event Withdrawal(address indexed to, uint256 nullifierHash);

    // ── State ──────────────────────────────────────────────────────────────────

    /// @notice On-chain Groth16 proof verifier (immutable; sound trusted setup).
    IGroth16Verifier public immutable verifier;

    /// @notice Fixed ETH amount required per deposit / paid per withdrawal.
    uint256 public immutable denomination;

    /// @notice Tracks spent nullifier hashes to prevent double-spend.
    mapping(uint256 nullifierHash => bool spent) public nullifierHashes;

    /// @notice Tracks known leaf commitments deposited into the pool.
    mapping(uint256 commitment => bool exists) public commitments;

    // ── Constructor ────────────────────────────────────────────────────────────

    /// @param _verifier     Deployed Groth16Verifier address.
    /// @param _hasher       Deployed Poseidon(2) hasher address.
    /// @param _denomination Fixed ETH amount in wei (e.g. 0.001 ether).
    /// @param _levels       Merkle tree depth (20 = 1,048,576 slots).
    constructor(
        IGroth16Verifier _verifier,
        IPoseidonHasher _hasher,
        uint256 _denomination,
        uint32 _levels
    ) PoseidonMerkleTreeWithHistory(_levels, _hasher) {
        if (_denomination == 0) revert WrongETHAmount();
        verifier = _verifier;
        denomination = _denomination;
    }

    // ── Core: deposit ────────────────────────────────────────────────────────

    /// @notice Deposit ETH into the pool under a Poseidon commitment.
    /// @param _commitment Poseidon(nullifier, secret), computed off-chain.
    function deposit(uint256 _commitment) external payable nonReentrant {
        if (msg.value != denomination)     revert WrongETHAmount();
        if (_commitment >= FIELD_SIZE)     revert CommitmentOutOfField();
        if (commitments[_commitment])      revert CommitmentAlreadySubmitted();

        uint32 insertedIndex = _insert(_commitment);
        commitments[_commitment] = true;

        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    // ── Core: withdraw ─────────────────────────────────────────────────────────

    /// @notice Withdraw `denomination` ETH to `_recipient` against a ZK proof.
    /// @param _pA            Groth16 proof component A.
    /// @param _pB            Groth16 proof component B.
    /// @param _pC            Groth16 proof component C.
    /// @param _root          Merkle root the proof was generated against.
    /// @param _nullifierHash Poseidon(nullifier) — prevents double-spend.
    /// @param _recipient     Address to receive the ETH (bound in the proof).
    function withdraw(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256 _root,
        uint256 _nullifierHash,
        address payable _recipient
    ) external nonReentrant {
        if (_recipient == address(0))          revert RecipientIsZeroAddress();
        if (nullifierHashes[_nullifierHash])   revert NoteAlreadySpent();
        if (!isKnownRoot(_root))               revert UnknownMerkleRoot();

        // Public signals MUST match the circuit order: [root, nullifierHash, recipient].
        // recipient is bound as a field element (uint160 address widened to uint256).
        uint[3] memory pubSignals = [
            _root,
            _nullifierHash,
            uint256(uint160(address(_recipient)))
        ];

        if (!verifier.verifyProof(_pA, _pB, _pC, pubSignals)) revert InvalidProof();

        nullifierHashes[_nullifierHash] = true;

        (bool ok, ) = _recipient.call{value: denomination}("");
        if (!ok) revert TransferFailed();

        emit Withdrawal(_recipient, _nullifierHash);
    }

    // ── Views ──────────────────────────────────────────────────────────────────

    /// @notice Returns whether a nullifier has been spent.
    /// @param _nullifierHash The nullifier hash to query.
    /// @return spent True if already spent.
    function isSpent(uint256 _nullifierHash) external view returns (bool spent) {
        return nullifierHashes[_nullifierHash];
    }

    /// @notice Returns whether a commitment exists as a deposited leaf.
    /// @param _commitment The commitment to query.
    /// @return exists True if deposited.
    function isCommitmentKnown(uint256 _commitment) external view returns (bool exists) {
        return commitments[_commitment];
    }

    /// @notice Total ETH currently held by this pool.
    /// @return balance Pool balance in wei.
    function poolBalance() external view returns (uint256 balance) {
        return address(this).balance;
    }

    /// @notice Number of deposits recorded in this pool.
    /// @return count Deposit count (= next leaf index).
    function depositCount() external view returns (uint32 count) {
        return nextIndex;
    }

    // ── Fallback ─────────────────────────────────────────────────────────────

    /// @notice Reject accidental ETH sends. Use deposit().
    receive() external payable {
        revert("Use deposit()");
    }
}
