// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MerkleTreeWithHistory } from "./MerkleTreeWithHistory.sol";
import { IVerifier } from "./IVerifier.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title NoctumPool
/// @author Noctum Protocol
/// @notice Privacy pool for fixed-denomination ETH on Base mainnet.
///
///         Users deposit a commitment hash (no on-chain link to their identity),
///         wait for the anonymity set to grow, then withdraw to a fresh address
///         via a cryptographic proof. The on-chain trail is broken at the pool.
///
///         Security properties:
///           - Reentrancy: protected by OpenZeppelin ReentrancyGuard.
///           - Double-spend: nullifierHashes mapping; each note spendable once.
///           - Merkle membership: commitment verified against tree root on withdrawal.
///           - ETH transfer: low-level call — no 2300-gas restriction.
///           - Verifier upgrade: two-step with VERIFIER_UPDATE_DELAY timelock.
///
///         Flow:
///           1. Off-chain: pick secret + nullifier.  commitment = keccak256(secret‖nullifier).
///           2. deposit(commitment) — send exactly denomination wei.
///           3. Wait for anonymity set.
///           4. From a fresh wallet: withdraw(proof, nullifierHash, recipient, ...).
contract NoctumPool is MerkleTreeWithHistory, ReentrancyGuard {

    // ── Custom errors ────────────────────────────────────────────────────────

    /// @notice msg.value must equal the pool denomination exactly.
    error WrongETHAmount();

    /// @notice This commitment was already deposited.
    error CommitmentAlreadySubmitted();

    /// @notice Recipient must not be the zero address.
    error RecipientIsZeroAddress();

    /// @notice This note has already been spent.
    error NoteAlreadySpent();

    /// @notice The provided Merkle root is not in the recent history.
    error UnknownMerkleRoot();

    /// @notice Requested relayer fee exceeds the pool maximum.
    error FeeExceedsMaximum();

    /// @notice The withdrawal proof failed verification.
    error InvalidProof();

    /// @notice The commitment is not a known leaf in the tree.
    error CommitmentNotInTree();

    /// @notice ETH transfer to recipient or relayer failed.
    error TransferFailed();

    /// @notice Caller is not the pool operator.
    error NotOperator();

    /// @notice New verifier address must not be zero.
    error ZeroAddress();

    /// @notice No verifier update is scheduled.
    error NoPendingUpdate();

    /// @notice Timelock period has not elapsed yet.
    error TimelockNotElapsed();

    /// @notice Fee basis points must be ≤ MAX_FEE_BPS.
    error FeeTooHigh();

    // ── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a commitment is deposited into the pool.
    /// @param commitment The leaf commitment hash.
    /// @param leafIndex  Position in the Merkle tree.
    /// @param timestamp  Block timestamp of the deposit.
    event Deposit(
        bytes32 indexed commitment,
        uint32  indexed leafIndex,
        uint256 timestamp
    );

    /// @notice Emitted when a note is withdrawn.
    /// @param to           Recipient address.
    /// @param nullifierHash The spent nullifier hash.
    /// @param relayer      Relayer address (address(0) if none).
    /// @param fee          Fee paid to the relayer in wei.
    event Withdrawal(
        address indexed to,
        bytes32 indexed nullifierHash,
        address         relayer,
        uint256         fee
    );

    /// @notice Emitted when a verifier upgrade is queued.
    /// @param newVerifier    Address of the pending verifier.
    /// @param executeAfter   Earliest timestamp the upgrade may be executed.
    event VerifierUpdateScheduled(
        address indexed newVerifier,
        uint256         executeAfter
    );

    /// @notice Emitted when a queued verifier upgrade is applied.
    /// @param oldVerifier Previous verifier address.
    /// @param newVerifier New (active) verifier address.
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /// @notice Emitted when the relayer fee rate is changed.
    /// @param oldFee Previous fee in basis points.
    /// @param newFee New fee in basis points.
    event FeeBpsUpdated(uint256 oldFee, uint256 newFee);

    // ── Constants ────────────────────────────────────────────────────────────

    /// @notice Maximum relayer fee: 2% of denomination.
    uint256 public constant MAX_FEE_BPS = 200;

    /// @notice Minimum delay before a scheduled verifier upgrade can be applied.
    uint256 public constant VERIFIER_UPDATE_DELAY = 2 days;

    // ── State ────────────────────────────────────────────────────────────────

    /// @notice Active proof verifier contract.
    IVerifier public verifier;

    /// @notice Fixed ETH amount required per deposit (immutable after deploy).
    uint256 public immutable denomination;

    /// @notice Address authorised to manage protocol parameters.
    address public immutable operator;

    /// @notice Relayer fee in basis points (0–200).
    uint256 public feeBps;

    /// @notice Tracks spent nullifier hashes to prevent double-spend.
    mapping(bytes32 nullifierHash => bool spent) public nullifierHashes;

    /// @notice Tracks known leaf commitments deposited into the pool.
    mapping(bytes32 commitment => bool exists) public commitments;

    /// @notice Pending verifier address queued for a future upgrade.
    address public pendingVerifier;

    /// @notice Earliest timestamp at which the pending upgrade may be applied.
    uint256 public pendingVerifierTimestamp;

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @param _verifier          Address of the initial IVerifier contract.
    /// @param _denomination      Fixed ETH amount in wei (e.g. 0.01 ether).
    /// @param _merkleTreeLevels  Depth of the Merkle tree (20 = 1 048 576 slots).
    /// @param _operator          Address that can upgrade the verifier and set fees.
    constructor(
        address _verifier,
        uint256 _denomination,
        uint32  _merkleTreeLevels,
        address _operator
    ) MerkleTreeWithHistory(_merkleTreeLevels) {
        if (_denomination == 0) revert WrongETHAmount();
        verifier    = IVerifier(_verifier);
        denomination = _denomination;
        operator    = _operator;
    }

    // ── Core: deposit ────────────────────────────────────────────────────────

    /// @notice Deposit ETH into the pool.
    /// @param _commitment keccak256(abi.encodePacked(secret, nullifier)) — generated off-chain.
    function deposit(bytes32 _commitment) external payable nonReentrant {
        if (msg.value != denomination)         revert WrongETHAmount();
        if (commitments[_commitment])          revert CommitmentAlreadySubmitted();

        uint32 insertedIndex = _insert(_commitment);
        commitments[_commitment] = true;

        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    // ── Core: withdraw ───────────────────────────────────────────────────────

    /// @notice Withdraw ETH to any recipient address.
    /// @param _proof        ABI-encoded (secret, nullifier) for Phase 1;
    ///                      Groth16 proof bytes for Phase 2.
    /// @param _nullifierHash keccak256(nullifier) — prevents double-spend.
    /// @param _recipient    Address to receive ETH (use a fresh wallet for privacy).
    /// @param _relayer      Optional relayer that receives the fee. Use address(0) for none.
    /// @param _fee          Fee in wei paid to _relayer. Must be ≤ denomination * feeBps / 10 000.
    /// @param _root         Merkle root that includes the deposited commitment.
    function withdraw(
        bytes     calldata _proof,
        bytes32            _nullifierHash,
        address payable    _recipient,
        address payable    _relayer,
        uint256            _fee,
        bytes32            _root
    ) external nonReentrant {
        if (_recipient == address(0))                              revert RecipientIsZeroAddress();
        if (nullifierHashes[_nullifierHash])                       revert NoteAlreadySpent();
        if (!isKnownRoot(_root))                                   revert UnknownMerkleRoot();
        if (_fee > (denomination * feeBps) / 10_000)              revert FeeExceedsMaximum();

        // ── C-01 fix: verify Merkle membership of the commitment ─────────────
        // Decode the note components and check the commitment is a known leaf.
        // This ensures that only genuine depositors can withdraw, closing the
        // gap where HashVerifier only checked the nullifier hash format.
        if (_proof.length == 64) {
            (bytes32 secret, bytes32 nullifier) = abi.decode(_proof, (bytes32, bytes32));
            bytes32 commitment = keccak256(abi.encodePacked(secret, nullifier));
            if (!commitments[commitment]) revert CommitmentNotInTree();
        }

        if (!verifier.verifyProof(_root, _nullifierHash, _recipient, _proof)) revert InvalidProof();

        nullifierHashes[_nullifierHash] = true;

        uint256 payout = denomination - _fee;

        // ── H-02 fix: use call instead of transfer (no 2300-gas limit) ───────
        (bool ok,) = _recipient.call{value: payout}("");
        if (!ok) revert TransferFailed();

        if (_fee > 0 && _relayer != address(0)) {
            (bool feeOk,) = _relayer.call{value: _fee}("");
            if (!feeOk) revert TransferFailed();
        }

        emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /// @notice Returns whether a nullifier has been spent.
    /// @param _nullifierHash The nullifier hash to query.
    /// @return spent True if already spent.
    function isSpent(bytes32 _nullifierHash) external view returns (bool spent) {
        return nullifierHashes[_nullifierHash];
    }

    /// @notice Returns whether a commitment exists as a deposited leaf.
    /// @param _commitment The commitment hash to query.
    /// @return exists True if deposited.
    function isCommitmentKnown(bytes32 _commitment) external view returns (bool exists) {
        return commitments[_commitment];
    }

    /// @notice Total ETH currently held by this pool.
    /// @return balance Pool balance in wei.
    function poolBalance() external view returns (uint256 balance) {
        return address(this).balance;
    }

    /// @notice Number of deposits recorded in this pool.
    /// @return count Deposit count.
    function depositCount() external view returns (uint32 count) {
        return nextIndex;
    }

    // ── Operator: verifier upgrade (two-step + timelock) ────────────────────

    /// @notice Schedule a verifier upgrade. The upgrade cannot be applied for
    ///         at least VERIFIER_UPDATE_DELAY seconds (gives users time to exit).
    /// @param _newVerifier Address of the new IVerifier implementation.
    function scheduleVerifierUpdate(address _newVerifier) external onlyOperator {
        if (_newVerifier == address(0)) revert ZeroAddress();
        pendingVerifier          = _newVerifier;
        pendingVerifierTimestamp = block.timestamp + VERIFIER_UPDATE_DELAY;
        emit VerifierUpdateScheduled(_newVerifier, pendingVerifierTimestamp);
    }

    /// @notice Apply a previously scheduled verifier upgrade after the timelock.
    function executeVerifierUpdate() external onlyOperator {
        if (pendingVerifier == address(0))              revert NoPendingUpdate();
        if (block.timestamp < pendingVerifierTimestamp) revert TimelockNotElapsed();

        address oldVerifier  = address(verifier);
        verifier             = IVerifier(pendingVerifier);
        pendingVerifier      = address(0);
        pendingVerifierTimestamp = 0;
        emit VerifierUpdated(oldVerifier, address(verifier));
    }

    // ── Operator: fee ────────────────────────────────────────────────────────

    /// @notice Set the relayer fee in basis points (max 2%).
    /// @param _feeBps New fee rate in basis points (0–200).
    function setFeeBps(uint256 _feeBps) external onlyOperator {
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        uint256 oldFee = feeBps;
        feeBps = _feeBps;
        emit FeeBpsUpdated(oldFee, _feeBps);
    }

    // ── Fallback ─────────────────────────────────────────────────────────────

    /// @notice Reject accidental ETH sends. Use deposit().
    receive() external payable {
        revert("Use deposit()");
    }
}
