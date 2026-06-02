// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { NoctumPool } from "./NoctumPool.sol";
import { HashVerifier } from "./HashVerifier.sol";

/// @title NoctumPoolFactory
/// @author Noctum Protocol
/// @notice Deploys and tracks all NoctumPool instances for a single network.
///         One factory per network — stores addresses of all denomination pools.
contract NoctumPoolFactory {

    // ── Custom errors ────────────────────────────────────────────────────────

    /// @notice Only the operator may call this function.
    error NotOperator();

    /// @notice A pool for this denomination already exists.
    error PoolAlreadyExists();

    // ── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a new pool is deployed.
    /// @param pool         Address of the new NoctumPool.
    /// @param denomination Fixed ETH denomination in wei.
    /// @param label        Human-readable label (e.g. "0.01 ETH").
    event PoolCreated(
        address indexed pool,
        uint256 indexed denomination,
        string          label
    );

    // ── Structs ──────────────────────────────────────────────────────────────

    /// @notice Metadata for a deployed pool.
    struct PoolInfo {
        /// @notice Pool contract address.
        address pool;
        /// @notice ETH denomination in wei.
        uint256 denomination;
        /// @notice Human-readable label.
        string  label;
    }

    // ── State ────────────────────────────────────────────────────────────────

    /// @notice Address authorised to deploy new pools.
    address public immutable operator;

    /// @notice Shared verifier used by all pools deployed by this factory.
    address public immutable verifier;

    /// @notice Ordered list of all deployed pools.
    PoolInfo[] public pools;

    /// @notice Lookup from denomination (wei) to pool address.
    mapping(uint256 denomination => address pool) public poolByDenomination;

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @param _operator Address authorised to create pools.
    constructor(address _operator) {
        operator = _operator;
        verifier = address(new HashVerifier());
    }

    // ── Factory ──────────────────────────────────────────────────────────────

    /// @notice Deploy a new NoctumPool for a given ETH denomination.
    /// @param _denomination ETH amount in wei (must be unique per factory).
    /// @param _label        Human-readable label stored in PoolInfo.
    /// @return pool Address of the newly deployed NoctumPool.
    function createPool(
        uint256 _denomination,
        string calldata _label
    ) external returns (address pool) {
        if (msg.sender != operator)                       revert NotOperator();
        if (poolByDenomination[_denomination] != address(0)) revert PoolAlreadyExists();

        NoctumPool newPool = new NoctumPool(
            verifier,
            _denomination,
            20,       // 2^20 = 1 048 576 deposit slots
            operator
        );

        pool = address(newPool);
        pools.push(PoolInfo({ pool: pool, denomination: _denomination, label: _label }));
        poolByDenomination[_denomination] = pool;

        emit PoolCreated(pool, _denomination, _label);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /// @notice Returns metadata for all deployed pools.
    /// @return All PoolInfo structs in deployment order.
    function getAllPools() external view returns (PoolInfo[] memory) {
        return pools;
    }

    /// @notice Returns the pool address for a given denomination in wei.
    /// @param _denomination Denomination to look up.
    /// @return Pool address, or address(0) if not deployed.
    function getPool(uint256 _denomination) external view returns (address) {
        return poolByDenomination[_denomination];
    }
}
