# Noctum Protocol

Privacy infrastructure on Base (EVM L2) — anonymous fixed-denomination ETH transactions via cryptographic commitment schemes and ZK-SNARK proofs.

## Overview

Noctum breaks the on-chain transaction trail by allowing users to deposit ETH into a privacy pool under a cryptographic commitment, wait for the anonymity set to grow, then withdraw to a fresh address using a proof of knowledge — without revealing which deposit is being spent.

**Chain:** Base mainnet (chainId 8453)  
**Domain:** noctum.io

## Architecture

```
NoctumPoolFactory
└── NoctumPool (per denomination)
    ├── MerkleTreeWithHistory   — incremental keccak256 Merkle tree (20 levels, 1M slots)
    ├── HashVerifier            — Phase 1: commitment-reveal proof (keccak256)
    └── IVerifier               — interface; swap to Groth16 verifier for Phase 2 on-chain
```

## ZK Circuit

`zk/circuits/withdraw.circom` — Groth16 circuit (bn128, 20-level Poseidon Merkle tree):

- **CommitmentHasher**: `commitment = Poseidon(secret, nullifier)`, `nullifierHash = Poseidon(nullifier)`
- **MerkleTreeChecker**: 20-level inclusion proof against a committed root
- **Recipient binding**: constrains the recipient address to prevent front-running
- **Public signals**: `[root, nullifierHash, recipient]`

Trusted setup: Hermez powers-of-tau (2^15), Groth16 final zkey via `snarkjs`.  
Verification key: `zk/verification_key.json`.

## Smart Contracts

| Contract | Description |
|---|---|
| `NoctumPool.sol` | Core privacy pool — deposit, withdraw, fee management |
| `MerkleTreeWithHistory.sol` | Incremental Merkle tree with 100-root history buffer |
| `HashVerifier.sol` | Phase 1 commitment-reveal verifier |
| `NoctumPoolFactory.sol` | Deploys and indexes denomination pools |
| `IVerifier.sol` | Verifier interface |

## Security

All findings from the internal audit have been remediated before this release:

| ID | Severity | Finding | Status |
|---|---|---|---|
| C-01 | CRITICAL | HashVerifier missing Merkle membership check | Fixed — `NoctumPool.withdraw()` validates `commitments[commitment]` |
| H-01 | HIGH | `updateVerifier` had no timelock | Fixed — two-step upgrade with `VERIFIER_UPDATE_DELAY = 2 days` |
| H-02 | HIGH | `.transfer()` 2300 gas limit | Fixed — replaced with `.call{value}()` |
| H-03 | MEDIUM | Missing events on admin functions | Fixed — `VerifierUpdated`, `FeeBpsUpdated` events added |
| M-01 | MEDIUM | `commitments[]` unused in withdrawal | Fixed — membership check added (C-01 fix) |

Full report: [SECURITY_AUDIT.md](./SECURITY_AUDIT.md)

## Build

```bash
# Install dependencies
cd contracts && npm install

# Compile contracts
npx hardhat compile

# Run Solidity linter
npx solhint 'contracts/**/*.sol'

# Deploy to Base
DEPLOYER_PRIVATE_KEY=0x... npx hardhat run scripts/deploy.ts --network base
```

## License

MIT
