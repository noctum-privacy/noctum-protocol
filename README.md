# Noctum Protocol

Privacy infrastructure on Base (Ethereum L2). Anonymous ETH transfers using Groth16 ZK-SNARKs — every withdrawal is proven on-chain by a deployed Verifier contract before any funds move.

**Live:** https://noctum.io  
**Network:** Base Mainnet (chainId 8453)  
**Transparency:** https://noctum.io/transparency

---

## What It Does

Noctum lets you deposit ETH into a fixed-denomination pool and withdraw it to a different address with no on-chain link between the two. The unlinkability is enforced by a real zero-knowledge proof — not a mixer, not a multisig, not a commit-reveal scheme.

**Phase 1** — keccak commitment pools (on-chain, legacy)  
**Phase 2** — Groth16 ZK-SNARK pools (live on Base mainnet, described below)

---

## ZK Circuit

**File:** `zk/circuits/withdraw.circom`  
**Compiler:** circom 2.0+  
**Library:** circomlib (Poseidon)  
**SHA-256:** `9b3893257327939a0b1bdbbf1c37e7a4de232462f8993657209dfa7eda8ae6ea`

```circom
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

// commitment = Poseidon(nullifier, secret)
// nullifierHash = Poseidon(nullifier)
template CommitmentHasher() { ... }

// 20-level binary Merkle tree using Poseidon(2) at each node
template MerkleTreeChecker(levels) { ... }

template Withdraw(levels) {
    // Public signals
    signal input root;          // known Merkle root
    signal input nullifierHash; // prevents double-spend
    signal input recipient;     // bound into proof — prevents front-running

    // Private witnesses
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    ...
}

component main {public [root, nullifierHash, recipient]} = Withdraw(20);
```

**Public signal order:** `[root, nullifierHash, uint256(uint160(recipient))]`  
**Tree depth:** 20 levels (capacity: 2^20 = 1,048,576 leaves)  
**Hash function:** Poseidon — ZK-native, ~3× cheaper in-circuit than Keccak

---

## Trusted Setup

| File | Size | SHA-256 |
|---|---|---|
| `artifacts/noctum/public/zk/withdraw.zkey` | 5.0 MB | `9dcd801511ddba60efb27ddf0f40be91159bfa4e6115a51f6f5b4df4dc0b0935` |
| `artifacts/noctum/public/zk/withdraw.wasm` | 2.0 MB | `1a6a796064112b9f61281d88c5212a3012a5f51d3d4f989b14f2cc25f2b32af6` |
| `zk/verification_key.json` | — | protocol: groth16, curve: bn128, nPublic: 3 |

**Powers of Tau:** Hermez ceremony (2^15) — publicly verifiable ptau from the Hermez network trusted setup.  
**Caveat:** This is a single-party zkey derived from the Hermez ptau. A multi-party Phase 2 ceremony would provide stronger guarantees. Deposits should be sized accordingly until a ceremony is organized.

You can verify the zkey against the ptau and r1cs yourself:

```bash
snarkjs groth16 verify zk/verification_key.json public.json proof.json
```

---

## Deployed Contracts — Base Mainnet

All contracts are verified on BaseScan. There is no owner, no pause switch, and no upgrade path.

| Contract | Address | BaseScan |
|---|---|---|
| Groth16Verifier | `0x1C0E08B443f383da890CFB0f67836C974b02E969` | [view](https://basescan.org/address/0x1C0E08B443f383da890CFB0f67836C974b02E969) |
| PoseidonHasher | `0x0515b6E0407D78F7E49bd3D2f408c0efA6BCC3dd` | [view](https://basescan.org/address/0x0515b6E0407D78F7E49bd3D2f408c0efA6BCC3dd) |
| ZkNoctumPool 0.001 ETH | `0x676aCaBB6B599D7F699B8058b675816be346d24D` | [view](https://basescan.org/address/0x676aCaBB6B599D7F699B8058b675816be346d24D) |
| ZkNoctumPool 0.005 ETH | `0xB93000D0eb8559C2202Ca047FF1c7d5A8e569ed0` | [view](https://basescan.org/address/0xB93000D0eb8559C2202Ca047FF1c7d5A8e569ed0) |
| ZkNoctumPool 0.01 ETH  | `0x8F7927de1461e822D396bfC551244B5fd13304d5` | [view](https://basescan.org/address/0x8F7927de1461e822D396bfC551244B5fd13304d5) |
| ZkNoctumPool 0.1 ETH   | `0x749621fbD86250c103F2219Acea4F5FbF4241eA0` | [view](https://basescan.org/address/0x749621fbD86250c103F2219Acea4F5FbF4241eA0) |
| ZkNoctumPool 1.0 ETH   | `0xE9b3F084a46219d75534015b4b0950220b373C82` | [view](https://basescan.org/address/0xE9b3F084a46219d75534015b4b0950220b373C82) |

Deployed by: `0x4DA175C235f4251A88d84C46ba330a33889f8508`  
Deployed at: 2026-06-02

---

## Smart Contracts

```
contracts/contracts/
├── Groth16Verifier.sol              # snarkjs-generated Groth16 on-chain verifier (bn128)
├── ZkNoctumPool.sol                 # Phase 2 pool — deposit ETH, withdraw with ZK proof
├── PoseidonMerkleTreeWithHistory.sol # On-chain Poseidon Merkle tree, 100-root history
├── IPoseidonHasher.sol              # Interface for the deployed Poseidon hasher
├── IVerifier.sol                    # Interface for the Groth16 verifier
├── NoctumPool.sol                   # Phase 1 pool (keccak commitment)
├── MerkleTreeWithHistory.sol        # Phase 1 keccak Merkle tree
├── HashVerifier.sol                 # Phase 1 verifier
└── NoctumPoolFactory.sol            # Phase 1 factory
```

**`ZkNoctumPool.sol` key functions:**

```solidity
// Deposit: appends a Poseidon commitment as a leaf
function deposit(uint256 commitment) external payable;

// Withdraw: verifies Groth16 proof on-chain, marks nullifier spent, sends ETH
function withdraw(
    uint256[2] calldata pA,
    uint256[2][2] calldata pB,
    uint256[2] calldata pC,
    uint256 root,
    uint256 nullifierHash,
    address payable recipient
) external nonReentrant;
```

Security properties enforced in the contract:
- `nonReentrant` (OpenZeppelin) on all state-changing functions
- Nullifier marked spent **before** ETH transfer (checks-effects-interactions)
- Recipient is a public signal — the proof is bound to the specific recipient address, preventing front-running
- Root must exist in the 100-root history (deposits from up to 100 blocks ago are valid)
- No owner, no pause, no upgrade — contract is immutable after deployment

---

## ZK Flow

```
DEPOSIT
  user generates: nullifier (random), secret (random)
  commitment = Poseidon(nullifier, secret)         ← private
  user calls: pool.deposit(commitment) + msg.value
  contract: appends leaf to on-chain Poseidon tree

WITHDRAW (different wallet, no link)
  user fetches all Deposit events → rebuilds Merkle tree locally
  nullifierHash = Poseidon(nullifier)
  user calls: snarkjs.groth16.fullProve(witness, withdraw.wasm, withdraw.zkey)
    → generates proof + public signals [root, nullifierHash, recipient]
  user submits proof to pool.withdraw(pA, pB, pC, root, nullifierHash, recipient)
  contract: calls Groth16Verifier.verifyProof(...) — REVERT if invalid
  contract: checks nullifierHash not spent, root in history
  contract: marks nullifierHash spent, sends ETH to recipient
```

The backend/API **never** sees the nullifier or the Merkle path. The client builds the tree from on-chain events, so the backend cannot correlate deposit → withdrawal.

---

## snarkjs Integration

**Version:** snarkjs `^0.7.6` — used in both frontend and backend.

**Frontend** (`artifacts/noctum/src/components/ZkPhase2.tsx`):
- Proof generation runs in-browser via `snarkjs.groth16.fullProve`
- WASM and zkey are served at `/zk/withdraw.{wasm,zkey}` from the frontend public folder
- No server-side proving — the user's browser proves membership without revealing the leaf

**Backend** (`artifacts/api-server/src/routes/zk.ts`):
- `snarkjs.groth16.verify(vkey, publicSignals, proof)` — off-chain double-check before recording settlement
- `snarkjs` kept external in esbuild config to prevent worker thread re-execution

---

## Automated Security Analysis

Run on the Solidity contracts using two independent tools. Results are published at https://noctum.io/transparency.

| Tool | Vendor | Scope | Outcome |
|---|---|---|---|
| Slither | Trail of Bits | 12 contracts, 101 detectors | No confirmed exploitable issue after manual triage |
| Aderyn | Cyfrin | 9 contracts, 88 detectors | No confirmed exploitable issue after manual triage |
| circomspect | Trail of Bits | Circom circuit | Pending — binary unavailable in CI env |

High-severity flags (all expected):
- `arbitrary-send-eth` — recipient is bound inside the ZK proof as a public signal; ETH destination is cryptographically fixed at proof time
- `incorrect-return` / Yul assembly — inside the snarkjs auto-generated `Groth16Verifier.sol`; this is standard Groth16 pairing check assembly
- `reentrancy` — flagged against the `verifyProof` call; guarded by `nonReentrant` and nullifier-spent-before-transfer pattern

Raw reports: `slither-report.json`, `aderyn-report.md`

**These are automated tools. They do not replace a manual audit by a security firm. A third-party audit is on the roadmap.**

---

## Repository Structure

```
.
├── contracts/                  # Hardhat project
│   ├── contracts/              # Solidity source (Phase 1 + Phase 2)
│   ├── scripts/                # Deploy scripts
│   ├── test/                   # Contract tests
│   ├── zk-deployments.json     # Deployed addresses (Base mainnet)
│   └── hardhat.config.ts
├── zk/
│   ├── circuits/
│   │   └── withdraw.circom     # ZK circuit (Poseidon + Merkle + nullifier)
│   └── verification_key.json   # Groth16 verification key (bn128)
├── artifacts/
│   ├── noctum/                 # React + Vite frontend
│   │   └── public/zk/
│   │       ├── withdraw.wasm   # Circuit witness generator (2.0 MB)
│   │       └── withdraw.zkey   # Groth16 proving key (5.0 MB)
│   └── api-server/             # Express API server
│       └── src/routes/zk.ts    # ZK deposit/withdraw/tree endpoints
├── lib/
│   ├── db/                     # Drizzle ORM schema + client
│   └── api-spec/               # OpenAPI spec + codegen
├── slither-report.json         # Full Slither static analysis output
└── aderyn-report.md            # Full Aderyn static analysis report
```

---

## Build & Run

**Requirements:** Node.js 20+, pnpm 9+

```bash
pnpm install

# Run API server (port 8080)
pnpm --filter @workspace/api-server run dev

# Run frontend (port auto-assigned)
pnpm --filter @workspace/noctum run dev

# Typecheck everything
pnpm run typecheck

# Push DB schema changes (dev)
pnpm --filter @workspace/db run push

# Regenerate API hooks from OpenAPI spec
pnpm --filter @workspace/api-spec run codegen
```

**Required env vars:**

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `DEPLOYER_PRIVATE_KEY` | Only needed for contract deployment |

---

## Stack

| Layer | Technology |
|---|---|
| Network | Base Mainnet (chainId 8453, Ethereum L2) |
| ZK proof system | Groth16 (bn128) via snarkjs 0.7.6 |
| Circuit | circom 2.0, circomlib Poseidon |
| Contracts | Solidity 0.8.24, Hardhat, OpenZeppelin |
| Frontend | React, Vite, TypeScript, Tailwind CSS, wagmi |
| Backend | Express 5, TypeScript, Drizzle ORM, PostgreSQL |
| Codegen | Orval (OpenAPI → React Query hooks + Zod schemas) |

---

## Security Disclosures

- No third-party manual audit has been completed yet.
- The trusted setup uses Hermez ptau (public, multi-party) for the universal phase; the circuit-specific phase was run locally (single-party). Real multi-party ceremony is on the roadmap.
- Contracts are immutable — no admin key, no pause, no upgrade path.
- Bug reports: open a GitHub issue or contact via https://noctum.io

---

## License

MIT
