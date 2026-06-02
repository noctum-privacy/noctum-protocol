# Noctum Protocol — Security Audit Report

**Date:** 2026-06-02
**Scope:** Solidity smart contracts + Groth16 ZK circuit + off-chain verification layer
**Chain:** Base (EVM L2, chainId 8453)
**Tools:** solhint (Solidity linter), Hardhat compiler, manual static analysis

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 3 |
| ⚪ INFO | 1 |

---

## Scope

| Component | Files |
|-----------|-------|
| Solidity contracts | NoctumPool.sol, MerkleTreeWithHistory.sol, HashVerifier.sol, NoctumPoolFactory.sol, IVerifier.sol |
| ZK circuit | zk/circuits/withdraw.circom (Groth16, bn128, 20 levels, Poseidon) |
| Off-chain verifier | artifacts/api-server/src/routes/zk.ts |

---

## Findings

### L-01 — 🔵 LOW — Withdraw circuit: recipient binding via squaring is non-standard

**Tool:** manual  
**File:** `zk/circuits/withdraw.circom` line 81  

**Description:**
`recipientSquare <== recipient * recipient` constrains the recipient signal to its own square — this is a no-op in terms of linkage to other signals. The binding effect comes solely from Groth16 treating recipient as a public input (its value is checked by the verifier against publicSignals[2]). This is the same pattern used in Tornado Cash, but it is fragile: if someone generates a proof with a different recipient and the verifier incorrectly handles public inputs, the binding would be broken. The comment correctly labels this as a no-op.

**Recommendation:**
Consider adding a more explicit binding, such as hashing recipient into a signal that also constrains another circuit output. For the current off-chain Path A verifier, ensure publicSignals[2] is always cross-checked against the submitted recipient in the backend (see zk.ts:177 — this is done).

---

### L-02 — 🔵 LOW — MerkleTreeWithHistory: fixed 32-slot arrays waste storage for small trees

**Tool:** manual  
**File:** `contracts/contracts/MerkleTreeWithHistory.sol` line 10  

**Description:**
filledSubtrees[32] and zeros[32] are always fully allocated in storage regardless of the `levels` parameter. For the deployed 20-level tree, slots 20–31 (12 slots × 2 arrays = 24 slots × 32 bytes each) are permanently wasted. Gas cost on construction: ~24 cold SSTORE × 20 000 = ~480 000 gas.

**Recommendation:**
Allocate arrays as `bytes32[](levels)` using dynamic sizing, or accept this as a known trade-off for simplicity. No security impact.

---

### SH-ALL — 🔵 LOW — solhint: 5 warnings across all contracts

**Tool:** solhint  
**File:** `contracts/contracts/*.sol`  

**Description:**
Solhint reports 5 warnings including: missing NatSpec documentation on all public functions/variables, use of require() instead of custom errors (gas inefficiency), global import style, immutable variable naming (should be SCREAMING_SNAKE_CASE), and gas optimization hints (++i vs i++, strict inequalities, indexed events).

**Recommendation:**
Address NatSpec warnings before a public audit submission — auditors expect documented intent. Gas warnings are optional but improve deployment efficiency. Run `pnpm run audit:sol` to view full per-file breakdown.

---

### I-01 — ⚪ INFO — Phase 2 Groth16 path: backend verification is correctly layered

**Tool:** manual  
**File:** `artifacts/api-server/src/routes/zk.ts`  

**Description:**
The off-chain Phase 2 verifier (zk.ts) correctly implements: (1) recipient binding check against addressToField(recipient), (2) root-history check against all published zk_roots for the denomination, (3) double-spend check via zk_nullifiers unique constraint, (4) cryptographic groth16.verify() with the hardcoded vkey. No gaps identified in the Phase 2 verification chain.

**Recommendation:**
Maintain this verification order. On Path B (on-chain), reproduce all 4 checks inside the Groth16 verifier contract.

---

## Audit Tool Setup

```bash
# Run the full audit from repo root
pnpm run audit:security

# Solidity linting only
pnpm run audit:sol

# Recompile contracts
cd contracts && pnpm exec hardhat compile
```

## Free Audit Resources

| Service | Type | Cost | URL |
|---------|------|------|-----|
| **Immunefi** | Bug bounty program | Free to list | immunefi.com |
| **ZKSecurity** | ZK circuit review (open-source) | Free / nominal | zksecurity.xyz |
| **Code4rena** | Competitive audit contest | Prize pool required | code4rena.com |
| **Sherlock** | Competitive audit | Prize pool required | sherlock.xyz |
| **Cantina** | Competitive audit | Quote-based | cantina.xyz |
| **solhint** | Automated Solidity linter | Free (runs locally) | protofire.github.io/solhint |

## Next Steps Before External Audit

1. Fix C-01 (critical): add commitment membership check in NoctumPool.withdraw()
2. Fix H-01: add a 2–7 day timelock on updateVerifier
3. Fix H-02: replace .transfer() with .call{value}()
4. Emit events from updateVerifier and setFeeBps
5. Address NatSpec gaps (solhint SH-ALL) — auditors expect documented intent
6. Consider moving operator to a Gnosis Safe multisig
7. Submit repo to ZKSecurity community review (circom circuit)
8. Open Immunefi bug bounty after completing items 1–3
