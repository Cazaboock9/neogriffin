# 🛡️ NeoGriffin — Multi-Chain Security API for AI Agents

Security-as-a-service for the OpenClaw ecosystem. Protects AI agents and their users from scam tokens, prompt injection, malicious skills, and wallet threats on **Solana** and **Base**.

**Live server:** `http://164.92.188.91:3847`

## What It Does

NeoGriffin gives AI agents the ability to protect themselves. Before an agent swaps a token, installs a skill, or processes user input — NeoGriffin scans it first.

**Token Auditing** — Deep security analysis on Solana (Helius + DexScreener) and Base (GoPlus + DexScreener). Checks liquidity, holder concentration, mint/freeze authority, honeypot detection, and rug pull indicators.

**Prompt Injection Detection** — 193 patterns across critical, high, and medium severity. Includes unicode normalization to defeat evasion techniques (cyrillic substitution, HTML entities, hex encoding).

**Skill Supply Chain Scanner** — Analyzes OpenClaw skills before installation. Detects eval/exec, base64 obfuscation, hardcoded wallet addresses, credential theft (PRIVATE_KEY, SEED_PHRASE), unauthorized network calls, and hidden prompt injection in skill descriptions.

**NFT Threat Scanner** — Scans wallet NFT collections for phishing links, metadata injection, fake domains, and unverified creators/collections.

**Wallet Monitor** — 24/7 monitoring with 7 detection rules: large transfers, token approvals, authority changes, account closures, batch drains, unknown program interactions, and memo injection.

**Community Reports** — Crowdsourced threat intelligence with duplicate prevention and reputation tracking.

## OpenClaw Vulnerabilities Addressed

NeoGriffin directly addresses 5 critical OpenClaw security gaps:

1. **Prompt Injection** — 193 pattern detection engine with evasion protection
2. **Memory Poisoning** — Scans data inputs for hidden instructions
3. **Credential Exposure** — No private keys required; x402 handles payments client-side
4. **Excessive Agency** — Risk scoring before any agent action
5. **Skill Supply Chain** — Code + injection analysis before skill installation

## Endpoints

### Free Tier
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Prompt injection detection |
| `/api/stats` | GET | Network statistics |
| `/api/token/:mint/status` | GET | Community report status |
| `/api/token/report` | POST | Report suspicious token |
| `/api/nft/scan` | POST | NFT collection scan |
| `/api/nft/:mint` | GET | Single NFT scan |
| `/api/watcher/alerts` | GET | Wallet monitoring alerts |
| `/api/watcher/status` | GET | Watcher status |

### Paid Tier ($0.10 USDC / 5 SURGE)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/audit/solana` | POST | Full Solana token audit |
| `/api/audit/base` | POST | Full Base token audit |
| `/api/watcher/register` | POST | Register wallet for monitoring |
| `/api/scan/skill` | POST | Skill supply chain scanner |

### Agent API
| Endpoint | Price | Description |
|----------|-------|-------------|
| `/v1/score` | $0.01 / 0.05 SURGE | Single token safety score |
| `/v1/batch-score` | $0.05 / 0.25 SURGE | Batch scoring (up to 10) |

## Payment

Dual payment system — choose either:

**x402 (USDC):** Send request → receive 402 + payment details → pay via facilitator → resend with proof.

**SURGE Token:** Send SURGE to server wallet on Solana mainnet → include tx signature in `x-surge-tx` header.

SURGE mint: `3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg`

## Quick Start

```bash
git clone https://github.com/Cazaboock9/neogriffin.git
cd neogriffin
cp .env.example .env
# Edit .env with your keys
npm install
node server.js
```

## Tech Stack

Node.js, Express v5, better-sqlite3, Helius DAS API, DexScreener API, GoPlusLabs API, x402 protocol, SURGE token (SPL)

## License

Apache-2.0
