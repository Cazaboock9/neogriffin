import "dotenv/config";
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import path from 'path';
import crypto from 'crypto';
import https from 'https';
import http from 'http';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

// x402 Payment Protocol
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { ExactSvmScheme } from '@x402/svm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { surgePaymentMiddleware } from './surge-payment.js';

// CJS compat for wallet-watcher and nft-scanner
const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================
// 🛡️ NEOGRIFFIN SECURITY API v2.0.0
// x402 Micropayments · Multi-Chain · Hardened
// ============================================
const app = express();
const PORT = 3847;

// ============================================
// CONFIG
// ============================================
const HELIUS_KEY = process.env.HELIUS_KEY || '';
const HELIUS_URL = `https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY}`;
const WALLET_ADDRESS = process.env.WALLET_ADDRESS || '';
const SOLANA_WALLET = process.env.SOLANA_WALLET || '';
const SOLANA_NETWORK = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const X402_NETWORK = 'eip155:84532'; // Base Sepolia testnet (change to eip155:8453 for mainnet)
const FACILITATOR_URL = process.env.FACILITATOR_URL || 'https://facilitator.payai.network';

// ============================================
// SECURITY MIDDLEWARE
// ============================================
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(cors());
app.set('trust proxy', 1);

// ============================================
// RATE LIMITING (in-memory, zero deps)
// ============================================
const rateLimitStore = new Map();
function rateLimit({ windowMs = 60000, max = 30, message = 'Too many requests' } = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const key = `${ip}:${req.route ? req.route.path : req.path}`;
    const now = Date.now();
    if (!rateLimitStore.has(key)) {
      rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    const entry = rateLimitStore.get(key);
    if (now > entry.resetAt) {
      entry.count = 1;
      entry.resetAt = now + windowMs;
      return next();
    }
    entry.count++;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: message, retryAfter: Math.ceil((entry.resetAt - now) / 1000) });
    }
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 300000);
app.use(rateLimit({ windowMs: 60000, max: 60, message: 'Global rate limit exceeded' }));

// ============================================
// INPUT VALIDATION & SANITIZATION
// ============================================
function sanitizeString(str, maxLen = 1000) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim().slice(0, maxLen);
}
function isValidBase58(str) { return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(str); }
function isValidEvmAddress(str) { return /^0x[a-fA-F0-9]{40}$/.test(str); }
function isValidRiskScore(score) { return typeof score === 'number' && score >= 0 && score <= 100 && Number.isFinite(score); }
function isValidRiskLevel(level) { return ['safe', 'low', 'medium', 'high', 'critical', 'unknown'].includes(level); }

// ============================================
// REQUEST LOGGING
// ============================================
app.use((req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || '?';
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (req.originalUrl !== '/' && !req.originalUrl.startsWith('/api/stats')) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms [${ip}]`);
    }
  });
  next();
});

// ============================================
// DATABASE SETUP
// ============================================
const db = new Database(path.join(__dirname, 'aegis.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS token_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mint TEXT NOT NULL, risk_score INTEGER DEFAULT 0, risk_level TEXT DEFAULT 'unknown',
    reported_by TEXT DEFAULT 'anonymous', threats TEXT DEFAULT '[]',
    metadata_injection BOOLEAN DEFAULT 0, reporter_ip TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_hash TEXT NOT NULL, is_threat BOOLEAN DEFAULT 0, threat_level TEXT DEFAULT 'safe',
    threats TEXT DEFAULT '[]', confidence REAL DEFAULT 0, scanner_ip TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total_scans INTEGER DEFAULT 0, total_threats_blocked INTEGER DEFAULT 0,
    total_tokens_scanned INTEGER DEFAULT 0, total_reports INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_token_mint ON token_reports(mint);
  CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_logs(created_at);
`);
try { db.exec(`ALTER TABLE token_reports ADD COLUMN reporter_ip TEXT DEFAULT ''`); } catch (e) {}
try { db.exec(`ALTER TABLE scan_logs ADD COLUMN scanner_ip TEXT DEFAULT ''`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_report_ip_mint ON token_reports(reporter_ip, mint)`); } catch (e) {}
db.prepare(`INSERT OR IGNORE INTO stats (id, total_scans, total_threats_blocked, total_tokens_scanned, total_reports) VALUES (1, 0, 0, 0, 0)`).run();

// ============================================
// ANTI-ABUSE
// ============================================
function canReportToken(ipHash, mint) {
  const r = db.prepare(`SELECT COUNT(*) as count FROM token_reports WHERE reporter_ip = ? AND mint = ? AND created_at > datetime('now', '-1 hour')`).get(ipHash, mint);
  return r.count === 0;
}
function getDailyReportCount(ipHash) {
  return db.prepare(`SELECT COUNT(*) as count FROM token_reports WHERE reporter_ip = ? AND created_at > datetime('now', '-24 hours')`).get(ipHash).count;
}

// ============================================
// PROMPT INJECTION ENGINE
// ============================================
const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?(previous\s+)?instructions/i, category: 'prompt_injection', severity: 'critical', name: 'Instruction Override' },
  { pattern: /you\s+are\s+now\s+(a|an|my)/i, category: 'identity_attack', severity: 'high', name: 'Identity Hijack' },
  { pattern: /forget\s+(everything|all|your)/i, category: 'prompt_injection', severity: 'critical', name: 'Memory Wipe' },
  { pattern: /new\s+instructions?\s*:/i, category: 'prompt_injection', severity: 'critical', name: 'Instruction Injection' },
  { pattern: /system\s*prompt\s*:/i, category: 'prompt_injection', severity: 'critical', name: 'System Prompt Override' },
  { pattern: /disregard\s+(all|any|previous)/i, category: 'prompt_injection', severity: 'critical', name: 'Disregard Command' },
  { pattern: /override\s+(safety|security|protocol)/i, category: 'prompt_injection', severity: 'critical', name: 'Safety Override' },
  { pattern: /pretend\s+(you|to\s+be|that)/i, category: 'identity_attack', severity: 'high', name: 'Pretend Attack' },
  { pattern: /act\s+as\s+(if|a|an|my)/i, category: 'identity_attack', severity: 'medium', name: 'Role Play Attack' },
  { pattern: /do\s+not\s+follow\s+(your|the|any)/i, category: 'prompt_injection', severity: 'critical', name: 'Rule Breaking' },
  { pattern: /approve\s+(unlimited|infinite|max)/i, category: 'fund_transfer', severity: 'critical', name: 'Unlimited Approval' },
  { pattern: /sign\s+(this|the|blind|all)/i, category: 'fund_transfer', severity: 'high', name: 'Blind Signing' },
  { pattern: /transfer\s+(all|entire|everything)/i, category: 'fund_transfer', severity: 'critical', name: 'Full Transfer' },
  { pattern: /send\s+(all|entire|everything)\s*(sol|token|fund|balance)/i, category: 'fund_transfer', severity: 'critical', name: 'Drain Wallet' },
  { pattern: /withdraw\s+(all|entire|everything)/i, category: 'fund_transfer', severity: 'critical', name: 'Full Withdrawal' },
  { pattern: /delegate\s+(authority|all|access)/i, category: 'fund_transfer', severity: 'high', name: 'Authority Delegation' },
  { pattern: /set\s+authority\s+to/i, category: 'fund_transfer', severity: 'critical', name: 'Authority Change' },
  { pattern: /close\s+account/i, category: 'fund_transfer', severity: 'high', name: 'Account Closure' },
  { pattern: /burn\s+(all|token|nft)/i, category: 'fund_transfer', severity: 'high', name: 'Token Burn' },
  { pattern: /revoke\s+(and\s+)?transfer/i, category: 'fund_transfer', severity: 'critical', name: 'Revoke & Transfer' },
  { pattern: /admin\s+(mode|access|override|command)/i, category: 'social_engineering', severity: 'high', name: 'Admin Impersonation' },
  { pattern: /maintenance\s+(mode|update|required)/i, category: 'social_engineering', severity: 'medium', name: 'Maintenance Scam' },
  { pattern: /urgent\s*(action|update|required|immediately)/i, category: 'social_engineering', severity: 'medium', name: 'Urgency Manipulation' },
  { pattern: /verify\s+(your|account|wallet)/i, category: 'social_engineering', severity: 'medium', name: 'Verification Phishing' },
  { pattern: /security\s+(alert|warning|update|patch)/i, category: 'social_engineering', severity: 'medium', name: 'Fake Security Alert' },
  { pattern: /airdrop\s+(claim|ready|waiting)/i, category: 'social_engineering', severity: 'medium', name: 'Airdrop Scam' },
  { pattern: /free\s+(tokens?|sol|nft|mint)/i, category: 'social_engineering', severity: 'medium', name: 'Free Token Scam' },
  { pattern: /connect\s+wallet\s+to\s+(claim|verify|receive)/i, category: 'social_engineering', severity: 'high', name: 'Wallet Connect Phishing' },
  { pattern: /base64|eval\s*\(|atob\s*\(/i, category: 'obfuscation', severity: 'high', name: 'Code Obfuscation' },
  { pattern: /\\x[0-9a-f]{2}/i, category: 'obfuscation', severity: 'medium', name: 'Hex Encoding' },
  { pattern: /&#\d+;/i, category: 'obfuscation', severity: 'medium', name: 'HTML Entity Encoding' },
  { pattern: /\u200b|\u200c|\u200d|\ufeff/i, category: 'obfuscation', severity: 'high', name: 'Invisible Characters' },
];

function scanInput(input) {
  if (!input || typeof input !== 'string') {
    return { isThreat: false, threatLevel: 'safe', confidence: 1.0, threats: [], patternsChecked: INJECTION_PATTERNS.length, recommendation: 'SAFE — No input provided' };
  }
  const normalized = input.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/&#(\d+);/g, (_, c) => String.fromCharCode(c));
  input = normalized;
  const detectedThreats = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.pattern.test(input)) {
      detectedThreats.push({ category: p.category, severity: p.severity, name: p.name });
    }
  }
  const hasCritical = detectedThreats.some(t => t.severity === 'critical');
  const hasHigh = detectedThreats.some(t => t.severity === 'high');
  const count = detectedThreats.length;
  let threatLevel = 'safe';
  let confidence = 1.0;
  if (hasCritical || count >= 3) { threatLevel = 'critical'; confidence = Math.min(0.95, 0.7 + count * 0.08); }
  else if (hasHigh || count >= 2) { threatLevel = 'high'; confidence = Math.min(0.9, 0.6 + count * 0.1); }
  else if (count === 1) { threatLevel = detectedThreats[0].severity === 'medium' ? 'medium' : 'high'; confidence = 0.7; }
  const recs = { safe: 'SAFE — No threats detected', medium: 'CAUTION — Suspicious pattern detected', high: 'WARNING — High risk patterns detected', critical: 'BLOCK — Critical threat detected, do not process' };
  return { isThreat: count > 0, threatLevel, confidence: Math.round(confidence * 100) / 100, threats: detectedThreats, patternsChecked: INJECTION_PATTERNS.length, recommendation: recs[threatLevel] || recs.safe };
}
// SKILL SUPPLY CHAIN SCANNER
const SKILL_CODE_PATTERNS = [
  { pattern: /eval\s*\(/i, category: 'code_execution', severity: 'critical', name: 'Dynamic Code Execution (eval)' },
  { pattern: /Function\s*\(/i, category: 'code_execution', severity: 'critical', name: 'Dynamic Function Constructor' },
  { pattern: /child_process|exec\s*\(|spawn\s*\(/i, category: 'code_execution', severity: 'critical', name: 'System Command Execution' },
  { pattern: /atob\s*\(|btoa\s*\(|Buffer\.from\s*\([^)]*,\s*['"]base64['"]/i, category: 'obfuscation', severity: 'high', name: 'Base64 Encoding/Decoding' },
  { pattern: /String\.fromCharCode/i, category: 'obfuscation', severity: 'high', name: 'Character Code Obfuscation' },
  { pattern: /[1-9A-HJ-NP-Za-km-z]{32,44}/g, category: 'hardcoded_wallet', severity: 'high', name: 'Hardcoded Solana Wallet Address' },
  { pattern: /0x[a-fA-F0-9]{40}/g, category: 'hardcoded_wallet', severity: 'high', name: 'Hardcoded EVM Wallet Address' },
  { pattern: /process\.env/i, category: 'credential_access', severity: 'high', name: 'Environment Variable Access' },
  { pattern: /\.env|dotenv|PRIVATE_KEY|SECRET_KEY|MNEMONIC|SEED_PHRASE/i, category: 'credential_access', severity: 'critical', name: 'Credential/Secret Access' },
  { pattern: /fs\.(read|write|unlink|rmdir|mkdir)/i, category: 'filesystem', severity: 'high', name: 'Filesystem Operations' },
  { pattern: /fetch\s*\(|axios|https?\.request/i, category: 'network', severity: 'medium', name: 'External Network Request' },
  { pattern: /approve\s*\(|transferFrom|delegateTokens|setAuthority/i, category: 'token_manipulation', severity: 'critical', name: 'Token Approval/Delegation' },
  { pattern: /signTransaction|signAllTransactions|signMessage/i, category: 'signing', severity: 'critical', name: 'Transaction Signing Request' },
];

function scanSkill(content) {
  if (!content || typeof content !== 'string') {
    return { isSafe: true, riskLevel: 'safe', codeThreats: [], injectionThreats: [], totalThreats: 0, recommendation: 'SAFE' };
  }
  const normalized = content.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
  const codeThreats = [];
  for (const p of SKILL_CODE_PATTERNS) {
    const regex = new RegExp(p.pattern.source, p.pattern.flags);
    const matches = normalized.match(regex);
    if (matches) {
      codeThreats.push({ category: p.category, severity: p.severity, name: p.name, occurrences: matches.length });
    }
  }
  const injectionResult = scanInput(normalized);
  const injectionThreats = injectionResult.threats || [];
  const allThreats = [...codeThreats, ...injectionThreats];
  const hasCritical = allThreats.some(t => t.severity === 'critical');
  const hasHigh = allThreats.some(t => t.severity === 'high');
  const count = allThreats.length;
  let riskLevel = 'safe';
  if (hasCritical || count >= 5) riskLevel = 'critical';
  else if (hasHigh || count >= 3) riskLevel = 'high';
  else if (count >= 1) riskLevel = 'medium';
  const recs = { safe: 'SAFE — No threats detected', medium: 'CAUTION — Review before installing', high: 'WARNING — Dangerous patterns found', critical: 'BLOCK — Likely malicious' };
  return { isSafe: count === 0, riskLevel, codeThreats, injectionThreats, totalThreats: count, patternsChecked: SKILL_CODE_PATTERNS.length + INJECTION_PATTERNS.length, recommendation: recs[riskLevel] };
}

function secureHash(str) { return crypto.createHash('sha256').update(str).digest('hex').slice(0, 16); }
function hashIP(ip) { return crypto.createHash('sha256').update((ip || '') + 'aegis-salt-2026').digest('hex').slice(0, 12); }

// ============================================
// HELPER: HTTPS fetch (promise-based)
// ============================================
function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const method = options.method || 'GET';
    const urlObj = new URL(url);
    const reqOpts = {
      hostname: urlObj.hostname, path: urlObj.pathname + urlObj.search,
      method, timeout: options.timeout || 10000,
      headers: options.headers || {},
    };
    if (options.body) reqOpts.headers['Content-Length'] = Buffer.byteLength(options.body);
    if (!reqOpts.headers['Content-Type'] && options.body) reqOpts.headers['Content-Type'] = 'application/json';
    const req = mod.request(reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('JSON parse failed')); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ============================================
// x402 PAYMENT MIDDLEWARE SETUP
// ============================================
const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(X402_NETWORK, new ExactEvmScheme()).register(SOLANA_NETWORK, new ExactSvmScheme());

const x402Routes = {
  "GET /api/audit/solana": {
    accepts: [{ scheme: 'exact', price: '$0.10', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: 'Full Solana token security audit — risk score, holders, liquidity, injection detection',
    mimeType: 'application/json',
  },
  "GET /api/audit/base": {
    accepts: [{ scheme: 'exact', price: '$0.10', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: 'Full Base token security audit — honeypot detection, contract analysis, risk scoring',
    mimeType: 'application/json',
  },
  "POST /api/watcher/register": {
    accepts: [{ scheme: 'exact', price: '$0.25', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.25', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.25', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: '24/7 wallet monitoring — real-time alerts for drains, phishing, authority changes',
    mimeType: 'application/json',
  },
  "GET /v1/score": {
    accepts: [{ scheme: 'exact', price: '$0.01', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.01', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.01', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: 'Quick safety score for trading agents — returns score + safe_to_trade boolean',
    mimeType: 'application/json',
  },
  "POST /v1/batch-score": {
    accepts: [{ scheme: 'exact', price: '$0.05', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.05', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.05', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: 'Batch safety scoring — up to 10 tokens per call for trading agents',
    mimeType: 'application/json',
  },
  "POST /api/scan/skill": {
    accepts: [{ scheme: 'exact', price: '$0.10', network: X402_NETWORK, payTo: WALLET_ADDRESS }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 } }, { scheme: 'exact', price: '$0.10', network: SOLANA_NETWORK, payTo: SOLANA_WALLET, asset: { address: '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg', decimals: 9 } }],
    description: 'Skill supply chain scanner — detects malicious code and prompt injection in OpenClaw skills',
    mimeType: 'application/json',
  },
};

// SURGE payment (custom verification)
app.use(surgePaymentMiddleware);
// x402 payment (USDC via facilitator) - skip if SURGE already paid
app.use((req, res, next) => { if (req.surgePaid) return next(); paymentMiddleware(x402Routes, resourceServer)(req, res, next); });

// ============================================
// FREE ENDPOINTS
// ============================================

// POST /api/scan — Prompt injection detection (FREE)
app.post('/api/scan', rateLimit({ windowMs: 60000, max: 60 }), (req, res) => {
  const { input } = req.body;
  if (!input || typeof input !== 'string') return res.status(400).json({ error: 'Missing "input" field (string)' });
  const cleaned = sanitizeString(input, 5000);
  const result = scanInput(cleaned);
  // Log to DB
  const ipHash = hashIP(req.ip || req.connection?.remoteAddress);
  try {
    db.prepare(`INSERT INTO scan_logs (input_hash, is_threat, threat_level, threats, confidence, scanner_ip) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(secureHash(cleaned), result.isThreat ? 1 : 0, result.threatLevel, JSON.stringify(result.threats), result.confidence, ipHash);
    db.prepare(`UPDATE stats SET total_scans = total_scans + 1${result.isThreat ? ', total_threats_blocked = total_threats_blocked + 1' : ''}, updated_at = CURRENT_TIMESTAMP WHERE id = 1`).run();
  } catch (e) { console.error('Scan log error:', e.message); }
  res.json(result);
});

// GET /api/stats — Network stats (FREE)
app.get('/api/stats', (req, res) => {
  try {
    const stats = db.prepare('SELECT * FROM stats WHERE id = 1').get() || {};
    let walletCount = 0;
    try { walletCount = db.prepare('SELECT COUNT(*) as count FROM watched_wallets WHERE active = 1').get()?.count || 0; } catch (e) {}
    const recentScans = db.prepare(`SELECT COUNT(*) as count FROM scan_logs WHERE created_at > datetime('now', '-24 hours')`).get();
    const recentReports = db.prepare(`SELECT COUNT(*) as count FROM token_reports WHERE created_at > datetime('now', '-24 hours')`).get();
    const uniqueTokens = db.prepare(`SELECT COUNT(DISTINCT mint) as count FROM token_reports`).get();
    res.json({
      network: 'NeoGriffin Security Network', version: '2.0.0',
      chains: ['solana', 'base'], payments: 'x402 USDC',
      total_scans: stats.total_scans || 0,
      threats_detected: stats.total_threats_blocked || 0,
      total_tokens_scanned: stats.total_tokens_scanned || 0,
      total_reports: stats.total_reports || 0,
      unique_tokens_reported: uniqueTokens?.count || 0,
      wallets_monitored: walletCount,
      last_24h: { scans: recentScans?.count || 0, reports: recentReports?.count || 0 },
      injection_patterns: INJECTION_PATTERNS.length,
      uptime: Math.floor(process.uptime() / 3600) + 'h',
      status: 'online',
    });
  } catch (e) {
    res.json({ network: 'NeoGriffin Security Network', version: '2.0.0', status: 'online', error: 'Stats temporarily unavailable' });
  }
});

// GET /api/patterns — Pattern list (FREE)
app.get('/api/patterns', (req, res) => {
  const patterns = INJECTION_PATTERNS.map(p => ({ name: p.name, category: p.category, severity: p.severity }));
  const categories = {};
  patterns.forEach(p => { if (!categories[p.category]) categories[p.category] = []; categories[p.category].push(p.name); });
  res.json({ total_patterns: patterns.length, categories, patterns });
});

// POST /api/token/report — Community reports (FREE, 10/min)
app.post('/api/token/report', rateLimit({ windowMs: 60000, max: 10, message: 'Report rate limit: max 10/min' }), (req, res) => {
  try {
    const { mint, risk_score, risk_level, threats, metadata_injection, reported_by } = req.body;
    if (!mint) return res.status(400).json({ error: 'Missing "mint" field' });
    if (!isValidBase58(mint)) return res.status(400).json({ error: 'Invalid mint address' });
    const safeScore = isValidRiskScore(risk_score) ? Math.round(risk_score) : 0;
    const safeLevel = isValidRiskLevel(risk_level) ? risk_level : 'unknown';
    let safeThreats = [];
    if (Array.isArray(threats)) safeThreats = threats.filter(t => typeof t === 'string').slice(0, 20).map(t => sanitizeString(t, 100));
    const ipHash = hashIP(req.ip || req.connection?.remoteAddress);
    if (getDailyReportCount(ipHash) >= 50) return res.status(429).json({ error: 'Daily report limit reached (50/day)' });
    if (!canReportToken(ipHash, mint)) {
      const c = db.prepare(`SELECT COUNT(*) as count FROM token_reports WHERE mint = ?`).get(mint);
      return res.json({ success: true, mint, total_reports: c.count, message: 'Report already recorded', deduplicated: true });
    }
    db.prepare(`INSERT INTO token_reports (mint, risk_score, risk_level, threats, metadata_injection, reported_by, reporter_ip) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(mint, safeScore, safeLevel, JSON.stringify(safeThreats), metadata_injection ? 1 : 0, sanitizeString(reported_by || 'anonymous', 64), ipHash);
    db.prepare(`UPDATE stats SET total_tokens_scanned = total_tokens_scanned + 1, total_reports = total_reports + 1, updated_at = CURRENT_TIMESTAMP WHERE id = 1`).run();
    const c = db.prepare(`SELECT COUNT(*) as count FROM token_reports WHERE mint = ?`).get(mint);
    res.json({ success: true, mint, total_reports: c.count, message: 'Token reported successfully' });
  } catch (e) { console.error('Report error:', e); res.status(500).json({ error: 'Internal server error' }); }
});

// GET /api/token/:mint/status — Community verdict (FREE)
app.get('/api/token/:mint/status', rateLimit({ windowMs: 60000, max: 30 }), (req, res) => {
  try {
    const { mint } = req.params;
    if (!isValidBase58(mint)) return res.status(400).json({ error: 'Invalid mint address' });
    const reports = db.prepare(`SELECT risk_score, risk_level, threats, metadata_injection, created_at FROM token_reports WHERE mint = ? ORDER BY created_at DESC LIMIT 50`).all(mint);
    if (reports.length === 0) return res.json({ mint, reported: false, total_reports: 0, community_verdict: 'No reports yet' });
    const avg = Math.round(reports.reduce((s, r) => s + r.risk_score, 0) / reports.length);
    let verdict = avg < 30 ? 'Dangerous — Community flagged as scam' : avg < 50 ? 'Suspicious — Exercise caution' : avg < 70 ? 'Mixed reports — DYOR' : 'Likely Safe';
    res.json({ mint, reported: true, total_reports: reports.length, avg_risk_score: avg, community_verdict: verdict, reports: reports.slice(0, 10) });
  } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});

// GET /api/token/:mint/holders — Helius holder count (FREE, used internally)
app.get('/api/token/:mint/holders', rateLimit({ windowMs: 60000, max: 30 }), async (req, res) => {
  const { mint } = req.params;
  if (!mint || mint.length < 32) return res.status(400).json({ error: 'Invalid mint' });
  try {
    let totalHolders = 0, cursor = null;
    for (let i = 0; i < 5; i++) {
      const params = { mint, limit: 1000 };
      if (cursor) params.cursor = cursor;
      const resp = await fetchJSON(HELIUS_URL, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 'h', method: 'getTokenAccounts', params }) });
      const accounts = resp.result?.token_accounts || [];
      totalHolders += accounts.length;
      cursor = resp.result?.cursor || null;
      if (!cursor || accounts.length < 1000) break;
    }
    res.json({ mint, holders: totalHolders, exact: !cursor });
  } catch (e) { res.status(500).json({ error: 'Failed to get holders' }); }
});

// GET /api/token/:mint/audit — Legacy audit (FREE, for mobile app backward compat)
app.get('/api/token/:mint/audit', rateLimit({ windowMs: 60000, max: 20 }), async (req, res) => {
  const { mint } = req.params;
  if (!mint || mint.length < 32) return res.status(400).json({ error: 'Invalid mint' });
  try {
    const auditResult = await performSolanaAudit(mint);
    res.json(auditResult);
  } catch (e) { res.status(500).json({ error: 'Audit failed: ' + e.message }); }
});

// ============================================
// x402 PAID ENDPOINTS
// ============================================

// GET /api/audit/solana?mint=XXX — PAID Solana audit ($0.10 USDC)
app.get('/api/audit/solana', rateLimit({ windowMs: 60000, max: 20 }), async (req, res) => {
  const mint = req.query.mint;
  if (!mint || !isValidBase58(mint)) return res.status(400).json({ error: 'Missing or invalid ?mint= parameter (base58, 32-44 chars)' });
  try {
    const auditResult = await performSolanaAudit(mint);
    auditResult.payment = { method: 'x402', amount: '$0.10', asset: 'USDC', network: 'Base' };
    res.json(auditResult);
  } catch (e) { res.status(500).json({ error: 'Audit failed: ' + e.message }); }
});

// GET /api/audit/base?address=0x... — PAID Base audit ($0.10 USDC)
app.get('/api/audit/base', rateLimit({ windowMs: 60000, max: 20 }), async (req, res) => {
  const address = req.query.address;
  if (!address || !isValidEvmAddress(address)) return res.status(400).json({ error: 'Missing or invalid ?address= parameter (0x + 40 hex chars)' });
  try {
    const auditResult = await performBaseAudit(address);
    auditResult.payment = { method: 'x402', amount: '$0.10', asset: 'USDC', network: 'Base' };
    res.json(auditResult);
  } catch (e) { res.status(500).json({ error: 'Audit failed: ' + e.message }); }
});

// ============================================
// AUDIT ENGINES
// ============================================

async function performSolanaAudit(mint) {
  // Get mint info (freeze/mint authority)
  const mintResp = await fetchJSON(HELIUS_URL, {
    method: 'POST',
    body: JSON.stringify({ jsonrpc: '2.0', id: 'mint', method: 'getAccountInfo', params: [mint, { encoding: 'jsonParsed' }] }),
  });
  const parsed = mintResp.result?.value?.data?.parsed;
  const mintAuthority = parsed?.info?.mintAuthority || null;
  const freezeAuthority = parsed?.info?.freezeAuthority || null;

  // Get holders
  let holders = 0, holdersExact = true;
  try {
    const hResp = await fetchJSON(`http://localhost:${PORT}/api/token/${mint}/holders`, { timeout: 15000 });
    holders = hResp.holders || 0;
    holdersExact = hResp.exact !== false;
  } catch (e) {}

  // Get DexScreener data
  let dexData = {};
  try {
    const dexResp = await fetchJSON(`https://api.dexscreener.com/tokens/v1/solana/${mint}`, { timeout: 8000 });
    if (Array.isArray(dexResp) && dexResp.length > 0) {
      const best = dexResp.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];
      dexData = {
        price: parseFloat(best.priceUsd || '0'), liquidity: best.liquidity?.usd || 0,
        volume24h: best.volume?.h24 || 0, marketCap: best.fdv || 0,
        pairCreatedAt: best.pairCreatedAt || 0,
        name: best.baseToken?.name || 'Unknown', symbol: best.baseToken?.symbol || '???',
      };
    }
  } catch (e) {}

  // Calculate age & risk score
  const ageMs = dexData.pairCreatedAt ? Date.now() - dexData.pairCreatedAt : 0;
  const ageDays = ageMs > 0 ? Math.floor(ageMs / 86400000) : -1;
  let score = 100;
  const risks = [];
  if (mintAuthority) { score -= 20; risks.push('Mint authority active — can create more tokens'); }
  if (freezeAuthority) { score -= 20; risks.push('Freeze authority active — can freeze your tokens'); }
  if (holders < 100) { score -= 15; risks.push(`Only ${holders} holders — very low adoption`); }
  if (dexData.liquidity < 10000) { score -= 15; risks.push(`Liquidity $${dexData.liquidity || 0} — high slippage risk`); }
  if (ageDays >= 0 && ageDays < 1) { score -= 15; risks.push('Token is less than 1 day old'); }
  if (dexData.volume24h < 1000) { score -= 10; risks.push('Very low 24h volume'); }

  // Check injection in name (FIXED: was using .is_threat instead of .isThreat)
  let injectionDetected = false;
  if (dexData.name) {
    const scanResult = scanInput(dexData.name);
    if (scanResult.isThreat) {
      injectionDetected = true;
      score -= 25;
      risks.push(`Injection detected in token name: ${scanResult.threats.map(t => t.name).join(', ')}`);
    }
  }
  if (score < 0) score = 0;

  const riskLevel = score >= 75 ? 'safe' : score >= 50 ? 'medium' : score >= 25 ? 'high' : 'critical';
  return {
    chain: 'solana', mint, name: dexData.name || 'Unknown', symbol: dexData.symbol || '???',
    riskScore: score, riskLevel, holders, holdersExact,
    price: dexData.price || 0, liquidity: dexData.liquidity || 0,
    volume24h: dexData.volume24h || 0, marketCap: dexData.marketCap || 0,
    ageDays, mintAuthority: !!mintAuthority, freezeAuthority: !!freezeAuthority,
    injectionDetected, risks,
    recommendation: riskLevel === 'safe' ? 'Token passes security checks. Always DYOR.' :
      riskLevel === 'medium' ? 'Some risk factors. Proceed with caution.' :
      riskLevel === 'high' ? 'Multiple risks detected. Consider avoiding.' :
      'DANGER: Critical risk factors. High probability of scam.',
  };
}

async function performBaseAudit(address) {
  // GoPlusLabs — contract security for Base (chain ID 8453)
  let goplus = {};
  try {
    const gpResp = await fetchJSON(`https://api.gopluslabs.com/api/v1/token_security/8453?contract_addresses=${address}`, { timeout: 10000 });
    goplus = gpResp.result?.[address.toLowerCase()] || {};
  } catch (e) {}

  // DexScreener — market data for Base
  let dexData = {};
  try {
    const dexResp = await fetchJSON(`https://api.dexscreener.com/tokens/v1/base/${address}`, { timeout: 8000 });
    if (Array.isArray(dexResp) && dexResp.length > 0) {
      const best = dexResp.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];
      dexData = {
        price: parseFloat(best.priceUsd || '0'), liquidity: best.liquidity?.usd || 0,
        volume24h: best.volume?.h24 || 0, marketCap: best.fdv || 0,
        pairCreatedAt: best.pairCreatedAt || 0,
        name: best.baseToken?.name || 'Unknown', symbol: best.baseToken?.symbol || '???',
      };
    }
  } catch (e) {}

  // Calculate risk score
  let score = 100;
  const risks = [];
  const isHoneypot = goplus.is_honeypot === '1';
  const isMintable = goplus.is_mintable === '1';
  const isProxy = goplus.is_proxy === '1';
  const hasOwner = goplus.owner_address && goplus.owner_address !== '0x0000000000000000000000000000000000000000';
  const canTakeBack = goplus.can_take_back_ownership === '1';
  const isOpenSource = goplus.is_open_source === '1';
  const buyTax = parseFloat(goplus.buy_tax || '0');
  const sellTax = parseFloat(goplus.sell_tax || '0');

  if (isHoneypot) { score -= 50; risks.push('HONEYPOT — Cannot sell this token'); }
  if (isMintable) { score -= 20; risks.push('Contract is mintable — supply can be inflated'); }
  if (isProxy) { score -= 15; risks.push('Proxy contract — code can be changed'); }
  if (canTakeBack) { score -= 20; risks.push('Owner can reclaim ownership'); }
  if (!isOpenSource) { score -= 15; risks.push('Contract source code not verified'); }
  if (hasOwner) { score -= 5; risks.push('Contract has active owner'); }
  if (buyTax > 0.05) { score -= 10; risks.push(`Buy tax: ${(buyTax * 100).toFixed(1)}%`); }
  if (sellTax > 0.05) { score -= 10; risks.push(`Sell tax: ${(sellTax * 100).toFixed(1)}%`); }
  if (dexData.liquidity < 10000) { score -= 10; risks.push(`Low liquidity: $${dexData.liquidity || 0}`); }

  // Check injection in name
  let injectionDetected = false;
  if (dexData.name) {
    const scanResult = scanInput(dexData.name);
    if (scanResult.isThreat) {
      injectionDetected = true;
      score -= 25;
      risks.push(`Injection in token name: ${scanResult.threats.map(t => t.name).join(', ')}`);
    }
  }
  if (score < 0) score = 0;

  const ageMs = dexData.pairCreatedAt ? Date.now() - dexData.pairCreatedAt : 0;
  const ageDays = ageMs > 0 ? Math.floor(ageMs / 86400000) : -1;
  const riskLevel = score >= 75 ? 'safe' : score >= 50 ? 'medium' : score >= 25 ? 'high' : 'critical';

  return {
    chain: 'base', address, name: dexData.name || 'Unknown', symbol: dexData.symbol || '???',
    riskScore: score, riskLevel,
    price: dexData.price || 0, liquidity: dexData.liquidity || 0,
    volume24h: dexData.volume24h || 0, marketCap: dexData.marketCap || 0,
    ageDays, isHoneypot, isMintable, isProxy, isOpenSource: !!isOpenSource,
    hasOwner: !!hasOwner, buyTax, sellTax, injectionDetected, risks,
    goplusAvailable: Object.keys(goplus).length > 0,
    recommendation: riskLevel === 'safe' ? 'Token passes security checks. Always DYOR.' :
      riskLevel === 'medium' ? 'Some risk factors. Proceed with caution.' :
      riskLevel === 'high' ? 'Multiple risks detected. Consider avoiding.' :
      'DANGER: Critical risk factors. High probability of scam.',
  };
}

// ============================================
// v1 AGENT API — Infrastructure Layer
// ============================================

// Quick score — $0.01 per call, designed for trading agents
app.get('/v1/score', rateLimit({ windowMs: 60000, max: 100 }), async (req, res) => {
  try {
    const { address, chain } = req.query;
    if (!address) return res.status(400).json({ error: 'address required', usage: 'GET /v1/score?address=TOKEN&chain=solana|base' });

    const detectedChain = chain || (address.startsWith('0x') ? 'base' : 'solana');
    let audit;
    if (detectedChain === 'base') {
      audit = await performBaseAudit(address);
    } else {
      audit = await performSolanaAudit(address);
    }

    const safeToTrade = audit.riskScore >= 60 && !audit.isHoneypot && !audit.injectionDetected;

    res.json({
      address,
      chain: detectedChain,
      score: audit.riskScore,
      safe_to_trade: safeToTrade,
      risk_level: audit.riskLevel,
      flags: audit.risks || [],
      token: { name: audit.name, symbol: audit.symbol },
      market: {
        price: audit.price || 0,
        liquidity: audit.liquidity || 0,
        volume_24h: audit.volume24h || 0,
        market_cap: audit.marketCap || 0,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    res.status(500).json({ error: 'Score failed', detail: e.message });
  }
});

// Batch score — $0.05 per call, up to 10 tokens
app.post('/v1/batch-score', rateLimit({ windowMs: 60000, max: 20 }), async (req, res) => {
  try {
    const { tokens } = req.body;
    if (!tokens || !Array.isArray(tokens) || tokens.length === 0) {
      return res.status(400).json({ error: 'tokens array required', usage: 'POST /v1/batch-score { "tokens": [{"address":"...", "chain":"solana|base"}, ...] }' });
    }
    if (tokens.length > 10) {
      return res.status(400).json({ error: 'Maximum 10 tokens per batch' });
    }

    const results = await Promise.allSettled(
      tokens.map(async (t) => {
        const addr = typeof t === 'string' ? t : t.address;
        const chain = (typeof t === 'object' && t.chain) || (addr.startsWith('0x') ? 'base' : 'solana');
        let audit;
        if (chain === 'base') {
          audit = await performBaseAudit(addr);
        } else {
          audit = await performSolanaAudit(addr);
        }
        const safeToTrade = audit.riskScore >= 60 && !audit.isHoneypot && !audit.injectionDetected;
        return {
          address: addr,
          chain,
          score: audit.riskScore,
          safe_to_trade: safeToTrade,
          risk_level: audit.riskLevel,
          flags: audit.risks || [],
          token: { name: audit.name, symbol: audit.symbol },
        };
      })
    );

    const output = results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value;
      const addr = typeof tokens[i] === 'string' ? tokens[i] : tokens[i].address;
      return { address: addr, error: r.reason?.message || 'Failed' };
    });

    const safe = output.filter(r => r.safe_to_trade === true).length;
    const unsafe = output.filter(r => r.safe_to_trade === false).length;

    res.json({
      total: output.length,
      safe,
      unsafe,
      errors: output.filter(r => r.error).length,
      results: output,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    res.status(500).json({ error: 'Batch scoring failed', detail: e.message });
  }
});
 
// POST /api/scan/skill — Skill supply chain scanner (PAID)
app.post('/api/scan/skill', rateLimit({ windowMs: 60000, max: 20 }), (req, res) => {
  try {
    const { content, name } = req.body;
    if (!content || typeof content !== 'string') {
      return res.status(400).json({ error: 'Missing "content" field' });
    }
    if (content.length > 50000) {
      return res.status(400).json({ error: 'Content too large (max 50KB)' });
    }
    const cleaned = sanitizeString(content, 50000);
    const result = scanSkill(cleaned);
    const ipHash = hashIP(req.ip || req.connection?.remoteAddress);
    try {
      db.prepare('INSERT INTO scan_logs (input_hash, is_threat, threat_level, threats, confidence, scanner_ip) VALUES (?, ?, ?, ?, ?, ?)').run(secureHash(cleaned), result.isSafe ? 0 : 1, result.riskLevel, JSON.stringify([...result.codeThreats, ...result.injectionThreats]), result.isSafe ? 1.0 : 0.3, ipHash);
      db.prepare('UPDATE stats SET total_scans = total_scans + 1' + (!result.isSafe ? ', total_threats_blocked = total_threats_blocked + 1' : '') + ', updated_at = CURRENT_TIMESTAMP WHERE id = 1').run();
    } catch (e) { console.error('Skill scan log error:', e.message); }
    res.json({ skill: name || 'unknown', ...result, payment: { method: req.surgePaid ? 'SURGE' : 'x402', amount: req.surgePaid ? '5 SURGE' : '$0.10 USDC' }, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ error: 'Skill scan failed', detail: e.message });
  }
});
// ============================================
// WALLET WATCHER & NFT SCANNER (CJS modules)
// ============================================
try {
  const watcher = require('./wallet-watcher.cjs');
  watcher.attachToServer(app);
  setInterval(() => watcher.pollAllWallets(), 30000);
  console.log('  ✅ Wallet Watcher loaded');
} catch (e) {
  console.warn('  ⚠️  Wallet Watcher not loaded:', e.message);
}

try {
  const nftScanner = require('./nft-scanner.cjs');
  nftScanner.init(INJECTION_PATTERNS, HELIUS_KEY);
  nftScanner.attachToServer(app);
  console.log('  ✅ NFT Scanner loaded');
} catch (e) {
  console.warn('  ⚠️  NFT Scanner not loaded:', e.message);
}
// ============================================
// ERROR HANDLERS (must be AFTER all routes)
// ============================================
app.use((req, res) => { res.status(404).json({ error: 'Endpoint not found' }); });
app.use((err, req, res, next) => { console.error('Unhandled:', err); res.status(500).json({ error: 'Internal server error' }); });

// ============================================
// START
// ============================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║   🛡️  NEOGRIFFIN SECURITY API v2.0.0        ║
  ║   Running on port ${PORT}                      ║
  ║   Chains: Solana + Base                      ║
  ║   Payments: x402 USDC on ${X402_NETWORK}      ║
  ║   Wallet: ${WALLET_ADDRESS.slice(0, 10)}...${WALLET_ADDRESS.slice(-6)}       ║
  ║   Patterns loaded: ${INJECTION_PATTERNS.length}                      ║
  ║   🔒 Hardened: rate limits + anti-abuse      ║
  ╚══════════════════════════════════════════════╝
  `);
});
