// ============================================
// 👁️ AEGIS WALLET WATCHER v1.0.0
// 24/7 wallet monitoring — detects suspicious activity
// Run: node wallet-watcher.js
// Or: pm2 start wallet-watcher.js --name aegis-watcher
// ============================================

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================
// CONFIG
// ============================================

const CONFIG = {
  HELIUS_KEY: '21a605c8-ec63-41d0-8a11-8521d15bfb13',
  AEGIS_SERVER: 'http://localhost:3847',
  POLL_INTERVAL_MS: 30000, // Check every 30 seconds
  WALLETS_FILE: path.join(__dirname, 'watched-wallets.json'),
  ALERTS_FILE: path.join(__dirname, 'alerts.json'),
  LOG_FILE: path.join(__dirname, 'watcher.log'),
};

// ============================================
// THREAT PATTERNS (direct wallet attacks)
// ============================================

const WALLET_THREATS = {
  // Suspicious program IDs
  KNOWN_DRAINERS: [
    // Add known drainer program IDs here as they're discovered
  ],

  // Transaction analysis rules
  RULES: [
    {
      name: 'Large SOL Transfer Out',
      check: (tx, wallet) => {
        if (!tx.nativeTransfers) return null;
        for (const transfer of tx.nativeTransfers) {
          if (transfer.fromUserAccount === wallet && transfer.amount > 1_000_000_000) { // > 1 SOL
            return { severity: 'high', detail: `${(transfer.amount / 1e9).toFixed(2)} SOL sent to ${transfer.toUserAccount?.slice(0, 8)}...` };
          }
        }
        return null;
      }
    },
    {
      name: 'Token Approval (Delegate)',
      check: (tx) => {
        if (!tx.instructions) return null;
        for (const ix of tx.instructions) {
          if (ix.programId === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') {
            // Approve instruction = type 4
            if (ix.parsed?.type === 'approve' || ix.parsed?.type === 'approveChecked') {
              return { severity: 'critical', detail: `Token approval to delegate ${ix.parsed?.info?.delegate?.slice(0, 8)}...` };
            }
          }
        }
        return null;
      }
    },
    {
      name: 'Authority Change',
      check: (tx) => {
        if (!tx.instructions) return null;
        for (const ix of tx.instructions) {
          if (ix.parsed?.type === 'setAuthority') {
            return { severity: 'critical', detail: `Authority changed to ${ix.parsed?.info?.newAuthority?.slice(0, 8)}...` };
          }
        }
        return null;
      }
    },
    {
      name: 'Account Close',
      check: (tx) => {
        if (!tx.instructions) return null;
        for (const ix of tx.instructions) {
          if (ix.parsed?.type === 'closeAccount') {
            return { severity: 'high', detail: `Token account closed, remaining SOL sent to ${ix.parsed?.info?.destination?.slice(0, 8)}...` };
          }
        }
        return null;
      }
    },
    {
      name: 'Multiple Transfers (Batch Drain)',
      check: (tx, wallet) => {
        if (!tx.nativeTransfers) return null;
        const outgoing = tx.nativeTransfers.filter(t => t.fromUserAccount === wallet);
        if (outgoing.length >= 3) {
          const totalLamports = outgoing.reduce((sum, t) => sum + t.amount, 0);
          return { severity: 'critical', detail: `${outgoing.length} outgoing transfers totaling ${(totalLamports / 1e9).toFixed(2)} SOL — possible batch drain` };
        }
        return null;
      }
    },
    {
      name: 'Unknown Program Interaction',
      check: (tx) => {
        if (!tx.instructions) return null;
        const knownPrograms = [
          '11111111111111111111111111111111',           // System Program
          'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', // Token Program
          'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', // Associated Token
          'ComputeBudget111111111111111111111111111111', // Compute Budget
          'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',  // Jupiter v6
          'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',  // Orca Whirlpool
          '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', // Raydium AMM
        ];
        for (const ix of tx.instructions) {
          if (ix.programId && !knownPrograms.includes(ix.programId)) {
            return { severity: 'medium', detail: `Interaction with unknown program: ${ix.programId.slice(0, 12)}...` };
          }
        }
        return null;
      }
    },
    {
      name: 'Memo with Injection',
      check: (tx) => {
        if (!tx.instructions) return null;
        for (const ix of tx.instructions) {
          if (ix.programId === 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr' ||
              ix.programId === 'Memo1UhkJBfCR6MNB9L6drXwMCHNrJoSYVFdYDZuFE') {
            const memo = ix.data || ix.parsed || '';
            const memoStr = typeof memo === 'string' ? memo : JSON.stringify(memo);
            // Check for injection patterns
            if (/ignore|override|pretend|transfer all|send all/i.test(memoStr)) {
              return { severity: 'critical', detail: `Suspicious memo: "${memoStr.slice(0, 50)}..."` };
            }
          }
        }
        return null;
      }
    },
  ],
};

// ============================================
// WALLET MANAGER
// ============================================

function loadWallets() {
  try {
    if (fs.existsSync(CONFIG.WALLETS_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG.WALLETS_FILE, 'utf8'));
    }
  } catch (e) {
    log('ERROR', `Failed to load wallets: ${e.message}`);
  }
  return {};
}

function saveWallets(wallets) {
  fs.writeFileSync(CONFIG.WALLETS_FILE, JSON.stringify(wallets, null, 2));
}

function registerWallet(address, label = '') {
  const wallets = loadWallets();
  wallets[address] = {
    label: label || address.slice(0, 8),
    registeredAt: new Date().toISOString(),
    lastChecked: null,
    lastSignature: null,
    alertCount: 0,
  };
  saveWallets(wallets);
  log('INFO', `Registered wallet: ${label || address.slice(0, 8)} (${address.slice(0, 12)}...)`);
}

// ============================================
// HELIUS API
// ============================================

async function getRecentTransactions(address, limit = 10) {
  return new Promise((resolve, reject) => {
    const url = `https://api.helius.xyz/v0/addresses/${address}/transactions?api-key=${CONFIG.HELIUS_KEY}&limit=${limit}`;

    https.get(url, { timeout: 10000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error('Invalid JSON from Helius'));
        }
      });
    }).on('error', reject);
  });
}

// ============================================
// AEGIS SCAN (via local server)
// ============================================

async function aegisScan(input) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ input });
    const url = new URL(CONFIG.AEGIS_SERVER + '/api/scan');

    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 5000,
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { reject(new Error('Bad response')); }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ============================================
// ALERTS
// ============================================

function loadAlerts() {
  try {
    if (fs.existsSync(CONFIG.ALERTS_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG.ALERTS_FILE, 'utf8'));
    }
  } catch {}
  return [];
}

function saveAlert(alert) {
  const alerts = loadAlerts();
  alerts.unshift(alert); // newest first
  // Keep last 500 alerts
  if (alerts.length > 500) alerts.length = 500;
  fs.writeFileSync(CONFIG.ALERTS_FILE, JSON.stringify(alerts, null, 2));
}

function createAlert(wallet, txSignature, rule, detail, severity) {
  const alert = {
    id: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    wallet: wallet.slice(0, 12) + '...',
    walletFull: wallet,
    txSignature,
    rule,
    detail,
    severity,
    acknowledged: false,
  };

  saveAlert(alert);
  log('ALERT', `🚨 [${severity.toUpperCase()}] ${rule}: ${detail} — wallet ${wallet.slice(0, 8)}... tx ${txSignature?.slice(0, 12)}...`);

  return alert;
}

// ============================================
// TRANSACTION ANALYZER
// ============================================

function analyzeTransaction(tx, walletAddress) {
  const threats = [];

  for (const rule of WALLET_THREATS.RULES) {
    try {
      const result = rule.check(tx, walletAddress);
      if (result) {
        threats.push({
          rule: rule.name,
          severity: result.severity,
          detail: result.detail,
        });
      }
    } catch (e) {
      // Rule failed, skip
    }
  }

  return threats;
}

// ============================================
// POLLING LOOP
// ============================================

async function checkWallet(address, walletInfo) {
  try {
    const txs = await getRecentTransactions(address, 5);

    if (!Array.isArray(txs) || txs.length === 0) return;

    for (const tx of txs) {
      const sig = tx.signature;

      // Skip if already checked
      if (sig === walletInfo.lastSignature) break;

      // Analyze transaction
      const threats = analyzeTransaction(tx, address);

      for (const threat of threats) {
        createAlert(address, sig, threat.rule, threat.detail, threat.severity);
        walletInfo.alertCount++;
      }

      // Also scan any memo through Aegis injection engine
      if (tx.instructions) {
        for (const ix of tx.instructions) {
          if (ix.programId?.includes('Memo')) {
            const memo = ix.data || ix.parsed || '';
            const memoStr = typeof memo === 'string' ? memo : JSON.stringify(memo);
            if (memoStr.length > 3) {
              try {
                const scanResult = await aegisScan(memoStr);
                if (scanResult.isThreat) {
                  createAlert(address, sig, 'Aegis Injection Scan', `Memo injection: ${scanResult.recommendation}`, scanResult.threatLevel);
                  walletInfo.alertCount++;
                }
              } catch {}
            }
          }
        }
      }
    }

    // Update last checked
    walletInfo.lastSignature = txs[0]?.signature || walletInfo.lastSignature;
    walletInfo.lastChecked = new Date().toISOString();

  } catch (e) {
    log('ERROR', `Failed to check wallet ${address.slice(0, 8)}...: ${e.message}`);
  }
}

async function pollAllWallets() {
  const wallets = loadWallets();
  const addresses = Object.keys(wallets);

  if (addresses.length === 0) {
    return;
  }

  for (const address of addresses) {
    await checkWallet(address, wallets[address]);
    // Small delay between wallets to avoid rate limits
    await new Promise(r => setTimeout(r, 1000));
  }

  saveWallets(wallets);
}

// ============================================
// LOGGING
// ============================================

function log(level, message) {
  const line = `[${new Date().toISOString()}] [${level}] ${message}`;
  console.log(line);

  // Append to log file
  try {
    fs.appendFileSync(CONFIG.LOG_FILE, line + '\n');
  } catch {}
}

// ============================================
// API ENDPOINTS (added to main server)
// ============================================

function attachToServer(app) {
  // Register wallet for monitoring
  app.post('/api/watcher/register', (req, res) => {
    const { wallet, label } = req.body;
    if (!wallet || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) {
      return res.status(400).json({ error: 'Invalid wallet address' });
    }
    registerWallet(wallet, label);
    res.json({ success: true, wallet, message: 'Wallet registered for monitoring' });
  });

  // List watched wallets
  app.get('/api/watcher/wallets', (req, res) => {
    const wallets = loadWallets();
    const list = Object.entries(wallets).map(([address, info]) => ({
      address: address.slice(0, 8) + '...' + address.slice(-6),
      label: info.label,
      lastChecked: info.lastChecked,
      alertCount: info.alertCount,
    }));
    res.json({ wallets: list, total: list.length });
  });

  // Get alerts
  app.get('/api/watcher/alerts', (req, res) => {
    const alerts = loadAlerts();
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    res.json({ alerts: alerts.slice(0, limit), total: alerts.length });
  });

  // Unregister wallet
  app.delete('/api/watcher/wallet/:address', (req, res) => {
    const wallets = loadWallets();
    const { address } = req.params;
    if (wallets[address]) {
      delete wallets[address];
      saveWallets(wallets);
      res.json({ success: true, message: 'Wallet removed from monitoring' });
    } else {
      res.status(404).json({ error: 'Wallet not found' });
    }
  });

  // Watcher status
  app.get('/api/watcher/status', (req, res) => {
    const wallets = loadWallets();
    const alerts = loadAlerts();
    res.json({
      status: 'active',
      walletsMonitored: Object.keys(wallets).length,
      totalAlerts: alerts.length,
      recentAlerts: alerts.slice(0, 5),
      pollInterval: CONFIG.POLL_INTERVAL_MS / 1000 + 's',
      rules: WALLET_THREATS.RULES.map(r => r.name),
    });
  });

  log('INFO', '👁️ Wallet Watcher endpoints attached to server');
}

// ============================================
// START
// ============================================

// If run standalone
if (require.main === module) {
  log('INFO', '=========================================');
  log('INFO', '👁️ AEGIS WALLET WATCHER v1.0.0');
  log('INFO', `Polling every ${CONFIG.POLL_INTERVAL_MS / 1000}s`);
  log('INFO', `Rules loaded: ${WALLET_THREATS.RULES.length}`);
  log('INFO', '=========================================');

  // Initial poll
  pollAllWallets();

  // Continuous polling
  setInterval(pollAllWallets, CONFIG.POLL_INTERVAL_MS);

  log('INFO', 'Watcher running. Register wallets via POST /api/watcher/register');
}

// Export for integration with server.js
module.exports = { attachToServer, registerWallet, pollAllWallets, analyzeTransaction };
