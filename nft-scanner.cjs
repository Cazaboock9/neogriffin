// ============================================
// 🖼️ Aegis NFT Scanner — NFT & cNFT Security
// /root/aegis-server/nft-scanner.js
// ============================================

const https = require('https');
const http = require('http');

// Reuse injection patterns from server
let INJECTION_PATTERNS = [];
let HELIUS_KEY = '';

// Suspicious domain patterns for phishing detection
const PHISHING_INDICATORS = [
  /bit\.ly/i, /tinyurl/i, /t\.co/i,          // URL shorteners
  /discord\.gg/i, /t\.me\//i,                  // Social links in NFT metadata
  /\.xyz\//i, /\.tk\//i, /\.ml\//i,           // Cheap/suspicious TLDs
  /free-?mint/i, /free-?claim/i, /free-?drop/i, // Phishing bait
  /claim-?your/i, /airdrop-?claim/i,
  /connect.*wallet/i, /verify.*wallet/i,        // Wallet phishing
  /\.exe$/i, /\.bat$/i, /\.cmd$/i,             // Executable links
  /data:text\/html/i,                           // Data URI attacks
];

const SUSPICIOUS_DOMAINS = [
  'solana-claim', 'sol-airdrop', 'free-sol', 'nft-mint-free',
  'phantom-verify', 'solflare-claim', 'magic-eden-free',
  'tensor-airdrop', 'jupiter-claim',
];

function init(patterns, heliusKey) {
  INJECTION_PATTERNS = patterns;
  HELIUS_KEY = heliusKey;
}

// Fetch NFTs using Helius DAS API
function fetchNFTs(walletAddress) {
  return new Promise((resolve, reject) => {
    const url = `https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY}`;
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 'aegis-nft',
      method: 'getAssetsByOwner',
      params: {
        ownerAddress: walletAddress,
        page: 1,
        limit: 50,
        displayOptions: { showUnverifiedCollections: true, showNativeBalance: false },
      },
    });

    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.result && parsed.result.items) {
            resolve(parsed.result.items);
          } else {
            resolve([]);
          }
        } catch (e) {
          reject(new Error('Failed to parse Helius response'));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Helius timeout')); });
    req.write(body);
    req.end();
  });
}

// Scan NFT metadata for threats
function scanNFTMetadata(nft) {
  const threats = [];
  let severity = 'safe';
  const severityOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

  const name = nft.content?.metadata?.name || '';
  const description = nft.content?.metadata?.description || '';
  const symbol = nft.content?.metadata?.symbol || '';
  const imageUri = nft.content?.links?.image || nft.content?.files?.[0]?.uri || '';
  const externalUrl = nft.content?.links?.external_url || '';
  const attributes = nft.content?.metadata?.attributes || [];

  // 1. Injection scan on name + description + symbol
  const textToScan = `${name} ${description} ${symbol}`;
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.regex && pattern.regex.test(textToScan)) {
      threats.push({
        type: 'metadata_injection',
        detail: `${pattern.name} detected in metadata`,
        severity: pattern.severity || 'high',
        field: 'name/description',
      });
      if (severityOrder[pattern.severity] > severityOrder[severity]) {
        severity = pattern.severity;
      }
    }
  }

  // 2. Injection scan on attributes
  for (const attr of attributes) {
    const attrText = `${attr.trait_type || ''} ${attr.value || ''}`;
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex && pattern.regex.test(attrText)) {
        threats.push({
          type: 'attribute_injection',
          detail: `${pattern.name} in attribute "${attr.trait_type}"`,
          severity: pattern.severity || 'high',
          field: 'attributes',
        });
        if (severityOrder[pattern.severity] > severityOrder[severity]) {
          severity = pattern.severity;
        }
        break; // One per attribute
      }
    }
  }

  // 3. Phishing link detection in image/external URLs
  const urlsToCheck = [imageUri, externalUrl, description];
  for (const url of urlsToCheck) {
    if (!url) continue;
    for (const phish of PHISHING_INDICATORS) {
      if (phish.test(url)) {
        threats.push({
          type: 'phishing_link',
          detail: `Suspicious URL pattern: ${phish.source}`,
          severity: 'high',
          field: 'url',
        });
        if (severityOrder['high'] > severityOrder[severity]) severity = 'high';
        break;
      }
    }
    // Check suspicious domains
    for (const domain of SUSPICIOUS_DOMAINS) {
      if (url.toLowerCase().includes(domain)) {
        threats.push({
          type: 'phishing_domain',
          detail: `Known phishing domain pattern: ${domain}`,
          severity: 'critical',
          field: 'url',
        });
        severity = 'critical';
        break;
      }
    }
  }

  // 4. Creator verification check
  const creators = nft.creators || [];
  const hasVerifiedCreator = creators.some(c => c.verified === true);
  if (creators.length > 0 && !hasVerifiedCreator) {
    threats.push({
      type: 'unverified_creator',
      detail: 'No verified creator — could be a fake collection',
      severity: 'medium',
      field: 'creator',
    });
    if (severityOrder['medium'] > severityOrder[severity]) severity = 'medium';
  }

  // 5. Collection verification
  const collection = nft.grouping?.find(g => g.group_key === 'collection');
  const isCollectionVerified = collection?.verified || false;
  if (collection && !isCollectionVerified) {
    threats.push({
      type: 'unverified_collection',
      detail: 'Unverified collection — may be a counterfeit',
      severity: 'medium',
      field: 'collection',
    });
    if (severityOrder['medium'] > severityOrder[severity]) severity = 'medium';
  }

  // 6. Burnt/frozen check
  if (nft.burnt) {
    threats.push({
      type: 'burnt_nft',
      detail: 'This NFT has been burnt',
      severity: 'low',
      field: 'status',
    });
  }

  return {
    id: nft.id,
    name: name || 'Unknown NFT',
    symbol: symbol || '',
    description: (description || '').slice(0, 200),
    image: imageUri,
    isCompressed: nft.compression?.compressed || false,
    collection: collection?.group_value || null,
    collectionVerified: isCollectionVerified,
    creatorVerified: hasVerifiedCreator,
    threats,
    severity,
    isThreat: threats.length > 0,
    threatCount: threats.length,
  };
}

// Attach endpoints to Express app
function attachToServer(app) {
  // Scan all NFTs in a wallet
  app.post('/api/nft/scan', async (req, res) => {
    const { wallet } = req.body;
    if (!wallet || typeof wallet !== 'string' || wallet.length < 32 || wallet.length > 44) {
      return res.status(400).json({ error: 'Valid wallet address required' });
    }

    if (!HELIUS_KEY) {
      return res.status(503).json({ error: 'Helius API not configured' });
    }

    try {
      const nfts = await fetchNFTs(wallet);
      const results = nfts.map(nft => scanNFTMetadata(nft));

      const summary = {
        total: results.length,
        clean: results.filter(r => !r.isThreat).length,
        suspicious: results.filter(r => r.isThreat).length,
        compressed: results.filter(r => r.isCompressed).length,
        standard: results.filter(r => !r.isCompressed).length,
        critical: results.filter(r => r.severity === 'critical').length,
        high: results.filter(r => r.severity === 'high').length,
        medium: results.filter(r => r.severity === 'medium').length,
      };

      res.json({
        wallet,
        summary,
        nfts: results,
        scannedAt: new Date().toISOString(),
      });
    } catch (e) {
      console.error('NFT scan error:', e.message);
      res.status(500).json({ error: 'Failed to scan NFTs', detail: e.message });
    }
  });

  // Scan a single NFT by mint
  app.get('/api/nft/:mint', async (req, res) => {
    const { mint } = req.params;
    if (!mint || mint.length < 32 || mint.length > 44) {
      return res.status(400).json({ error: 'Valid mint address required' });
    }

    if (!HELIUS_KEY) {
      return res.status(503).json({ error: 'Helius API not configured' });
    }

    try {
      const url = `https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY}`;
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: 'aegis-nft-single',
        method: 'getAsset',
        params: { id: mint },
      });

      const result = await new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const options = {
          hostname: urlObj.hostname,
          path: urlObj.pathname + urlObj.search,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          timeout: 10000,
        };
        const req2 = https.request(options, (res2) => {
          let data = '';
          res2.on('data', chunk => data += chunk);
          res2.on('end', () => {
            try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
          });
        });
        req2.on('error', reject);
        req2.on('timeout', () => { req2.destroy(); reject(new Error('timeout')); });
        req2.write(body);
        req2.end();
      });

      if (result.result) {
        const scanResult = scanNFTMetadata(result.result);
        res.json(scanResult);
      } else {
        res.status(404).json({ error: 'NFT not found' });
      }
    } catch (e) {
      console.error('Single NFT scan error:', e.message);
      res.status(500).json({ error: 'Failed to scan NFT' });
    }
  });

  console.log('  🖼️  NFT Scanner: loaded');
}

module.exports = { init, attachToServer };
