// surge-payment.js — Custom SURGE payment verification middleware
import { Connection, PublicKey } from '@solana/web3.js';

const SURGE_MINT = '3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg';
const OUR_WALLET = process.env.SOLANA_WALLET || '3h3hVrGh7sscWt1c2SyzTNYnWjAajDYxQVDx2eCgsoPj';
const HELIUS_RPC = `https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_KEY}`;

const connection = new Connection(HELIUS_RPC, 'confirmed');
const usedTxs = new Set();

const PRICES = {
  '/api/audit/solana':      500000000,
  '/api/audit/base':        500000000,
  '/api/watcher/register': 1200000000,
  '/v1/score':               50000000,
  '/v1/batch-score':        250000000,
  '/api/scan/skill':        500000000,
};

export async function surgePaymentMiddleware(req, res, next) {
  const txSig = req.headers['x-surge-tx'];
  if (!txSig) return next();

  try {
    if (usedTxs.has(txSig)) {
      return res.status(402).json({ error: 'Transaction already used' });
    }

    const tx = await connection.getParsedTransaction(txSig, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });

    if (!tx || !tx.meta || tx.meta.err) {
      return res.status(402).json({ error: 'Transaction not found or failed' });
    }

    const blockTime = tx.blockTime;
    if (!blockTime || (Date.now() / 1000 - blockTime > 300)) {
      return res.status(402).json({ error: 'Transaction too old (>5 min)' });
    }

    const preBalances = tx.meta.preTokenBalances || [];
    const postBalances = tx.meta.postTokenBalances || [];
    let receivedAmount = 0n;

    for (const post of postBalances) {
      if (post.mint === SURGE_MINT && post.owner === OUR_WALLET) {
        const pre = preBalances.find(p => p.accountIndex === post.accountIndex);
        const preAmt = pre ? BigInt(pre.uiTokenAmount.amount) : 0n;
        const postAmt = BigInt(post.uiTokenAmount.amount);
        const delta = postAmt - preAmt;
        if (delta > 0n) receivedAmount += delta;
      }
    }

    if (receivedAmount === 0n) {
      return res.status(402).json({ error: 'No SURGE received' });
    }

    const price = PRICES[req.path];
    if (!price) {
      return res.status(402).json({ error: 'No SURGE price for this endpoint' });
    }

    if (receivedAmount < BigInt(price)) {
      return res.status(402).json({ error: 'Insufficient SURGE', required: price.toString(), received: receivedAmount.toString() });
    }

    usedTxs.add(txSig);
    if (usedTxs.size > 10000) {
      Array.from(usedTxs).slice(0, 5000).forEach(t => usedTxs.delete(t));
    }

    req.surgePaid = true;
    req.surgeTx = txSig;
    console.log(`[SURGE] Paid: ${txSig} | ${receivedAmount.toString()} raw | ${req.path}`);
    next();

  } catch (error) {
    console.error('[SURGE] Error:', error.message);
    return res.status(402).json({ error: 'SURGE verification failed' });
  }
}
