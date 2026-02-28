import { Connection, Keypair, PublicKey, Transaction } from '@solana/web3.js';
import { getAssociatedTokenAddress, createTransferInstruction, getOrCreateAssociatedTokenAccount } from '@solana/spl-token';
import fs from 'fs';

const HELIUS_RPC = 'https://mainnet.helius-rpc.com/?api-key=efdc9852-5f33-464f-8015-c368e754d6c6';
const SERVER_URL = 'http://localhost:3847';
const SURGE_MINT = new PublicKey('3z2tRjNuQjoq6UDcw4zyEPD1Eb5KXMPYb4GWFzVT1DPg');
const SERVER_WALLET = new PublicKey('3h3hVrGh7sscWt1c2SyzTNYnWjAajDYxQVDx2eCgsoPj');
const SURGE_DECIMALS = 8;

const buyerKey = JSON.parse(fs.readFileSync('/root/aegis-server/surge-buyer.json'));
const buyer = Keypair.fromSecretKey(Uint8Array.from(buyerKey));
const connection = new Connection(HELIUS_RPC, 'confirmed');

console.log(`\n🔑 Buyer: ${buyer.publicKey.toBase58()}`);

async function sendSurge(amount) {
  const rawAmount = Math.round(amount * 10 ** SURGE_DECIMALS);

  const buyerAta = await getAssociatedTokenAddress(SURGE_MINT, buyer.publicKey);
  const serverAta = await getOrCreateAssociatedTokenAccount(connection, buyer, SURGE_MINT, SERVER_WALLET);

  const tx = new Transaction().add(
    createTransferInstruction(buyerAta, serverAta.address, buyer.publicKey, rawAmount)
  );

  const sig = await connection.sendTransaction(tx, [buyer]);
  await connection.confirmTransaction(sig, 'confirmed');
  console.log(`💸 Sent ${amount} SURGE | TX: ${sig}`);
  return sig;
}

async function testEndpoint(name, url, surgeAmount) {
  console.log(`\n--- ${name} ---`);
  const sig = await sendSurge(surgeAmount);

  // Small delay for confirmation
  await new Promise(r => setTimeout(r, 2000));

  const res = await fetch(url, { headers: { 'X-SURGE-TX': sig } });
  const data = await res.json();

  if (res.status === 200) {
    console.log(`✅ PAID WITH SURGE! Status: ${res.status}`);
    console.log(`   Result: ${JSON.stringify(data).slice(0, 120)}...`);
  } else {
    console.log(`❌ Failed. Status: ${res.status}`);
    console.log(`   Error: ${JSON.stringify(data)}`);
  }
}

async function main() {
  try {
    const bal = await connection.getTokenAccountBalance(
      await getAssociatedTokenAddress(SURGE_MINT, buyer.publicKey)
    );
    console.log(`💰 SURGE balance: ${bal.value.uiAmountString}`);

    await testEndpoint(
      'TEST 1: Solana audit (5 SURGE)',
      `${SERVER_URL}/api/audit/solana?mint=DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263`,
      5
    );

    await testEndpoint(
      'TEST 2: v1/score (0.5 SURGE)',
      `${SERVER_URL}/v1/score?address=DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263&chain=solana`,
      0.5
    );

    console.log('\n🎉 SURGE mainnet tests complete!');
  } catch (err) {
    console.error('Error:', err.message);
  }
}

main();
