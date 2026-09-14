// Confirms an account number actually belongs to a real account, and returns the name on it, so
// the "save a bank account" screen can show the user "this is whose account you're about to
// save" before they confirm — rather than trusting whatever they typed.
import { CORS_HEADERS, jsonResponse, paystack, requireUser } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    await requireUser(req);
    const { accountNumber, bankCode } = await req.json();
    if (!/^\d{10}$/.test(accountNumber || '')) throw new Error('Enter a valid 10-digit account number');
    if (!bankCode) throw new Error('Choose a bank');

    const data = await paystack(`/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`);
    return jsonResponse({ accountName: data.data.account_name });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
