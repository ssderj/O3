// Saves a bank account for withdrawals: re-verifies the account (never trusts an accountName the
// client sends — same reasoning as paystack-resolve-account), creates a Paystack Transfer
// Recipient for it, and stores the result. This is the function that makes "saved bank account"
// real — after this, a withdrawal never needs the account number again, only bank_accounts.id.
import { CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { accountNumber, bankCode, makeDefault } = await req.json();
    if (!/^\d{10}$/.test(accountNumber || '')) throw new Error('Enter a valid 10-digit account number');
    if (!bankCode) throw new Error('Choose a bank');

    const resolved = await paystack(`/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`);
    const accountName = resolved.data.account_name;

    const banks = await paystack('/bank?country=nigeria&currency=NGN&perPage=100');
    const bank = (banks.data || []).find((b: any) => b.code === bankCode);
    if (!bank) throw new Error('Unrecognized bank');

    const recipient = await paystack('/transferrecipient', {
      method: 'POST',
      body: JSON.stringify({
        type: 'nuban',
        name: accountName,
        account_number: accountNumber,
        bank_code: bankCode,
        currency: 'NGN',
      }),
    });

    const db = serviceClient();
    const isFirst = (await db.from('bank_accounts').select('id').eq('user_id', user.id)).data?.length === 0;
    const wantDefault = makeDefault !== false || isFirst;

    if (wantDefault) {
      await db.from('bank_accounts').update({ is_default: false }).eq('user_id', user.id);
    }

    const { data: row, error } = await db.from('bank_accounts').insert({
      user_id: user.id,
      bank_code: bankCode,
      bank_name: bank.name,
      account_number: accountNumber,
      account_name: accountName,
      paystack_recipient_code: recipient.data.recipient_code,
      is_default: wantDefault,
    }).select().single();
    if (error) throw new Error(error.message);

    return jsonResponse({ bankAccount: row });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
