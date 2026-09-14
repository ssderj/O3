// Pays an author out to one of their saved bank accounts. The requested amount is checked
// against the real, server-computed balance and the withdrawal row is created atomically by
// create_withdrawal_locked() (see 50_migration_economy_security_audit.sql) — a client can't
// withdraw more than it's actually owed no matter what it sends, and two concurrent requests
// can't both slip past the balance check the way two separate round trips from this function
// once could.
import { CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { bankAccountId, amountNaira } = await req.json();
    const amountKobo = Math.round(Number(amountNaira) * 100);
    if (!amountKobo || amountKobo < 10000) throw new Error('Minimum withdrawal is \u20a6100');

    const db = serviceClient();

    const { data: row, error: insertErr } = await db.rpc('create_withdrawal_locked', {
      p_user_id: user.id, p_bank_account_id: bankAccountId, p_amount_kobo: amountKobo,
    }).single();
    if (insertErr) throw new Error(insertErr.message);

    const { data: account, error: acctErr } = await db.from('bank_accounts')
      .select('*').eq('id', bankAccountId).eq('user_id', user.id).single();
    if (acctErr || !account) throw new Error('Saved bank account not found');

    try {
      const transfer = await paystack('/transfer', {
        method: 'POST',
        body: JSON.stringify({
          source: 'balance',
          amount: amountKobo,
          recipient: account.paystack_recipient_code,
          reason: 'Inkroot earnings withdrawal',
          reference: row.id,
        }),
      });
      await db.from('withdrawals').update({ paystack_transfer_code: transfer.data.transfer_code }).eq('id', row.id);
    } catch (transferErr) {
      // Paystack rejected the transfer outright (e.g. insufficient platform balance) — fail the
      // row now rather than leaving it pending forever with no transfer_code for the webhook to
      // ever match against.
      await db.from('withdrawals').update({ status: 'failed', failure_reason: transferErr.message }).eq('id', row.id);
      throw transferErr;
    }

    return jsonResponse({ withdrawal: row });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
