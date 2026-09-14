// Requests a manual withdrawal — the non-Paystack-Transfer path added by
// 62_migration_manual_withdrawals.sql for while Inkroot's Paystack business isn't yet verified for
// Transfers (that needs a business TIN on file; purchases/tips don't need that tier, only paying
// money OUT does). The request itself is checked against the real, server-computed balance and
// created atomically by create_manual_withdrawal_locked() — identical guarantee to
// paystack-withdraw's create_withdrawal_locked(), just without ever calling Paystack's /transfer.
//
// After the row is created, this also best-effort-pings a Telegram chat so the admin doesn't have
// to keep the Manual Withdrawals admin queue open to notice a new request. A failed or unconfigured
// notification never fails the withdrawal itself — the queue (admin_list_pending_manual_withdrawals)
// is the real source of truth and works with or without Telegram.
import { CORS_HEADERS, jsonResponse, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { bankAccountId, amountNaira } = await req.json();
    const amountKobo = Math.round(Number(amountNaira) * 100);
    if (!amountKobo || amountKobo < 10000) throw new Error('Minimum withdrawal is \u20a6100');

    const db = serviceClient();

    const { data: row, error: insertErr } = await db.rpc('create_manual_withdrawal_locked', {
      p_user_id: user.id, p_bank_account_id: bankAccountId, p_amount_kobo: amountKobo,
    }).single();
    if (insertErr) throw new Error(insertErr.message);

    try {
      const token = Deno.env.get('TELEGRAM_BOT_TOKEN');
      const chatId = Deno.env.get('TELEGRAM_CHAT_ID');
      if (token && chatId) {
        const [{ data: account }, { data: profile }] = await Promise.all([
          db.from('bank_accounts').select('bank_name, account_number, account_name').eq('id', bankAccountId).single(),
          db.from('profiles').select('pen_name, display_name').eq('id', user.id).single(),
        ]);
        const writerName = (profile && (profile.pen_name || profile.display_name)) || 'A writer';
        const text = [
          '\uD83D\uDCB8 New manual withdrawal request',
          '',
          `Writer: ${writerName}`,
          `Amount: \u20a6${(amountKobo / 100).toLocaleString('en-NG')}`,
          account ? `Bank: ${account.bank_name} \u2014 ${account.account_number} (${account.account_name})` : 'Bank: (missing)',
          '',
          'Review it in Inkroot\u2019s Manual Withdrawals admin queue.',
        ].join('\n');
        await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, text }),
        });
      }
    } catch (notifyErr) {
      // Best-effort only — see the header comment. Logged for the admin's own visibility in the
      // function's logs, never surfaced to the writer and never affects the response below.
      console.error('manual-withdraw: Telegram notification failed', notifyErr);
    }

    return jsonResponse({ withdrawal: row });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
