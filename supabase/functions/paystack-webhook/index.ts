// The single source of truth for "did the money actually move". Paystack calls this URL
// directly (configure it in the Paystack dashboard, not from the app) for both transaction
// events (reader payments) and transfer events (author withdrawals). Every signature is
// verified against PAYSTACK_SECRET_KEY before anything in the request body is trusted — this is
// the one function that's allowed to flip a purchases/withdrawals row to success or failed;
// nothing else in the codebase does.
import { CORS_HEADERS, serviceClient } from '../_shared/payments.ts';

// Constant-time comparison — a plain `===` on two hex strings short-circuits at the first
// mismatched character, which leaks (via response timing) how many leading characters an
// attacker's guess got right. Both inputs here are fixed-length hex (SHA-512 HMAC, 128 chars),
// so walking the full length unconditionally costs nothing extra in the normal case, and closes
// that side channel for what is otherwise the only gate deciding whether a request gets to flip
// a purchases/withdrawals row to success.
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifySignature(rawBody: string, signature: string | null): Promise<boolean> {
  if (!signature) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(Deno.env.get('PAYSTACK_SECRET_KEY')!),
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody));
  const hex = Array.from(new Uint8Array(mac)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return timingSafeEqual(hex, signature);
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  const rawBody = await req.text();
  const valid = await verifySignature(rawBody, req.headers.get('x-paystack-signature'));
  if (!valid) return new Response('Invalid signature', { status: 401 });

  const event = JSON.parse(rawBody);
  const db = serviceClient();

  try {
    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      // A charge reference belongs to exactly one of these three tables (paystack-init-purchase,
      // paystack-init-event-entry, and paystack-init-hosting-fee each mint their own mutually
      // exclusive prefix), so running all three updates is safe — whichever table doesn't have a
      // matching pending row just updates zero rows. All three are idempotent the same way:
      // Paystack may retry the same event, and a retry only ever matches a row that's still
      // 'pending', so it can never re-fire twice.
      await db.from('purchases')
        .update({ status: 'success', paid_at: new Date().toISOString() })
        .eq('paystack_reference', reference)
        .eq('status', 'pending');
      await db.from('guild_event_entries')
        .update({ status: 'success', paid_at: new Date().toISOString() })
        .eq('paystack_reference', reference)
        .eq('status', 'pending');
      await db.from('guild_event_hosting_fee_payments')
        .update({ status: 'success', paid_at: new Date().toISOString() })
        .eq('paystack_reference', reference)
        .eq('status', 'pending');
    } else if (event.event === 'transfer.success') {
      await db.from('withdrawals')
        .update({ status: 'success', completed_at: new Date().toISOString() })
        .eq('paystack_transfer_code', event.data.transfer_code)
        .eq('status', 'pending');
    } else if (event.event === 'transfer.failed' || event.event === 'transfer.reversed') {
      // transfer.failed always arrives while the row is still 'pending' (the transfer never
      // succeeded), but transfer.reversed can arrive AFTER transfer.success already flipped the
      // row to 'success' — the receiving bank accepted the transfer, then reversed it later. Both
      // are matched here so a reversal is never silently ignored: author_balance_kobo() only
      // counts a withdrawal that's still 'pending' or 'success' against the writer's balance, so
      // flipping a reversed transfer to 'failed' is what actually gives the writer their balance
      // back to withdraw again.
      await db.from('withdrawals')
        .update({ status: 'failed', failure_reason: event.data.reason || event.event })
        .eq('paystack_transfer_code', event.data.transfer_code)
        .in('status', ['pending', 'success']);
    } else if (event.event === 'refund.processed' || event.event === 'charge.dispute.create') {
      // A buyer's bank dispute or a Paystack-processed refund on a charge that had already been
      // marked 'success' — see 50_migration_economy_security_audit.sql for why 'refunded' exists
      // and what excluding it from status = 'success' actually does downstream (author_balance_
      // kobo and settle_guild_event's pool sum both already only count 'success' rows). Paystack
      // nests the original charge reference differently across these two event types, so every
      // known location is tried; whichever of the three tables actually has a matching 'success'
      // row is the one this updates — the other two just match zero rows, same "safe to run all
      // three" reasoning charge.success above already relies on. Only a currently-'success' row
      // is ever touched — a still-'pending' or already-'failed' row is left alone, so this can
      // never manufacture a credit that charge.success itself never granted.
      const reference = event.data.reference || event.data.transaction?.reference || event.data.transaction_reference;
      if (reference) {
        await db.from('purchases')
          .update({ status: 'refunded' })
          .eq('paystack_reference', reference)
          .eq('status', 'success');
        await db.from('guild_event_entries')
          .update({ status: 'refunded' })
          .eq('paystack_reference', reference)
          .eq('status', 'success');
        await db.from('guild_event_hosting_fee_payments')
          .update({ status: 'refunded' })
          .eq('paystack_reference', reference)
          .eq('status', 'success');
      }
    }
    // Any other event type: acknowledge and ignore, nothing here needs it.
    return new Response('ok', { status: 200, headers: CORS_HEADERS });
  } catch (e) {
    // Still 200 — a webhook retry storm from a 500 here doesn't help; log and move on.
    console.error('paystack-webhook error:', e.message);
    return new Response('ok', { status: 200, headers: CORS_HEADERS });
  }
});
