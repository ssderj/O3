// Starts a real Naira payment to enter a host='guild' Guild Event (see
// 42_migration_guild_events.sql). Same shape as paystack-init-purchase: creates a `pending`
// guild_event_entries row server-side (so the amount/entrant on record can never be something
// the client made up) and returns a Paystack access_code the browser hands to Paystack's own
// inline checkout. Nothing is marked paid here — only paystack-webhook, once Paystack itself
// confirms the charge, does that. There is no equivalent function for host='inkroot' events —
// those have no entry fee and nothing for a reader to pay.
//
// The duplicate-entry check, the participant_limit check, and the row insert itself all happen
// inside create_guild_event_entry_locked() (see 50_migration_economy_security_audit.sql) under
// one advisory lock keyed to the event, so two simultaneous entry attempts — or an entry racing
// this event's own settlement — can't both slip past checks that used to be separate,
// unserialized round trips from this function.
import { authorAmountKobo, CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { eventId } = await req.json();

    const db = serviceClient();
    const { data: event, error: eventErr } = await db.from('guild_events')
      .select('id, guild_id, host, title, entry_fee_kobo, status, approval_status, participant_limit').eq('id', eventId).single();
    if (eventErr || !event) throw new Error('Event not found');
    if (event.host !== 'guild') throw new Error('This event has no entry fee to pay');

    // Net of Inkroot's platform fee, using the exact same formula/constant as an ordinary book
    // sale — see authorAmountKobo in _shared/payments.ts. This is what counts toward the
    // event's prize pool at settlement (guild_event_entries.net_kobo), computed once here so it
    // can never drift from what was actually charged.
    const amountKobo = event.entry_fee_kobo;
    const netKobo = authorAmountKobo(amountKobo);

    const { data: authUser } = await db.auth.admin.getUserById(user.id);
    const email = authUser?.user?.email;
    if (!email) throw new Error('Your account has no email on file — cannot start checkout');

    const reference = `inkroot_event_entry_${crypto.randomUUID()}`;

    const { error: insertErr } = await db.rpc('create_guild_event_entry_locked', {
      p_user_id: user.id, p_event_id: eventId, p_paystack_reference: reference,
      p_amount_kobo: amountKobo, p_net_kobo: netKobo,
    });
    if (insertErr) throw new Error(insertErr.message);

    const tx = await paystack('/transaction/initialize', {
      method: 'POST',
      body: JSON.stringify({
        email,
        amount: amountKobo,
        currency: 'NGN',
        reference,
        metadata: {
          kind: 'guild_event_entry',
          event_title: event.title,
        },
      }),
    });

    return jsonResponse({
      reference,
      accessCode: tx.data.access_code,
      authorizationUrl: tx.data.authorization_url,
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
