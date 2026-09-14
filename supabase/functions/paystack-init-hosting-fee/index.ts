// Starts (or, for a currently-configured 0-kobo fee, immediately records) the one hosting-fee
// payment a guild owner owes Inkroot for a host='guild' event before it can move approved ->
// published — see 47_migration_guild_event_hosting_fee.sql. Same shape as
// paystack-init-event-entry: creates the pending row server-side (so the fee on record can never
// be something the client made up — it's read fresh from current_guild_event_hosting_fee(), not
// passed in by the caller) and returns a Paystack access_code for the browser's inline checkout.
// Nothing is marked paid here except the 0-kobo case — paystack-webhook, once Paystack itself
// confirms the charge, does that for every real charge.
import { CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { eventId } = await req.json();

    const db = serviceClient();
    const { data: event, error: eventErr } = await db.from('guild_events')
      .select('id, guild_id, host, title, entry_fee_kobo, approval_status').eq('id', eventId).single();
    if (eventErr || !event) throw new Error('Event not found');

    const { data: guild } = await db.from('player_guilds').select('id, owner_id').eq('id', event.guild_id).single();
    if (!guild || guild.owner_id !== user.id) throw new Error('Only the guild owner can pay this event\u2019s hosting fee');
    if (event.host !== 'guild') throw new Error('This event has no hosting fee to pay');
    if (event.approval_status !== 'approved') throw new Error('This event needs Inkroot approval before its hosting fee can be paid');

    const { data: existing } = await db.from('guild_event_hosting_fee_payments')
      .select('id, status, fee_kobo').eq('event_id', eventId).maybeSingle();
    if (existing && existing.status === 'success') throw new Error('The hosting fee for this event has already been paid');

    const { data: rate, error: rateErr } = await db.rpc('current_guild_event_hosting_fee').single();
    if (rateErr || !rate) throw new Error('No hosting fee is currently configured \u2014 contact Inkroot');
    const feeKobo = rate.fee_kobo;

    // Nothing to charge: record it paid outright rather than opening a ₦0 Paystack checkout.
    if (feeKobo <= 0) {
      const { error: upsertErr } = await db.from('guild_event_hosting_fee_payments').upsert({
        id: existing?.id,
        event_id: eventId,
        guild_id: event.guild_id,
        rate_id: rate.rate_id,
        fee_kobo: 0,
        status: 'success',
        paid_by: user.id,
        paid_at: new Date().toISOString(),
      }, { onConflict: 'event_id' });
      if (upsertErr) throw new Error(upsertErr.message);
      return jsonResponse({ feeKobo: 0, requiresPayment: false });
    }

    const { data: authUser } = await db.auth.admin.getUserById(user.id);
    const email = authUser?.user?.email;
    if (!email) throw new Error('Your account has no email on file — cannot start checkout');

    const reference = `inkroot_hosting_fee_${crypto.randomUUID()}`;

    const { error: upsertErr } = await db.from('guild_event_hosting_fee_payments').upsert({
      id: existing?.id,
      event_id: eventId,
      guild_id: event.guild_id,
      rate_id: rate.rate_id,
      fee_kobo: feeKobo,
      status: 'pending',
      paystack_reference: reference,
      paid_by: user.id,
    }, { onConflict: 'event_id' });
    if (upsertErr) throw new Error(upsertErr.message);

    const tx = await paystack('/transaction/initialize', {
      method: 'POST',
      body: JSON.stringify({
        email,
        amount: feeKobo,
        currency: 'NGN',
        reference,
        metadata: {
          kind: 'guild_event_hosting_fee',
          event_title: event.title,
        },
      }),
    });

    return jsonResponse({
      feeKobo,
      requiresPayment: true,
      reference,
      accessCode: tx.data.access_code,
      authorizationUrl: tx.data.authorization_url,
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
