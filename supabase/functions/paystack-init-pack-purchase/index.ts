// Starts a real Naira payment for a Worldbuilding Pack (fix-tracker item 20). Mirrors
// paystack-init-purchase's 'book' path closely, with one deliberate difference: a free pack
// (price 0) still needs a durable purchases row (the app owner's own call — same audit-trail
// consistency every other purchase kind gets), but Paystack itself won't process a zero-amount
// charge — so a free pack's row is written directly as `success` here, with no Paystack call at
// all, rather than ever reaching the popup.
import { authorAmountKobo, CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { packId } = await req.json();

    const db = serviceClient();
    const { data: pack, error: packErr } = await db.from('published_packs')
      .select('id, author_id, price, title').eq('id', packId).single();
    if (packErr || !pack) throw new Error('Pack not found');
    if (pack.author_id === user.id) throw new Error("You can't buy your own pack");

    const reference = `inkroot_pack_${crypto.randomUUID()}`;
    const priceNaira = typeof pack.price === 'number' ? pack.price : 0;

    if (!priceNaira || priceNaira <= 0) {
      // Free pack: record it as a $0 purchases row, already settled — this is also what grants
      // download access, since published_pack_content's own RLS checks for exactly this
      // (buyer_id, pack_id, status = 'success') row, free or paid alike.
      const { error: insertErr } = await db.from('purchases').insert({
        paystack_reference: reference,
        buyer_id: user.id,
        author_id: pack.author_id,
        kind: 'pack',
        pack_id: pack.id,
        amount_kobo: 0,
        author_amount_kobo: 0,
        status: 'success',
        paid_at: new Date().toISOString(),
      });
      if (insertErr) throw new Error(insertErr.message);
      return jsonResponse({ reference, free: true });
    }

    const amountKobo = Math.round(priceNaira * 100);

    const { data: authorProfile } = await db.from('profiles').select('display_name').eq('id', pack.author_id).single();

    const { data: authUser } = await db.auth.admin.getUserById(user.id);
    const email = authUser?.user?.email;
    if (!email) throw new Error('Your account has no email on file — cannot start checkout');

    const { error: insertErr } = await db.from('purchases').insert({
      paystack_reference: reference,
      buyer_id: user.id,
      author_id: pack.author_id,
      kind: 'pack',
      pack_id: pack.id,
      amount_kobo: amountKobo,
      author_amount_kobo: authorAmountKobo(amountKobo),
      status: 'pending',
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
          kind: 'pack',
          pack_title: pack.title,
          author_name: authorProfile?.display_name || 'this writer',
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
