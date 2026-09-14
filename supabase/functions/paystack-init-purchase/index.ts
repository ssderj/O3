// Starts a real Naira payment: either buying a published book, or tipping its author directly.
// Creates a `pending` purchases row (server-side, so the amount/author on record can never be
// something the client made up) and returns a Paystack access_code the browser hands to
// Paystack's own inline checkout. Nothing is marked paid here — only paystack-webhook, once
// Paystack itself confirms the charge, does that.
import { authorAmountKobo, CORS_HEADERS, jsonResponse, paystack, requireUser, serviceClient } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    const { user } = await requireUser(req);
    const { kind, bookId, amountNaira } = await req.json();
    if (!['book', 'tip'].includes(kind)) throw new Error('Invalid purchase kind');

    const db = serviceClient();
    const { data: book, error: bookErr } = await db.from('published_books')
      .select('id, author_id, price, title').eq('id', bookId).single();
    if (bookErr || !book) throw new Error('Book not found');
    if (book.author_id === user.id) throw new Error("You can't buy or tip your own book");

    let amountKobo: number;
    if (kind === 'book') {
      if (!book.price || book.price <= 0) throw new Error('This book is free — no payment needed');
      amountKobo = Math.round(book.price * 100);
    } else {
      const naira = Number(amountNaira);
      if (!naira || naira < 100) throw new Error('Minimum tip is \u20a6100');
      amountKobo = Math.round(naira * 100);
    }

    const { data: authorProfile } = await db.from('profiles').select('display_name').eq('id', book.author_id).single();

    const { data: authUser } = await db.auth.admin.getUserById(user.id);
    const email = authUser?.user?.email;
    if (!email) throw new Error('Your account has no email on file — cannot start checkout');

    const reference = `inkroot_${kind}_${crypto.randomUUID()}`;

    const { error: insertErr } = await db.from('purchases').insert({
      paystack_reference: reference,
      buyer_id: user.id,
      author_id: book.author_id,
      kind,
      book_id: kind === 'book' ? book.id : null,
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
          kind,
          book_title: book.title,
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
