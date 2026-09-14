// Proxies Paystack's bank list so the client never needs the Paystack secret key just to
// populate a "which bank" dropdown when saving an account. Signed-in users only (not because the
// list itself is sensitive, but because there's no reason for it to be callable by someone not
// using the app).
import { CORS_HEADERS, jsonResponse, paystack, requireUser } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  try {
    await requireUser(req);
    const data = await paystack('/bank?country=nigeria&currency=NGN&perPage=100');
    const banks = (data.data || []).map((b: any) => ({ name: b.name, code: b.code }));
    return jsonResponse({ banks });
  } catch (e) {
    return jsonResponse({ error: e.message }, 400);
  }
});
