// Read-only: hands back PLATFORM_FEE_BPS (see _shared/payments.ts) so the client can show
// Inkroot's per-entry platform cut — e.g. in the hosting-fee/revenue breakdown a guild owner
// reviews before publishing an event (see 47_migration_guild_event_hosting_fee.sql) — without a
// second copy of the constant living in the frontend that could drift from what
// paystack-init-event-entry/paystack-init-purchase actually charge. No auth required: this is
// the same number for every event/purchase, not something scoped to a caller.
import { CORS_HEADERS, jsonResponse, PLATFORM_FEE_BPS } from '../_shared/payments.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  return jsonResponse({ platformFeeBps: PLATFORM_FEE_BPS });
});
