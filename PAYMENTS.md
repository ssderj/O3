# Naira payments (Paystack) — setup

Inkroot's payment system runs on [Paystack](https://paystack.com), which supports Nigerian
cards, bank transfer, and USSD for collecting payments, and direct bank transfers for paying
authors out. This doc is everything needed to turn it on for a deployment — nothing here runs
automatically, none of it was deployed or tested from this environment (no network access), so
budget time to actually walk through it once against a real (or test-mode) Paystack account.

## What's real vs what this doesn't cover

- Readers can buy a published book, or tip an author, in Naira — charged via Paystack's inline
  checkout popup.
- Authors can save a Nigerian bank account once and reuse it — no re-entering account details on
  every withdrawal, only when adding a different account or removing one.
- Authors can withdraw their available balance (sales + tips, minus Inkroot's platform fee — see
  `PLATFORM_FEE_BPS` in `supabase/functions/_shared/payments.ts`, currently 10%) to their default
  saved account. **Right now this goes through manual review, not an automatic Paystack Transfer**
  — see "Manual withdrawals" below for why and how to switch it back once that's no longer true.
- **Not covered** (unchanged from before): buying more than one book from the Cart happens as
  separate sequential charges, not one combined transaction; Worldbuilding Packs and Guild-only
  listings still aren't purchasable — only books published to the Grand Library are.

## 1. Get a Paystack account

Sign up at [paystack.com](https://dashboard.paystack.com/#/signup). Start in **Test Mode** (the
toggle in the dashboard) and use Paystack's test cards until everything below is verified working
— switch to Live Mode (which requires business verification) only once you're ready to move real
money.

From **Settings → API Keys & Webhooks**, copy the **Secret Key** (`sk_test_...` or `sk_live_...`).
Never put this in `.env` or anywhere client-side — it only ever goes into Supabase's Edge Function
secrets (next step).

## 2. Deploy the database migration

Run `supabase/history/32_migration_naira_payments.sql` once against your Supabase project (SQL
editor, or `supabase db push` if you use migrations that way) — it's already included at the
bottom of the consolidated `supabase/schema.sql` too, so a **fresh** install just needs
`schema.sql` as usual.

## 3. Deploy the Edge Functions

Requires the [Supabase CLI](https://supabase.com/docs/guides/cli). From the project root:

```bash
supabase login
supabase link --project-ref <your-project-ref>

# The Paystack secret key — the one thing that has to be set by hand.
supabase secrets set PAYSTACK_SECRET_KEY=sk_test_xxxxxxxxxxxx

supabase functions deploy paystack-banks
supabase functions deploy paystack-resolve-account
supabase functions deploy paystack-save-bank-account
supabase functions deploy paystack-init-purchase
supabase functions deploy paystack-webhook --no-verify-jwt
supabase functions deploy paystack-withdraw
supabase functions deploy manual-withdraw
```

`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` are already available to
every Edge Function automatically — nothing to set for those.

`paystack-webhook` is deployed with `--no-verify-jwt` because Paystack calls it directly, with no
Supabase session — its own security is the HMAC signature check inside the function (see the
`verifySignature` code in `supabase/functions/paystack-webhook/index.ts`), not Supabase's own JWT
check.

## 4. Point Paystack's webhook at your function

In the Paystack dashboard: **Settings → API Keys & Webhooks → Webhook URL**, set it to:

```
https://<your-project-ref>.functions.supabase.co/paystack-webhook
```

This is what actually confirms a payment or withdrawal succeeded — the app's own database rows
only ever flip from `pending` to `success`/`failed` once Paystack calls this URL. Nothing is
marked paid from the browser.

## 5. Test it

In Test Mode, use one of [Paystack's test cards](https://paystack.com/docs/payments/test-payments/)
to buy a paid book or send a tip, and one of their test bank accounts to save a payout account
and request a withdrawal. Check the `purchases` / `withdrawals` tables in Supabase to confirm rows
move from `pending` to `success` after the webhook fires.

## Where the money actually goes

Paystack settles collected payments to your Paystack account's own settlement bank account on
its normal schedule — Inkroot never touches funds directly. An author's "withdrawal" is a
Paystack Transfer *out of your Paystack balance* to their saved bank account, so your Paystack
account needs sufficient balance for withdrawals to succeed (this is a real operational
constraint of running a marketplace this way, not something the code can route around).

**This only applies once your Paystack business is verified** — Transfers specifically require a
registered business with a TIN on file; purchases and tips (money coming in) don't. Until then,
see "Manual withdrawals" below.

## Manual withdrawals (while your Paystack business isn't verified yet)

`create_withdrawal_locked`/`paystack-withdraw` (money out, above) need a verified Paystack
business; `paystack-init-purchase`/`paystack-webhook` (money in) don't. So a brand-new Inkroot
deployment can take real payments long before it can pay authors out automatically. Rather than
block withdrawals entirely until that's sorted, `62_migration_manual_withdrawals.sql` adds a
second withdrawal method that never calls Paystack's `/transfer` at all: a writer requests it the
same way, it's checked against the exact same real balance, but a platform admin sends the money
by hand (their own bank) and marks it settled in the app afterward. See that migration's own
comment, and `src/admin/manual-withdrawals-admin.jsx`, for the full mechanics.

**Setup, in addition to steps 1–4 above:**

1. Make your own account a platform admin — from the Supabase SQL editor (this column is
   deliberately never settable from the app itself, by anyone, including another admin — see
   `protect_admin_profile_columns` in `schema.sql`):
   ```sql
   update profiles set is_platform_admin = true where id = '<your-auth-user-id>';
   ```
   This also unlocks the existing Inkroot Events Admin screen, not just this one — same flag.
2. (Optional but recommended) Set up a Telegram bot so you get pinged the moment a request comes
   in, instead of having to keep the admin queue open: message [@BotFather](https://t.me/BotFather)
   to create a bot and get its token, then message your new bot once and fetch
   `https://api.telegram.org/bot<token>/getUpdates` to find your `chat.id`. Then:
   ```bash
   supabase secrets set TELEGRAM_BOT_TOKEN=xxxxxxxxxx
   supabase secrets set TELEGRAM_CHAT_ID=xxxxxxxxxx
   ```
   Withdrawal requests still land in the in-app queue with or without this — Telegram is a
   best-effort push alert on top, never the only way to see one (see `manual-withdraw`'s own
   comment).
3. In the app: **Author's Hall → ⚑ Manual Withdrawals admin** (only visible once `is_platform_admin`
   is set) to review and settle requests.

**Switching back once your business is verified:** flip `ACTIVE_WITHDRAWAL_METHOD` in
`src/lib/payments.js` from `'manual'` back to `'paystack'`. `create_withdrawal_locked`,
`paystack-withdraw`, and the webhook were never touched by any of this and still work exactly as
they did before — nothing to re-deploy or re-migrate.
