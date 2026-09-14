import { supabase } from './supabaseClient.js';

// ---------- Naira formatting ----------
// Inkroot's payment system runs in Naira (see supabase/history/32_migration_naira_payments.sql)
// — published_books.price and every amount here is a plain Naira number, converted to kobo only
// at the edge (right before it's sent to Paystack, and right after it comes back from a query
// that stores kobo).
export function formatNaira(amountNaira) {
    if (!amountNaira || amountNaira <= 0) return 'Free';
    return `\u20a6${Number(amountNaira).toLocaleString('en-NG', { maximumFractionDigits: 2 })}`;
}

export function koboToNaira(amountKobo) {
    return Math.round(amountKobo) / 100;
}

// Exported so other real-money flows outside this file (guild-events.js's event-entry checkout)
// can reuse the exact same edge-function error unwrapping instead of a second copy of it.
export async function invoke(name, body) {
    const { data, error } = await supabase.functions.invoke(name, { body });
    if (error) {
        // supabase-js only gives a generic error for a non-2xx response — the function's own
        // { error: "..." } body (via jsonResponse in _shared/payments.ts) is what actually
        // explains what went wrong, so surface that instead when it's there.
        const detail = await error.context?.json?.().catch(() => null);
        throw new Error(detail?.error || error.message);
    }
    if (data?.error) throw new Error(data.error);
    return data;
}

// ---------- Checkout (readers paying for a book or tipping an author) ----------

let paystackScriptPromise = null;
// Exported for the same reason as invoke() above — one script loader, not one per checkout flow.
export function loadPaystackScript() {
    if (window.PaystackPop) return Promise.resolve();
    if (!paystackScriptPromise) {
        paystackScriptPromise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://js.paystack.co/v2/inline.js';
            script.onload = resolve;
            script.onerror = () => reject(new Error('Could not load Paystack — check your connection.'));
            document.head.appendChild(script);
        });
    }
    return paystackScriptPromise;
}

// Polls the purchases row for `reference` until the webhook (see
// supabase/functions/paystack-webhook) flips it to success/failed, or timeoutMs runs out.
// Paystack's own popup already confirmed the charge to the browser by the time this runs — this
// is just waiting for Inkroot's own record of it to catch up, which is normally near-instant.
async function waitForPurchaseSettled(reference, timeoutMs = 20000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        const { data } = await supabase.from('purchases').select('status').eq('paystack_reference', reference).single();
        if (data && data.status !== 'pending') return data.status;
        await new Promise((r) => setTimeout(r, 1500));
    }
    return 'pending'; // webhook hasn't landed yet — caller shows "still processing" rather than failing
}

// kind: 'book' | 'tip'. amountNaira only matters for a tip (a book's price is looked up
// server-side from published_books, never trusted from here). Returns the final status:
// 'success' | 'failed' | 'pending' (pending meaning "Paystack confirmed it, Inkroot's own record
// hasn't caught up yet — will settle shortly").
export async function checkoutBook({ bookId, kind, amountNaira }) {
    await loadPaystackScript();
    const init = await invoke('paystack-init-purchase', { kind, bookId, amountNaira });
    const outcome = await new Promise((resolve, reject) => {
        const popup = new window.PaystackPop();
        popup.resumeTransaction(init.accessCode, {
            onSuccess: () => resolve('confirmed'),
            onCancel: () => reject(new Error('Payment cancelled')),
            onError: (err) => reject(new Error(err?.message || 'Payment failed')),
        });
    });
    if (outcome !== 'confirmed') return 'failed';
    return waitForPurchaseSettled(init.reference);
}

// Same idea as checkoutBook above, for a Worldbuilding Pack (fix-tracker item 20) — a pack's
// price is looked up server-side from published_packs, never trusted from here, same as a
// book's. Diverges from checkoutBook in one place: a free pack's init call comes back
// `{ free: true }` instead of a Paystack access code (see paystack-init-pack-purchase — Paystack
// itself won't process a zero-amount charge), so the popup is skipped entirely rather than ever
// being shown for a pack that already has its settled purchases row.
export async function checkoutPack({ packId }) {
    const init = await invoke('paystack-init-pack-purchase', { packId });
    if (init.free) return 'success';
    await loadPaystackScript();
    const outcome = await new Promise((resolve, reject) => {
        const popup = new window.PaystackPop();
        popup.resumeTransaction(init.accessCode, {
            onSuccess: () => resolve('confirmed'),
            onCancel: () => reject(new Error('Payment cancelled')),
            onError: (err) => reject(new Error(err?.message || 'Payment failed')),
        });
    });
    if (outcome !== 'confirmed') return 'failed';
    return waitForPurchaseSettled(init.reference);
}

// ---------- Saved bank accounts ----------

export async function fetchBanks() {
    const data = await invoke('paystack-banks', {});
    return data.banks;
}

export async function resolveBankAccount({ accountNumber, bankCode }) {
    const data = await invoke('paystack-resolve-account', { accountNumber, bankCode });
    return data.accountName;
}

export async function saveBankAccount({ accountNumber, bankCode, makeDefault }) {
    const data = await invoke('paystack-save-bank-account', { accountNumber, bankCode, makeDefault });
    return data.bankAccount;
}

export async function fetchSavedBankAccounts() {
    const { data, error } = await supabase.from('bank_accounts').select('*').order('is_default', { ascending: false }).order('created_at', { ascending: false });
    if (error) throw new Error(error.message);
    return data || [];
}

export async function deleteBankAccount(id) {
    const { error } = await supabase.from('bank_accounts').delete().eq('id', id);
    if (error) throw new Error(error.message);
}

export async function setDefaultBankAccount(id) {
    const { error } = await supabase.rpc('set_default_bank_account', { target_account_id: id });
    if (error) throw new Error(error.message);
}

// ---------- Earnings & withdrawals ----------

export async function fetchAvailableBalanceNaira() {
    const { data: session } = await supabase.auth.getSession();
    const userId = session.session?.user?.id;
    if (!userId) return 0;
    const { data, error } = await supabase.rpc('author_balance_kobo', { check_user_id: userId });
    if (error) throw new Error(error.message);
    return koboToNaira(data || 0);
}

export async function fetchSalesLedger() {
    const { data, error } = await supabase.from('purchases').select('id, kind, book_id, amount_kobo, author_amount_kobo, status, created_at, paid_at')
        .order('created_at', { ascending: false }).limit(50);
    if (error) throw new Error(error.message);
    return data || [];
}

// paystack_transfer_code is included purely for display: once it's set, the transfer has
// actually been handed to Paystack (see paystack-withdraw), so a still-'pending' row with a
// transfer code is "in flight" rather than merely "requested" — see withdrawalStage() in
// creator-dashboard.jsx, which is the only place this field is read. Never used to gate any
// action here — the server-side status column is still the only source of truth for what a
// withdrawal actually is.
export async function fetchWithdrawals() {
    const { data, error } = await supabase.from('withdrawals').select('id, amount_kobo, status, failure_reason, created_at, completed_at, bank_account_id, paystack_transfer_code')
        .order('created_at', { ascending: false }).limit(50);
    if (error) throw new Error(error.message);
    return data || [];
}

export async function requestWithdrawal({ bankAccountId, amountNaira }) {
    const data = await invoke('paystack-withdraw', { bankAccountId, amountNaira });
    return data.withdrawal;
}

// The manual-settlement sibling of requestWithdrawal — see manual-withdraw's own header comment
// for why this exists at all. Same shape, same client-side validation left to the server; the
// only difference from the caller's point of view is which Edge Function gets invoked.
export async function requestManualWithdrawal({ bankAccountId, amountNaira }) {
    const data = await invoke('manual-withdraw', { bankAccountId, amountNaira });
    return data.withdrawal;
}

// Which withdrawal method WithdrawModal (creator-dashboard.jsx) actually uses today. A single
// switch rather than a per-call choice: Paystack Transfers need a business TIN Inkroot doesn't
// have yet, so every withdrawal goes through the manual queue for now (see
// 62_migration_manual_withdrawals.sql). Flip this back to 'paystack' once that's sorted —
// create_withdrawal_locked/paystack-withdraw/the webhook were never touched and still work
// exactly as before.
export const ACTIVE_WITHDRAWAL_METHOD = 'manual';

// The two admin-only calls behind the Manual Withdrawals admin queue (src/admin/
// manual-withdrawals-admin.jsx). Both are RPCs a signed-in admin's own client calls directly —
// see admin_list_pending_manual_withdrawals/admin_settle_manual_withdrawal's own comments in
// schema.sql for why these don't go through an Edge Function the way requestManualWithdrawal does.
export async function adminFetchPendingManualWithdrawals() {
    const { data, error } = await supabase.rpc('admin_list_pending_manual_withdrawals');
    if (error) throw new Error(error.message);
    return data || [];
}

export async function adminSettleManualWithdrawal(withdrawalId, newStatus, note) {
    const { data, error } = await supabase.rpc('admin_settle_manual_withdrawal', {
        p_withdrawal_id: withdrawalId, p_new_status: newStatus, p_note: note || null,
    }).single();
    if (error) throw new Error(error.message);
    return data;
}

