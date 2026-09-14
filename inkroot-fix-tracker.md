# Inkroot — Consolidated Fix Tracker (v8)

Same purpose as v1–v7: hand Claude one item's "Prompt for Claude" block at a time in a fresh or
focused session. Verified against source in the current project zip.

**What changed from v7 — item 33, a real crash reported directly by the app owner, found and
fixed.** Tapping Publish from the Workshop (Author Studio) blanked the whole app. Root cause:
`PublishingWizard` assumes `project.chapters` is always a real array, but when opened from the
Workshop it's actually fed the lightweight project *index* entry, which never carries `chapters`
— only pre-computed summary fields. Two unguarded `project.chapters.length` reads threw on
render, and with no error boundary anywhere in the app, that uncaught exception unmounted the
entire tree. See "Recently completed, continued (12)" below for the fix, and the same entry for
a broader gap flagged but intentionally not fixed here (no error boundary exists anywhere in this
app — a future crash from any other cause would still blank the screen the same way). **Nothing
else is open as of this version.**

**What changed from v6 — item 31 was already fixed (this document just hadn't caught up), and a
final production audit found one more item (32), now also fixed.** A full end-to-end production
audit re-checked item 31's claim against current source and found `followAuthor`/`unfollowAuthor`
already check `error` and throw, and both call sites already gate the local toggle/count on
success with an `AlertDialog` on failure — the fix this document's own v6 "Still open" section
below describes as a "Prompt for Claude" had, in fact, already been made in the codebase by the
time v6 was written; the tracker simply wasn't updated to say so. Left the v6 section unedited
just below rather than quietly rewritten, so this document's history stays honest about carrying
a wrong "still open" claim for at least one version — same standing lesson this file has called
out twice before (see the correction above "Confirmed solid" near the bottom, and v3's rewrite
note). The same audit found one genuinely new (if minor) issue — **item 32, two cosmetic-but-
misleading gaps, now fixed** — see "Recently completed, continued (11)" below. **Nothing is open
as of this version.**

**What changed from v5 — item 30 is fixed; item 31 is the only thing left open.** Item 30 (a
published Guild Anthology was unreadable/undiscoverable by anyone but its own publisher) is now
closed — see "Recently completed, continued (10)" below. Item 31 (`followAuthor`/`unfollowAuthor`
swallowing errors) was not touched and is still open, with its own "Prompt for Claude" block below.

**What changed from v4 — a final full-system audit found four more issues; two are fixed, two are
still open.** Items 26 and 27 (Player Guild publishing parity, and publishing reliability/
atomicity) were the last items open when v4 was written and are both now done — see "Recently
completed, continued (7)" and "(8)" below. A subsequent full-system audit, run specifically to
check cross-account/cross-device behavior end-to-end rather than any single feature in isolation,
found four more issues: items 28 and 29 (a fresh-install-breaking duplicate RLS policy, and a
moderator-takedown bypass discovered while fixing it) are now closed — see "Recently completed,
continued (9)" below. **Items 30 and 31 are not fixed yet** — see "Still open" below, each with its
own "Prompt for Claude" block.

**What changed from v3 — P4 is now fully closed.** v3 already had item 18 confirmed done (see
below) and item 19 still open at the point it was written; when this session picked the tracker
back up, the zip handed over still listed 19–22 as open in the *PDF* copy of this document (the
PDF hadn't caught up to this in-repo `.md` on item 18 — worth keeping just one canonical copy of
this file going forward, since the PDF/`.md` split is exactly the kind of staleness this
document's own lesson warns about). Re-checking source directly rather than trusting either
copy: item 18 was confirmed already done (migration 83 exists, client wiring is real — matches
what this document already said), and **items 19, 20, 21, and 22 have now all been built and
are done** — see "Recently completed, continued (3)" below for each.

**The lesson driving v3's rewrite, still the standing rule:** every "Confirmed still open" line
in this document is only as good as the pass that last checked it — "Confirmed" means checked
against current source in the session that wrote the line, not carried forward from a prior
version of this document. Two things worth recording from *this* pass specifically, since they're
the same lesson showing up in two new shapes:

- **Item 20 wasn't fully scoped by its own v2/v3 prompt.** The prompt only described a
  purchase/download backend for a pack, which implicitly assumed a reader could already find
  another author's pack to buy. They couldn't — `published_packs` didn't exist at all before this
  session; the Worldbuilding Packs shelf was built from `projects.flatMap(...)`, this device's own
  local `projects` state, so a pack was never visible to anyone but the author who published it,
  on any device. Building only the purchase/download half (as originally scoped) would have shipped
  a Buy button nobody but the author could ever see. The fix built covers both: a real
  `published_packs` directory (mirroring `published_books`/`fetchDiscoverBooks`) *and* the
  purchase/download path the prompt described.
- **Items 21 and 22 both had an open design question in their own prompt text** (purchase step or
  free-to-install/use; moderation gate or not) that genuinely needed the app owner's call, not an
  assumption. Both were answered explicitly before building: addons and templates are
  **free-to-use/install, no purchase step, no `content_reports` moderation gate** (for either —
  the app owner's own call, not an oversight; `published_packs`/`published_pack_content` from item
  20 also has no `content_reports` entry yet, for the same reason: not asked for this session).

---

## Recently completed (removed from active list)

**From the original audit (items 1–11):**
- **Item 1** — Readers cannot read anyone else's published book. `published_book_content` table,
  `publishBookContentRemote`/`fetchPublishedBookContent` in `src/lib/library.js`.
- **Item 2** — Banned users could write to 10 tables. `71_migration_ban_check_insert_policies.sql`
  — `and not is_banned(auth.uid())` added to all 10 insert policies.
- **Item 3** — No server-side cap on Player Guilds per owner. `72_migration_player_guild_
  ownership_cap.sql` — unique index on `owner_id` plus `create_or_get_own_guild()` RPC.
- **Item 4** — No minimum word count to publish. `73_migration_publish_word_count_floor.sql` (and
  `74_migration_anthology_publish_word_count_floor.sql` for the anthology path) — 5,000-word floor
  enforced both client-side and in the insert policy.
- **Item 5** — No rate limit on content reports. `75_migration_content_reports_rate_limit.sql` —
  partial unique index (one open report per reporter/content pair) plus a rate-limit trigger.
- **Item 6** — No rate limit on Fireside posts. `76_migration_fireside_post_cooldown.sql` — a
  per-author cooldown trigger, advisory-locked against the same-instant race.
- **Item 7** — No in-app admin/moderator management. `77_migration_admin_role_revocation.sql` plus
  `src/admin/manage-admins.jsx` — grant/revoke with an audit log; minting a NEW admin deliberately
  stays service-role-only (a considered departure from the original ask — see the migration's own
  header for why "an admin can mint another admin" was rejected as too large a blast radius).
- **Item 8** — Moderators couldn't remove content. `78_migration_moderator_content_removal.sql` —
  soft-hide (`removed_by_moderator`) across `published_books`/`fireside_posts`/`reviews`/
  `guild_book_feedback`/`book_discussion_posts`, with a "Remove content" action wired into
  `src/moderation/moderation-queue.jsx`.
- **Item 9** — Guild owner account deletion silently orphaned the guild. `79_migration_account_
  deletion_guild_check.sql` — corrects the original audit's own premise too (purge never actually
  cascade-deleted the guild; the real bug was a permanently-banned owner left in place — see that
  migration's header).
- **Item 11** — Any member could tag a post "announcement." `80_migration_fireside_announcement_
  officer_gate.sql` — insert policy now matches `notice-board.jsx`'s own officer/admin check.
- **Item 12** — A writer's own Rank showed different numbers on Home vs. Author's Hall. Shared
  `myPublishedCountFor`/`buildLegacyBooksForReputation`/`meaningfulCompletedCountFor` helpers in
  `src/library/author-reputation.jsx`.
- **Item 13** — Public Reputation ignored real follower/review counts. `fetchFollowerCount` +
  reused `fetchAuthorRatingsSummary` in `src/lib/library.js`; `reviewReputationCountsFrom` in
  `author-reputation.jsx`; `rating`/`review` flipped to `live: true`.

**From the P4 pass (items 14, 15, 17):**
- **Item 14** — Living Universe's Guild Events widget was flagged simulated; already wired to
  `fetchPublicGuildEvents` in `living-universe-screen.jsx` (migration 51). Only the stale comments
  describing it as future work needed fixing.
- **Item 15** — Guild Order World Bible tab was fully simulated. New `guild_order_world_entries`
  table (`81_migration_guild_order_world_bible.sql`), new `src/lib/guild-world-bible.js`,
  `GoWorldBibleTab` in `guild-order.jsx` rewritten to fetch/subscribe for real, both call sites in
  `guild-anthology.jsx` updated. Real for both guild types, live via Realtime, same shape as
  Manuscript.
- **Item 17** — Treasury/Anthology were flagged as still-simulated for Founder Guilds; already
  real for both guild types via `69_migration_founder_guild_parity.sql`. No code change needed —
  fixed several stale comments in `guild-order.jsx`/`guild-anthology.jsx` that still claimed
  otherwise, since those are what caused this to look open.
- **Item 16** — Guild Order Council/Voting tab was fully simulated (hardcoded vote-count seeds
  plus only this device's own local vote). New `guild_order_proposals`/`guild_order_votes` tables
  (`82_migration_guild_order_council.sql`, same document/contribution split as Manuscript), new
  `src/lib/guild-order-council.js`, `GoCouncilTab` rewritten to fetch/vote/close for real and
  subscribe live. A proposal can only be closed by whoever opened it — simplest rule, no rung
  re-derivation needed, documented as an MVP choice in the migration itself. Real for both guild
  types, no simulated fallback (Council never had one to begin with — same as Roster).

---

## Recently completed, continued

- **Item 10** — Sync-conflict recovery had a working data layer but no UI. Found the existing
  app-wide event-listener precedent (`src/shell/sync-context.jsx`'s `online` handler) and added a
  matching one for `inkroot:sync-conflict`, loading `listConflictBackups()` both on that event and
  once on mount (a conflict can be backed up during a prior session, before anything's listening).
  New `src/shell/conflict-recovery-control.jsx` — a Home-only pill button (rendered only when
  `conflictBackups.length > 0`, so a writer who's never hit a conflict never sees it) next to
  `AccountSyncControl`, opening a panel listing each backup with Restore/Dismiss. Conflict
  resolution itself (remote still wins) is unchanged — this is purely the missing recovery
  surface `syncEngine.js`'s own comment already flagged as absent.

---

## Recently completed, continued (2)

- **Item 18** — Inbox / notifications entirely local, no real backend. Scope agreed with the app
  owner: real, push-on-write notifications for new follower, new review, Guild Order activity
  (proposal opened, chapter/passage/World Bible entry added), and guild event results posted —
  everything else the Inbox shows (Messages, Sales, Marketplace, Achievements, System, and the
  non-event-driven half of Guild Notifications like invitations/mentions) stays local/seeded, no
  real backend concept exists for those yet. New `notifications` table
  (`83_migration_notifications.sql`), seven trigger functions (one per event; the four Guild
  Order ones share a `notify_guild_order_members()` broadcast helper), live via Realtime — same
  pattern `guild_order_world_entries`/`guild_order_proposals` (81/82) already use. New
  `src/lib/notifications.js` (`fetchNotifications`/`subscribeNotificationsRealtime`).
  `AuthorInboxScreen` now layers real mail on top of local/seeded `INBOX_KEY` state on load and
  live — Reviews is real-only going forward (the fake `rev-*` seed letters retire once a real
  source exists, same honesty call `seedInboxItems()` itself already makes for `hasPublished`);
  Reputation and Guild Notifications layer real items on top of their still-fake seed content,
  since the rest of those categories has no real backend yet.

---

## Recently completed, continued (3)

- **Item 19** — Living Universe's activity Feed was entirely simulated (`useLivingUniverseFeed`
  invented a new fictional entry on a random 14–30s interval, persisted to `LU_FEED_KEY`), no
  real backend concept behind it. Scoped per item 18's own follow-up question: the Feed is a
  public/cross-user view over the same event sources item 18's `notifications` already covers,
  not a second, separate real-time system. New `list_living_universe_feed()` RPC
  (`84_migration_living_universe_public_feed.sql`) pulling from publish/follow/review/guild-join
  events. New `src/lib/living-universe-feed.js`, wired into `useLivingUniverseFeed()` — the local
  generator is demoted to the last-resort empty-state fallback for the `release`/`guild` kinds it
  covers, same pattern `useLuTrending`'s `trendingIsReal` already used for Trending in this same
  screen; kinds with no real backend are left alone.

- **Item 20** — Worldbuilding Pack purchases had no purchase/download backend — and, discovered
  while re-scoping this item against current source (see this document's intro above), no
  *discovery* backend either: `published_packs` didn't exist, so a pack was never visible to
  anyone but its own author, on any device. Both gaps closed together in
  `85_migration_worldbuilding_pack_discovery_and_purchase.sql`:
  - `published_packs` — the missing directory (mirrors `published_books`'/`fetchDiscoverBooks`'
    RLS shape: anyone reads, author owns writes). `grand-library-screen.jsx`'s `publishedPacks`
    now sources from a real `fetchDiscoverPacks()` instead of local-only `projects.flatMap(...)`.
  - `published_pack_content` — full gated content, mirroring `published_book_content`'s single-
    jsonb-blob shape **but gated by purchase**, per the app owner's explicit call: unlike a book
    (free to read by design; Buy/tip there is support, not a paywall), a pack's Buy button is its
    only gate, so an ungated mirror would leave nothing to sell.
  - `purchases.kind` extended with `'pack'`, new `pack_id` column, `amount_kobo`'s check loosened
    from `> 0` to `>= 0` — needed because a free pack (price 0) still gets a durable `$0`
    purchases row, per the app owner's call for audit-trail consistency with every other purchase
    kind; Paystack itself won't process a zero-amount charge, so `paystack-init-pack-purchase`
    writes that row directly, `success`, with no Paystack call, for a free pack.
  - New `src/lib/worldbuilding-packs.js` (publish/unpublish/discover/access-check/content-fetch),
    `checkoutPack` added to `src/lib/payments.js`, `WorldbuildingPackDetailModal`'s old
    `ComingSoonNotice` replaced with a real Buy-or-Download section (download saves the full
    content as a JSON file — the literal word the original prompt used, not a merge into the
    buyer's own project, which would be a separate, larger feature).

- **Item 21** — Addon marketplace was fully device-local (`readAddons`/`writeAddons` in
  `localStorage`, not even synced across one writer's own devices), no sharing backend. Per the
  app owner's call: **free-to-install, no purchase step, no `content_reports` content_type.**
  New `published_addons` table (`86_migration_addon_marketplace.sql`), simpler than
  `published_packs` since an addon isn't project-scoped and has no gated-content split (its
  `contains` manifest *is* the public listing). New `src/lib/addon-marketplace.js`
  (publish/unpublish/discover). `addon-data.jsx`'s `emptyAddon()` gained `marketplaceStatus`/
  `publishedAt` — deliberately separate from the existing `status` field, which only ever meant
  "is this addon finished," never "is it shared." `addon-studio.jsx`'s old `ComingSoonNotice`
  replaced with a real `AddonMarketplaceBrowser` (browse → "Add to My Addons" installs the
  manifest locally, after which the existing per-project Install toggle works unchanged) plus a
  `MarketplaceToggle` (Share/Unshare) on each of your own addon cards.

- **Item 22** — Template sharing was fully device-local (`readTemplates`/`writeTemplates`), no
  sharing backend. Per the app owner's call: **free-to-use, no purchase step, no
  `content_reports` content_type** — same as item 21. New `published_templates` table
  (`87_migration_template_marketplace.sql`), following `published_addons`' own pattern almost
  exactly; one difference — a template's fields vary by `type` (book/chapter/character/
  worldbuilding), so they're kept in one `payload` jsonb column rather than fixed columns, same
  "manifest, not fixed shape" reasoning `published_addons.contains` already uses. New
  `src/lib/template-marketplace.js`. `templates.jsx`'s `emptyTemplate()` gained the same
  `marketplaceStatus`/`publishedAt` pair item 21 added to addons; its old `ComingSoonNotice` (and
  the file's own header comment, which was stale in exactly the way this document's intro
  describes — "needs a shared backend Inkroot doesn't have yet," when it now does) replaced with
  a `TemplateMarketplaceBrowser` + `MarketplaceToggle`, mirroring item 21's addon UI.

**Caveat covering items 19–22 together:** built and syntax-checked against the current source in
this session, but not run against a live Supabase instance or a real `vite build` — this
environment has neither network access for `supabase db push` / `npm install` nor a bundler.
Treat as ready-for-review, not deploy-tested. Recommended before shipping: apply migrations 84–87,
run a real build, and manually walk publish → browse as a second account → buy/add → download/
install for each of the Pack, Addon, and Template marketplaces.

---

## Recently completed, continued (4)

- **Item 23 — release blocker, found in a pre-launch audit, not the P4 pass.** Paid-book
  manuscript access was enforced only in React, not at the database. `published_book_content`'s
  original policy (`anyone can read published book content`, `using (true)`) predates this
  document's own "money-moving paths ... confirmed solid" line below — that line was wrong for
  this one table and stayed wrong across v1–v4 because nobody re-checked the RLS itself, only the
  app's own reading UI (`checkBookReadAccess`/`openReaderBook`, both correct). A direct
  `supabase.from('published_book_content').select(...)` call, or the Grand Library's own "Peek at
  the opening" sample loader (which fetched the FULL manuscript and truncated client-side), could
  pull any priced book's complete text for free, purchase or not.
  `89_migration_paid_book_content_access.sql` closes it: the open policy is replaced with three
  narrower ones (author-owns / price<=0 / verified `purchases` row, same three conditions
  `checkBookReadAccess` already used client-side, now also enforced at the table) — and a new
  `published_book_samples` table + `sync_published_book_sample()` trigger gives the sample
  feature a small, always-public, author-uncontrolled preview to read instead, so a priced book's
  "peek at the opening" still works without reopening the same hole. New
  `fetchPublishedBookSample` (`src/lib/library.js`); `BookDetailModal`'s `loadSample`
  (`grand-library-cards.jsx`) now calls that instead of `fetchPublishedBookContent` for every
  reader who isn't the book's own device. `checkBookReadAccess`/`openReaderBook` themselves were
  already correct and are unchanged.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–22) — apply migration 89 (or re-run `schema.sql` on a fresh install) and
  manually verify: a free book still reads in full for anyone; a priced book reads for its author
  and for a buyer with a real `success` purchase row; a priced book denies everyone else while
  still showing a sample; direct REST/SQL access to `published_book_content` for a priced,
  unpurchased book returns no row.

---

## Recently completed, continued (5)

- **Item 24 — release blocker, found in the same pre-launch audit as item 23.** Guild privacy:
  a book published specifically to a Guild (destination = 'guild') was, and still is by default,
  discoverable and fully readable through `published_books`/`published_book_content`'s own open
  policies — the exact same shape of hole item 23 closed for a priced book, just triggered by
  *destination* instead of *price*. `publishBookWithDetails` (`ink-root.jsx`) writes every
  publish, guild-destined or not, into both tables; their "anyone can read" policies (`using
  (true)`) never checked `destination`, so a guild-only book's listing and entire manuscript were
  world-readable to anyone with the anon key — the app's own Discover/Author's-Hall queries
  filtering to `destination = 'inkroot'` (`lib/library.js`) is a UI filter, not a permission
  boundary. `90_migration_guild_book_privacy.sql` closes it: `published_books`' open select
  policy is replaced with four narrower ones (Grand Library books public, author reads own,
  verified Founder Guild members read their own guild's listings via `guild_published_books` +
  `founder_guild_members`, moderators read all — same OR-together shape item 23's migration used);
  `published_book_content`'s "free book content is public" policy (89) is narrowed to
  `destination = 'inkroot'` and a matching guild-members policy added; `published_book_samples`
  gets the identical treatment, since its "peek" excerpt is derived straight from
  `published_book_content` and was just as open. No client code changes — `checkBookReadAccess`/
  `fetchPublishedBookContent`/`openReaderBook` already fail toward "book unavailable" when a
  lookup comes back empty, which is exactly what a non-member now gets. Player-Guild-destined
  books (which never get a `guild_published_books` row — see that table's own header on Player
  Guild bookshelves being local-only/no shared-shelf feature) end up author-only-readable, which
  is strictly more correct than the fully-public hole they had before, not a feature regression.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–23) — apply migration 90 (or re-run `schema.sql` on a fresh install) and
  manually verify: a Grand-Library book is unaffected; a Founder Guild member can still open a
  book on their own Guild Bookshelf and a non-member/signed-out reader cannot (direct REST/SQL
  included); the book's own author can always read/edit it from any device.

---

## Recently completed, continued (6)

- **Item 25 — release blocker, found in the same pre-launch audit as items 23–24.** A published
  Guild Anthology had no actual content behind it: `publish_guild_anthology()` inserted exactly
  one `published_books` listing row and nothing else, so every anthology hit the same "book has
  no content mirror" hole item 23's own migration (70) closed for a solo book — except here it
  was never closed at all, for any reader, including the guild owner who published it. Root
  cause was `guild_anthology_submissions`' own original design (migration 35): a submission was
  always a lightweight pointer (`project_id`, title, word count) to a contributor's manuscript,
  which otherwise lives solely in that contributor's own private, device-local `kv_store` — a
  security-definer publish function has no way to read another user's local project, so there
  was never any real prose to assemble a `published_book_content` row FROM.
  `91_migration_anthology_submission_content.sql` closes it: `guild_anthology_submissions` gets
  its own `content` column (chapters only, same 20MB cap as `published_book_content`'s own),
  filled by the contributor's own device at submit/edit time — `loadProjectManuscriptContent` in
  `guild-anthology.jsx` reads it via the same `storage`/`projectKey` singletons `ink-root.jsx`
  already uses for a solo book's own publish, not a new prop threaded down from anywhere.
  `guard_anthology_submission_update()` protects `content` with the exact same "frozen once
  reviewed, invisible to the reviewer's own update path" rule its three siblings already had.
  `publish_guild_anthology()` now refuses to publish while any approved submission is still
  missing content (with a clear, count-based message — see the migration's own header for why an
  already-`reviewing` anthology could have some), then assembles every approved contributor's
  content, in submission order, into the anthology's one `published_book_content` row — a short
  byline section per contributor followed by their own chapters, using the exact
  `chapters: [{id,title,text}]` shape `PublishedBookReader` already renders, so no reader-side
  code needed to change. `submitToAnthology`/`updateOwnSubmission` (`src/lib/guild-anthologies.js`)
  gained an optional `content` parameter; all three places the UI calls `submitToAnthology`
  (Quick Submit, the in-workspace "Submit your work" picker, and the "bring in one of your
  projects" seed flow on Create) now load and pass it, and saving an edit to a pending submission
  re-reads the project fresh (rather than reusing whatever was attached at first submit) so a
  contributor who keeps writing while their entry sits pending doesn't publish stale text — a
  failed local read on that path leaves the previously-attached content alone rather than wiping
  it to null.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–24) — apply migration 91 (or re-run `schema.sql` on a fresh install) and
  manually verify: submitting a new project to an open anthology attaches its chapters; a
  contributor without content attached (or a pre-migration submission) blocks Publish with the
  named-count message above; publishing with every approved contributor's content present
  produces a `published_book_content` row that opens and reads correctly — cover, one shared
  title/author line, each contributor's byline section, and their actual chapter text — from a
  second account, a signed-out session, and direct REST/SQL.

---

## Still open

Nothing. Items 23, 24, and 25 (found outside the P4 pass, in the same pre-launch audit), item 27
(found in a final production-readiness pass), items 28/29 (found in a final full-system audit
after item 27), item 30 (found in that same audit), item 31 (see the correction just below — it
was actually already fixed by the time this "Still open" entry was written), and item 32 (found
in a later full production audit, see "Recently completed, continued (11)") are all closed.

**Correction to item 31 below, made in the v7 pass:** the "Prompt for Claude" this section used
to carry described `followAuthor`/`unfollowAuthor` (`src/lib/library.js`, ~lines 349 and 412) as
returning the raw Supabase query builder without checking `error`, and their call sites in
`src/library/authors-hall-screen.jsx` and `src/library/grand-library-screen.jsx` as optimistically
updating local state before confirming success. Re-checked directly against source in the v7 pass:
**this was already fixed.** Both functions check `error` and throw; both call sites only flip the
local "Following" toggle/follower count after the call resolves, and show an `AlertDialog` on
failure. Left the original wording just below rather than deleted, so this document's history
stays honest about having carried a stale "still open" claim across at least one version — same
lesson as the correction above "Confirmed solid" near the bottom of this file.

- ~~**Item 31 — reliability gap, same bug class as item 27, just never applied here.**~~
  ~~`followAuthor`/`unfollowAuthor` (`src/lib/library.js`, ~lines 347 and 408) return the raw~~
  ~~Supabase query builder without checking `error` — the same pattern item 27 fixed everywhere in~~
  ~~the publishing path. Their only callers, in `src/library/authors-hall-screen.jsx` (~line 137) and~~
  ~~`src/library/grand-library-screen.jsx` (~line 62), do `.then(() => setFollowerCount(...))`, which~~
  ~~optimistically updates the local "Following" toggle and follower count on anything that resolves~~
  ~~— including a silently-denied RLS write or any other database-level error. A user could see~~
  ~~"Following" and an incremented count locally while nothing was actually written to the `follows`~~
  ~~table, meaning the follow won't be there on reload or on another device. Not a security hole —~~
  ~~the underlying `follows` row genuinely wasn't written either way — but it's a real~~
  ~~cross-device-consistency bug for the exact feature item 4 of the last audit asked about.~~ **(Not
  accurate as of v7 — see the correction above. Kept struck through, not deleted, per this
  document's own honesty policy about superseded claims.)**

---

## Recently completed, continued (10)

- **Item 30 — release blocker, found in the same final full-system audit as items 28/29.**
  `publish_guild_anthology()` correctly assembled every approved contributor's real content and
  inserted atomically into `published_books` + `published_book_content` with `destination =
  'guild'`, but never inserted the matching row into `guild_published_books`. Every guild-scoped
  read policy on `published_books`/`published_book_content` (migrations 90 and 92) resolves who's
  allowed to see a `'guild'` destination book by joining through `guild_published_books`; with no
  row there, only the book's own `author_id` (the officer who ran Publish) and moderators could see
  it under RLS. Concretely: it never appeared on the Guild Bookshelf
  (`fetchGuildPublishedBooks`/`src/lib/library-guild.js` only ever queries `guild_published_books`),
  and every other guild member — including every contributor who helped write it — hit "book
  unavailable" trying to open it. A published anthology delivered a readable book to exactly one
  person: whoever clicked Publish.
  Fixed with a new `93_migration_anthology_guild_shelf.sql` — a fresh `create or replace` of
  `publish_guild_anthology()` with one added insert into `guild_published_books` (same
  transaction, same atomicity guarantee the rest of the function already had), plus a one-time
  backfill for any anthology that was already published under the old buggy function before this
  migration existed. **Shipped as a new migration, not an edit to migration 91's own file** — unlike
  item 28's duplicate-policy bug (which threw a hard error, so no deployment could have gotten past
  it), this bug never errored, so a real deployment could already have successfully applied
  migration 91 exactly as originally written; editing that file after the fact wouldn't reach such
  a deployment, only a fresh `create or replace` shipped as a new migration does.
  `guild_anthologies.guild_id` has a hard foreign key to `player_guilds(id)`, so an anthology's
  guild is always a Player Guild, never a Founder Guild slug — the new insert uses the same
  `::text` cast `guild_published_books`'s own "player guild members ..." policies (migration 92)
  already use, not the Founder Guild ones. Also fixed three pieces of copy in
  `src/guild/guild-anthology.jsx` that all stemmed from the same misunderstanding — the anthology
  explainer text, the "Live in the Grand Library" status label, and the "Publish to the Grand
  Library" button — all claimed an anthology publishes to the Grand Library, which it never does
  (`destination` is always `'guild'`); all three now correctly say "Guild Bookshelf".
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–29) — manually verify: publishing a Guild Anthology creates a
  `guild_published_books` row alongside the `published_books`/`published_book_content` rows, the
  anthology appears on the Guild Bookshelf, and a guild member who isn't the publishing officer
  (a contributor, or any other member) can actually open and read it.

---

## Recently completed, continued (9)

- **Item 28 — release blocker, found in a final full-system audit. `schema.sql` (and the
  original `90_migration_guild_book_privacy.sql`) could not run against a fresh/existing
  database: `CREATE POLICY "moderators read all published books" ON published_books` was
  declared twice with no `DROP POLICY IF EXISTS` before the second declaration** (migration 78
  created it first; migration 90 re-declared the exact same name and definition, apparently
  without realizing it already existed). Postgres rejects a duplicate policy name outright, so
  applying `schema.sql` top-to-bottom on a fresh install — or applying the numbered migrations in
  order against a database that had already run migration 78 — aborted at that exact statement,
  silently skipping every migration after it: the rest of migration 90 (guild book privacy) and
  all of 91/92 (anthology content, Player Guild publishing) never took effect. Fixed by removing
  the redundant `CREATE POLICY` (byte-identical to the one migration 78 already created — zero
  behavior change) from `schema.sql` and from `90_migration_guild_book_privacy.sql`, replacing it
  with a comment explaining why nothing is declared there. Re-ran a full duplicate-policy scan
  across the entire consolidated `schema.sql` after the fix: this was the only instance.

- **Item 29 — found while fixing item 28, in the same policy block. Moderator-removed books
  silently became readable again the moment migration 90 applied.** Before migration 90,
  `published_books` had one read policy — `"anyone can read published books"` — that correctly
  gated on `not removed_by_moderator or auth.uid() = author_id` (migration 78). Migration 90
  dropped that single policy and replaced it with four narrower ones (Grand Library / author /
  Founder Guild member / moderator), plus a fifth from migration 92 (Player Guild member) — but
  none of the three non-author, non-moderator replacements carried the `removed_by_moderator`
  check forward. The moderation `removed_by_moderator` flag stayed correctly recorded and
  enforceable elsewhere (reviews, fireside_posts, guild_book_feedback, book_discussion_posts all
  still checked it correctly — this was isolated to `published_books`), but a book a moderator had
  taken down was fully public again via `"anyone can read grand library books"` (destination =
  'inkroot') or fully guild-visible again via either guild-member policy, the instant this
  migration ran. Fixed by adding `and not removed_by_moderator` to `"anyone can read grand library
  books"`, `"guild members read their guild's book listings"`, and `"player guild members read
  their guild's book listings"`, in `schema.sql` and in the original `90_migration_guild_book_
  privacy.sql`/`92_migration_player_guild_book_publishing.sql` files. The author's own listing
  policy and the moderator policy are deliberately left unconditional (same "author sees their own
  removed content" carve-out every other moderated table uses, and moderators need to see removed
  content by definition). `published_book_content`/`published_book_samples` needed no matching
  edit: their own policies join back to `published_books` via a subquery, and a subquery runs
  under the querying user's own RLS on the table it reads — so a row `published_books` now hides
  from a non-author/non-moderator is automatically invisible to those subqueries too.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–27) — manually verify: a moderator-removed Grand Library or Guild book
  returns no row to a logged-out session, a different regular reader, or a fellow guild member,
  while the book's own author and any moderator can still see it.

---

## Recently completed, continued (7)

- **Item 26 — release blocker, found in a follow-on pre-launch pass.** Player Guild books: the
  ordinary-book-to-Guild publishing path only ever worked for Founder Guilds.
  `publishBookWithDetails`/`setPublishStatus` (`ink-root.jsx`) pushed a `guild_published_books`
  row only when `guildProfile.guildType === 'founder'`, even though the Publishing Wizard itself
  (`writerGuildName`/`guildAvailableForTarget` in `publishing.jsx`) already offered "Guild" as a
  destination to a self-founded ('player') or joined ('joined') Player Guild writer too. Combined
  with item 24's own migration (90) locking `published_books`/`published_book_content` down to
  real guild members for `destination:'guild'`, a Player Guild's own book ended up
  author-only-readable — published to nowhere any other guildmate could actually see, silently.
  `92_migration_player_guild_book_publishing.sql` closes it using the exact same
  membership-checked, OR-together permissive-policy architecture the Founder Guild path already
  used (no parallel table, no new columns) — sibling policies checking `player_guild_members`
  instead of `founder_guild_members`, added to `guild_published_books` (select/insert/update),
  `guild_book_feedback` (select/insert/update — needed so a Player Guild's feedback thread doesn't
  silently break once its shelf is real), and `published_books`/`published_book_content`/
  `published_book_samples` (select), mirroring migration 90's own Founder Guild policies exactly.
  New `activeBookshelfGuildId()` helper in `ink-root.jsx` resolves the correct guild id (a Founder
  Guild's fixed slug, or a Player/Joined Guild's real `player_guilds.id`) for both publish call
  sites; `GuildBookshelf`'s `guildId` prop in `home-screen.jsx` now uses the same real id for a
  Player/Joined guild instead of `null`. Small related fix along the way: `project-workspace.jsx`'s
  own `writerGuildName` derivation fell through to the Founder branch (always null) for a
  `'joined'` member, showing the generic "my guild" fallback instead of the real joined guild's
  name — brought in line with `home-screen.jsx`'s own three-way derivation.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–25) — apply migration 92 (or re-run `schema.sql` on a fresh install) and
  manually verify: a Player Guild owner publishing a book with "Guild" as the destination shows up
  on their own Hall's Bookshelf; a second account that joins that same Player Guild by invite code
  can see, open, and leave feedback on it from their own Guild Hall; a signed-out session and a
  non-member (including someone seated in a *different* Player Guild or a Founder Guild) get "book
  unavailable"; the book's own author can always read/edit it regardless of guild.

---

## Recently completed, continued (8)

- **Item 27 — release blocker, found in a final production-readiness pass. Publishing
  reliability: a book/pack could show "Published" without actually being published, or be
  published-with-no-content forever.** Three compounding bugs, all in the publish/unpublish path:
  (1) both of Author Studio's quick-action functions (`setPublishStatus`/`setPackPublishStatus`
  in `ink-root.jsx`) and its Wizard-driven ones (`publishBookWithDetails`/`publishPackWithDetails`)
  wrote the local `publishStatus` — what the UI actually reads to show "Published" — *before* the
  remote listing/content/guild-shelf pushes even ran, which were themselves fired as
  non-blocking, uncaught promises (`.catch(e => console.warn(...))`); (2) `lib/library.js`,
  `lib/library-guild.js`, and `lib/worldbuilding-packs.js`'s own mutation functions returned the
  Supabase query builder directly, which *resolves* (never rejects) to `{ data, error }` on an
  ordinary database error (RLS denial, constraint violation), so even the `.catch()` that existed
  could never fire for a real failure, only a dropped connection; (3) worse, publishing from
  *inside* a project's own Settings tab or Publishing Hub (`project-workspace.jsx`'s
  `handleSetPublishStatus`/`handleWizardPublishBook`/`handleSetPackPublishStatus`/
  `handleWizardPublishPack`) made **no remote call at all** — purely a local `update()` — so a
  book published from that screen could show "Published" to its own author while being entirely
  invisible to Supabase, forever, on every other device. Combined with (1)/(2), a listing could
  also succeed while its content mirror failed, leaving a book that's discoverable in the Grand
  Library/Guild Bookshelf but permanently empty/broken for every reader but the author — the
  literal half-published book this item was written to prevent.
  Fixed with a new `lib/publish-flow.js` (`publishBookRemoteFlow`/`unpublishBookRemoteFlow`/
  `publishPackRemoteFlow`/`unpublishPackRemoteFlow`), used by **both** publishing entry points now:
  it awaits the listing write, then the content write, and rolls the listing back (delete) if the
  content write fails or silently no-ops from a dropped session — so a listing is never left
  standing with no content behind it. The Guild Bookshelf mirror stays deliberately best-effort
  and non-blocking (a failure there leaves the book correctly listed and fully readable via the
  two tables the app's own read paths actually check, just not yet mirrored onto the shared shelf
  row — a retryable inconsistency, not a half-published book). Every mutation in `library.js`/
  `library-guild.js`/`worldbuilding-packs.js` now explicitly checks `error` and throws, closing
  gap (2). All four `ink-root.jsx` functions and all four `project-workspace.jsx` handlers now
  await this flow and only write the local `publishStatus` once it resolves; `project-workspace.jsx`
  gained the `writerProfile` and `activeBookshelfGuildId` props it never had (needed to build the
  same content payload Author Studio already could), closing gap (3) entirely rather than papering
  over it. `PublishingWizard` (`publishing.jsx`) gained the same idle/publishing/error state
  `TipAuthorModal` already used elsewhere in the same file — the Confirm step now shows
  "Publishing…", stays open and shows the real error on failure instead of closing immediately
  regardless of outcome, and disables Back/Close while a publish is in flight. The two quick-action
  entry points that have no wizard around them (`setPublishStatus`/`setPackPublishStatus` in
  `ink-root.jsx`, and their `project-workspace.jsx` equivalents) show a new shared `AlertDialog`
  (`shared-ui/ui-primitives.jsx`) on failure instead of only a `console.warn`. Content-payload
  building (`buildPublishedBookContent`/`buildPublishedPackContent`) was pulled out of
  `ink-root.jsx` into a new `lib/publish-content.js` so both entry points build the exact same
  shape instead of each keeping a private copy that could drift.
  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as items 19–26) — manually verify: publishing a book from both Author Studio and from
  inside the project's own Settings/Publishing Hub actually creates rows in both `published_books`
  and `published_book_content` (not just one); simulating a `published_book_content` failure (e.g.
  a temporary RLS/constraint break) leaves no orphaned `published_books` row behind and shows the
  error in the Wizard or the AlertDialog rather than a false "Published"; unpublishing while
  offline/signed-out still works locally exactly as before; a Worldbuilding Pack goes through the
  same checks with `published_packs`/`published_pack_content`.

---

## Recently completed, continued (11)

- **Item 32 — two cosmetic-but-misleading gaps found in a final production audit, after item 31
  was confirmed already fixed (see the correction above).** Neither is a security or data bug;
  both are the same "stale claim outliving the fix it describes" pattern this document's own
  standing lesson (see v3's rewrite note near the top) already warns about — just found in
  in-app comments and UI copy instead of in this tracker.

  1. **Stale "no payment processor yet" / "reviews show as Coming Soon" comments.**
     `src/library/publishing.jsx` (the Grand Library header comment, the Personal Ratings
     section, and the Cart section) and `src/library/grand-library-screen.jsx` (the Cart's own
     inline comment) all still described pricing as non-chargeable, the Cart as a dead-end local
     queue, and public reviews as not yet built — all false as of the current codebase: Paystack
     checkout (`lib/payments.js`'s `checkoutBook`, the `paystack-*` Edge Functions), the Cart's
     real "Proceed to Checkout" path, and real public reviews (`submitReview`/`fetchBookStats` in
     `lib/library.js`, wired into `BookDetailModal`) all already exist and work — nothing in the
     actual behavior was wrong, only the comments describing it. Fixed by rewriting all four
     comment blocks to describe what the code actually does, with pointers to the real
     implementation instead of a "not built yet" disclaimer.
  2. **Orphaned Creator Dashboard tabs.** `src/library/creator-dashboard.jsx`'s "Templates" and
     "Add-ons" tabs rendered a flat `CreatorComingSoonPanel` even though the Template and Addon
     Marketplaces themselves (items 21 and 22) have been real and live for a while — just with no
     entry point on this particular screen. A writer who only ever checked their Creator Dashboard
     had no way to know sharing was already possible from a project's own Publishing Hub. Fixed
     with two new panels, `CreatorTemplatesPanel`/`CreatorAddonsPanel`, that read this device's
     real local templates/addons (`readTemplates`/`readAddons`) and reuse the exact same
     `MarketplaceToggle` share/unshare action `templates.jsx`/`addon-studio.jsx` already use
     (exported from both, not duplicated), so sharing from the dashboard and sharing from a
     project's Publishing Hub write the same `published_templates`/`published_addons` row. Kept
     deliberately read-only beyond that toggle — creating, editing, and installing a template or
     addon still needs a specific project's context (`update`), which this global,
     all-projects dashboard doesn't have; that CRUD stays in the Publishing Hub, same as before.
     `CreatorComingSoonPanel` itself was left in place in `grand-library-cards.jsx` (unused now,
     but harmless, and removing an exported component is a separate cleanup call from fixing what
     it was hiding).

  **Not run against a live Supabase instance from this session** (no network access here, same
  caveat as every other item in this document) — manually verify: the Creator Dashboard's
  Templates and Add-ons tabs show this account's real local templates/addons (including ones
  created from inside a project's Publishing Hub), the Share/Unshare button there actually
  flips the matching row in `published_templates`/`published_addons` (check from a second
  account that a newly-shared item now appears in that account's own Marketplace browser), and
  that toggling from the Dashboard and toggling from the Publishing Hub for the *same* item stay
  in sync (share from one, refresh the other, it should show shared there too).

---

## Confirmed solid — no action needed (context, don't re-audit)

**Correction to the line below, made when item 23 was fixed:** "RLS read-side coverage" was NOT
actually solid for `published_book_content` — see item 23 above for the real gap and the fix.
Left the original line unedited just below, rather than quietly rewritten, so this document's own
history stays honest about having carried a wrong "confirmed solid" claim across four versions —
matches this document's own standing lesson (see the top of this file) about what "Confirmed"
is supposed to mean.

Unchanged from v1–v3 — money-moving paths, RLS read-side coverage, the reporting flow up to
moderation removal (fully closed by item 8), media uploads, offline sync conflict *detection*
(resolution's UI half was item 10), anthology revenue splits, ban evasion, PDF import/export,
Health Checks, the guild event payout pipeline, and the realtime coverage note — larger again
after this session, since World Bible (item 15), Guild Order Council (item 16), Inbox
notifications (item 18), and the Living Universe Feed (item 19) each added their own live-push
source alongside the original five.

**New, not yet covered by any moderation/reporting path** (worth its own item if wanted, not
built this session since it wasn't asked for): `published_packs`/`published_pack_content`
(item 20), `published_addons` (item 21), and `published_templates` (item 22) have no
`content_reports` `content_type` entry. All three were an explicit app-owner call to skip for
this pass, not an oversight — flagging here so a future audit doesn't have to rediscover it.

---

## Recently completed, continued (12)

- **Item 33 — reported by the app owner as "the app goes blank when I tap Publish from the
  Workshop"; root cause found and fixed.** Not a backend issue — Supabase/RLS/Paystack were
  never involved. `PublishingWizard` (`src/library/publishing.jsx`) is opened from two different
  places with two different shapes of `project`: from a project's own Settings/Publishing Hub
  (`project-workspace.jsx`), it's the full loaded project, `chapters` included. From Author
  Studio / the Workshop (`grand-library-screen.jsx`'s `openPublishWizard`, fed by
  `CreatorDashboard`'s `projects` prop), `project` is the lightweight project *index* entry —
  deliberately summary-only (`useMetaReport` in `project-schema-and-backups.jsx` mirrors
  `wordCount`/`chapterCount`/etc. onto it precisely so the Grand Library/Author Studio never has
  to load a project's full manuscript just to list it) — it has no `chapters` array at all. Two
  spots in the Wizard's render (the Step 1 format summary, and the Step 4 confirm card's Series
  pill) read `project.chapters.length` directly, unguarded. Opened from the Workshop for any
  completed project, Step 1 renders immediately on mount and throws `TypeError: Cannot read
  properties of undefined (reading 'length')` — and since **no error boundary exists anywhere in
  this app** (`grep -rl componentDidCatch/ErrorBoundary src/` returns nothing), React 18 unmounts
  the whole tree on an uncaught render error with nothing left to show: the blank screen the app
  owner saw. A second, quieter bug shared the same cause: `bookWordCount` was recomputed from
  `(project.chapters || []).reduce(...)`, which silently evaluated to 0 for the same
  index-entry case — so even before hitting the crash, a genuinely long, ready-to-publish book
  opened from the Workshop would have shown "This manuscript is 0 words — publishing needs at
  least 30,000" and refused to continue, every single time.
  Fixed by making the three derived values (`bookWordCount`, and a new `bookChapterCount`) check
  `Array.isArray(project.chapters)` first: when real chapters are present (the Settings/Publishing
  Hub case), behavior is byte-for-byte unchanged from before; when they aren't (the Workshop/
  Author Studio case), it now falls back to the index's own already-accurate `project.wordCount`/
  `project.chapterCount` mirrors instead of treating a missing array as zero. Both former
  `project.chapters.length` call sites now read `bookChapterCount`.
  **Broader gap flagged, not fixed here** (out of scope for a report about one specific crash):
  this app has no error boundary at all, anywhere — the *specific* crash above is fixed, but any
  future uncaught render exception, from any cause, will still blank the entire app with nothing
  shown to the reader/writer and no way to recover short of a full reload. Worth a top-level
  `ErrorBoundary` around the app root (and arguably one around `PublishingWizard`/other modals
  specifically) as its own follow-up item if wanted.
  **Not run against a live instance from this session** (no network/browser access here) —
  manually verify: tapping Publish from the Workshop on a completed, well-over-the-word-floor
  project now opens the Wizard normally instead of blanking the screen, Step 1's "This project
  currently has N chapters" line shows the correct real count, and choosing Serialized Story
  format still shows the correct episode count on the Step 4 confirm card. Also verify the
  Settings/Publishing Hub's own Publish flow (which always had real `chapters`) is unchanged.
