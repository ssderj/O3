-- Inkroot — consolidated schema (fresh installs)
--
-- This is the full, current backend in one file: every table, RLS policy, trigger, index,
-- Storage bucket, and RPC function Inkroot uses, at the state they ended up in after 9 phases
-- of development and 14 migrations (see supabase/history/ for that original, phase-by-phase
-- record — it's kept for context and for upgrading an *existing* deployment, but a fresh
-- install only ever needs this one file).
--
-- For a NEW Supabase project: run this file once in the SQL editor. That's it — one script,
-- one run, already-correct end state. No phase order to get right, no migration dependency
-- chain, nothing to skip.
--
-- For an EXISTING deployment that already ran the old phase files: don't run this file — it
-- will collide with tables you already have. See supabase/history/README.md instead.
--
-- Organized by table (kv_store, then each social/guild feature, then Storage), not by the
-- historical order features were added in — that history is what supabase/history/ is for.

-- ============================================================================================
-- kv_store — the generic key-value sync table every local storage.get/set/delete call syncs
-- through (project JSON, writer profile, guild state, inbox, ...). No relational structure here
-- on purpose: Phase 1 needed sync to work without redesigning the app's existing local-storage
-- shape, and nothing since has needed to query *inside* a project's JSON server-side, so it's
-- stayed this way.
--
-- `version` and `updated_at` are both server-authoritative, stamped by the trigger below on
-- every write — never trusted from whatever a client sends. This is what the sync engine's
-- conflict resolution is keyed on (src/lib/syncEngine.js): a single database clock can't skew
-- against itself the way two different devices' clocks can, and a monotonic per-row version
-- counter lets a push detect "someone else changed this since my local copy" by an exact
-- match/mismatch instead of comparing two untrusted timestamps.
-- ============================================================================================

create table if not exists kv_store (
  user_id uuid not null references auth.users(id) on delete cascade,
  key text not null,
  value jsonb,
  version integer not null default 1,
  updated_at timestamptz not null default now(),
  deleted boolean not null default false,
  primary key (user_id, key),
  -- Storage buckets (see the Storage section below) cap a single upload at 5MB server-side —
  -- nothing here capped a single kv_store row the same way, even though a row can legitimately
  -- hold an entire project (manuscript text plus, per image-utils.jsx's readLocalImageFile,
  -- possibly several ~1.2MB base64 fallback images if a Storage upload ever failed or the writer
  -- was offline when adding them). 20MB is a generous multiple of both those figures — enough
  -- headroom for a large project with several embedded fallback images plus its own text and
  -- metadata — while still bounding a single row against an unbounded or malicious payload.
  -- octet_length(value::text), not pg_column_size(value), so this checks the actual JSON text
  -- size the sync engine pushes/pulls over the wire, not whatever TOAST compression happens to
  -- shrink it to on disk.
  check (octet_length(value::text) <= 20971520)
);

alter table kv_store enable row level security;

-- Every writer can only ever read/write their own rows. Critical since this table holds
-- everyone's private manuscripts.
create policy "select own rows" on kv_store
  for select using (auth.uid() = user_id);
create policy "insert own rows" on kv_store
  for insert with check (auth.uid() = user_id);
create policy "update own rows" on kv_store
  for update using (auth.uid() = user_id);
create policy "delete own rows" on kv_store
  for delete using (auth.uid() = user_id);

-- Supports the sync engine's incremental pull (src/lib/syncEngine.js: pullRemote()), which only
-- asks for rows changed since the last successful sync rather than the whole table.
create index if not exists kv_store_user_updated_idx on kv_store (user_id, updated_at);

create or replace function stamp_kv_store()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  if tg_op = 'INSERT' then
    new.version := 1;
  else
    new.version := old.version + 1;
  end if;
  return new;
end;
$$;

drop trigger if exists kv_store_stamp on kv_store;
create trigger kv_store_stamp
  before insert or update on kv_store
  for each row execute function stamp_kv_store();

-- ============================================================================================
-- profiles — the one place a writer's current display name lives. Every other table below that
-- needs to show "who wrote this" stores only the writer's id and looks the name up from here at
-- read time (src/lib/profile.js's fetchProfileNames) — there is deliberately no denormalized
-- name column anywhere else. An earlier version of this schema had published_books, reviews,
-- fireside_posts, guild_book_feedback, and guild_published_books each keep their own copy of
-- the author's name, refreshed by fanning a pen-name change out to all five on every save; that
-- fan-out could partially fail and leave a stray old name on some row indefinitely. Reading the
-- one row here instead removes the whole class of bug — there's nothing left to keep in sync.
-- ============================================================================================

create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  pen_name text check (pen_name is null or char_length(pen_name) <= 80),
  display_name text check (display_name is null or char_length(display_name) <= 80),
  avatar_url text,
  -- Anti-impersonation, piece 2 of 4 (see shared-utils/identity-safety.js for piece 1). Grants a
  -- checkmark badge next to a name so readers can tell a real, confirmed author from someone
  -- merely using their name. Settable in-app by a moderator, from the moderation queue
  -- (src/moderation/moderation-queue.jsx — see lib/moderation.js's setVerified) after confirming
  -- who someone is through some out-of-band channel — there's still no automated verification
  -- flow, and deliberately so: a manually-curated true signal beats an automated one a scammer
  -- could game. protect_admin_profile_columns below still blocks self-verifying (nobody can set
  -- this on their own row, moderator or not).
  verified boolean not null default false,
  -- Gates the in-app moderation queue itself and the "moderators read/update all reports"
  -- policies on content_reports below. Unlike verified/banned, this one stays service_role-only —
  -- see protect_admin_profile_columns below — minting a new moderator is a higher-trust action
  -- than granting a verified badge or a content ban, reserved for you, the deployment operator,
  -- specifically so one moderator account can't mint unlimited others. Flip it manually, e.g. via
  -- the Supabase SQL editor, logged in as the project owner.
  is_moderator boolean not null default false,
  -- Content ban — see is_banned() and its use in every content-creating table's insert/update
  -- policy below. Settable through the app (by a moderator, from the moderation queue —
  -- src/moderation/moderation-queue.jsx) via ordinary RLS — see protect_admin_profile_columns
  -- below for the exact rule. This alone is a content ban, not a login ban: it stops publishing,
  -- posting, leaving feedback, and reviewing, but a banned account can still sign in and read.
  banned boolean not null default false,
  ban_reason text check (ban_reason is null or char_length(ban_reason) <= 500),
  -- A true login ban — blocks sign-in entirely (see admin_set_login_ban() below). This is NOT
  -- settable through ordinary RLS the way `banned` above is: only Supabase's Auth layer
  -- (auth.users.banned_until) can actually block sign-in, and a regular signed-in caller can't
  -- write to the auth schema directly. This column is a client-readable MIRROR of that state,
  -- kept in sync by admin_set_login_ban() via a trusted bypass in protect_admin_profile_columns
  -- — it is never the source of truth and never what actually blocks sign-in, auth.users is.
  login_banned boolean not null default false,
  -- Mirrors login_banned's own "why", kept separate from ban_reason (content ban's own "why")
  -- since the two actions are independent — a moderator may have taken only one of them.
  login_ban_reason text check (login_ban_reason is null or char_length(login_ban_reason) <= 500),
  updated_at timestamptz not null default now()
);

alter table profiles enable row level security;

-- Public read — a profile is meant to be visible to anyone (it's what lets a follower list, a
-- review, a Fireside post, or a guild listing show a name at all). Only the owner can write it.
create policy "anyone can read profiles" on profiles
  for select using (true);
create policy "a user updates their own profile" on profiles
  for update using (auth.uid() = id);
create policy "a user inserts their own profile" on profiles
  for insert with check (auth.uid() = id);
-- Content ban AND the verified badge (see both columns' comments above) — lets a moderator
-- update ANY profile row, not just their own. protect_admin_profile_columns below is what keeps
-- this from also letting a moderator quietly rewrite someone else's name or avatar, or grant
-- is_moderator itself, through this same policy.
create policy "moderators manage other accounts" on profiles
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );

-- Both update policies above are row-scoped, not column-scoped — Postgres RLS has no native
-- per-column restriction. Without this trigger: (a) a signed-in user could include
-- `verified: true` or `is_moderator: true` in their own profile update and self-grant either,
-- and (b) the "moderators manage other accounts" policy above, needed so a moderator can update
-- SOMEONE ELSE's row at all, would just as easily let them rewrite that person's name or avatar
-- — or mint themselves (or anyone) a new moderator — while they're at it. This trigger enforces
-- the actual intended shape of each path:
--   - service_role (an operator working outside the client app): unrestricted, as before.
--   - A moderator acting on someone ELSE's row (via the policy above): may change ONLY
--     banned/ban_reason/verified — the moderation queue's actual toolset
--     (src/moderation/moderation-queue.jsx). Every other column on that row, is_moderator and
--     login_banned included, is held to its existing value.
--   - Anyone (moderator or not) acting on their OWN row (via the ordinary "own profile" policy):
--     may change name/avatar as before, but never banned/ban_reason/verified — no self-
--     unbanning, no self-verifying, and no way to plant a fake ban_reason on your own account.
--   - is_moderator: locked to service_role in EVERY path, full stop, moderator-on-someone-else's-
--     row included — minting a new moderator is a higher-trust action than granting a content
--     ban or a verified badge, and is reserved for you, the deployment operator, specifically so
--     one moderator account can't mint unlimited others.
--   - login_banned/login_ban_reason: also locked to service_role in every path — see
--     login_banned's own comment. It's a mirror of admin_set_login_ban()-managed state, not
--     something the ordinary moderator-update path should ever be able to set on its own (that
--     would make the mirror lie about whether a real login ban is actually in effect at the Auth
--     layer). admin_set_login_ban() below writes it through a separate, narrow trusted-RPC
--     bypass (inkroot.trusted_admin_rpc) rather than as service_role — see that function's own
--     comment for why it can't simply run as service_role itself.
create or replace function protect_admin_profile_columns()
returns trigger as $$
declare
  acting_is_moderator boolean;
begin
  if coalesce(auth.role(), '') = 'service_role' then
    return new;
  end if;
  -- Narrow, transaction-local escape hatch used ONLY by admin_set_login_ban() below, and only to
  -- update login_banned/login_ban_reason on the one row it just finished authorizing itself
  -- against — see that function's comment. set_config's third argument (is_local = true) means
  -- this can never leak past the current transaction, so no other code path can ever see or set
  -- it.
  if coalesce(current_setting('inkroot.trusted_admin_rpc', true), '') = 'true' then
    return new;
  end if;
  if new.is_moderator is distinct from old.is_moderator then
    new.is_moderator := old.is_moderator;
  end if;
  if new.login_banned is distinct from old.login_banned then
    new.login_banned := old.login_banned;
  end if;
  if new.login_ban_reason is distinct from old.login_ban_reason then
    new.login_ban_reason := old.login_ban_reason;
  end if;
  select p.is_moderator into acting_is_moderator from profiles p where p.id = auth.uid();
  if coalesce(acting_is_moderator, false) and auth.uid() <> old.id then
    new.pen_name := old.pen_name;
    new.display_name := old.display_name;
    new.avatar_url := old.avatar_url;
  else
    new.banned := old.banned;
    new.ban_reason := old.ban_reason;
    new.verified := old.verified;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists protect_verified_column_trigger on profiles;
drop trigger if exists protect_admin_profile_columns_trigger on profiles;
create trigger protect_admin_profile_columns_trigger
  before update on profiles
  for each row execute function protect_admin_profile_columns();

-- The real login ban — actually blocks sign-in, unlike the plain `banned` content-ban column
-- above. Callable directly via supabase.rpc('admin_set_login_ban', {...}) from the client — no
-- service-role key or separately-deployed server needed, unlike a typical "call the Auth Admin
-- API" approach would require. SECURITY DEFINER lets this function touch auth.users (a regular
-- signed-in caller can't write there directly, by design — that's exactly why this needs to be a
-- SECURITY DEFINER function rather than a plain RLS-scoped client call), but auth.uid()/
-- auth.role() still reflect the ACTUAL caller throughout (Supabase's auth helpers read live JWT
-- claims off the request, not the function owner's identity) — see the moderator check below,
-- which is what stands in for the RLS check this function's elevated privilege bypasses.
create or replace function admin_set_login_ban(target_user_id uuid, should_ban boolean, reason text default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (select 1 from profiles where id = auth.uid() and is_moderator) then
    raise exception 'Only a moderator can change login-ban status.';
  end if;
  if target_user_id = auth.uid() then
    raise exception 'Cannot change your own login-ban status.';
  end if;

  update auth.users set banned_until = case when should_ban then 'infinity'::timestamptz else null end
  where id = target_user_id;

  if should_ban then
    -- Same technique, and the same residual-token caveat, as purge_expired_account_deletions
    -- further below: this blocks all FUTURE sign-ins and token refreshes immediately, but an
    -- access token already issued before this call keeps working until it naturally expires
    -- (your project's JWT expiry window — Auth settings, default 1 hour). Deleting the
    -- session/refresh token here still matters: without it, the ban would only stop a brand-new
    -- sign-in, not someone who's already signed in and would otherwise just keep refreshing
    -- forever on their existing session.
    delete from auth.sessions where user_id = target_user_id;
    delete from auth.refresh_tokens where user_id = target_user_id::text;
  end if;

  -- Updates the client-readable mirror via the narrow trusted-RPC bypass in
  -- protect_admin_profile_columns above — see that trigger's comment on login_banned. is_local
  -- (the third argument) means this setting is automatically cleared at the end of this
  -- transaction, so it can never leak into any later, unrelated statement.
  perform set_config('inkroot.trusted_admin_rpc', 'true', true);
  update profiles set login_banned = should_ban, login_ban_reason = case when should_ban then reason else null end
  where id = target_user_id;
end;
$$;

grant execute on function admin_set_login_ban(uuid, boolean, text) to authenticated;

-- Used by every content-creating table's insert/update policy below to block a banned account
-- from publishing, posting, or reviewing anywhere, without each policy needing its own inline
-- subquery. `stable` (not `volatile`) lets Postgres cache the result within one statement.
create or replace function is_banned(check_user_id uuid)
returns boolean as $$
  select coalesce((select p.banned from profiles p where p.id = check_user_id), false);
$$ language sql stable;

-- Auto-creates a minimal profile row the moment someone signs up, so the client only ever needs
-- to UPDATE (src/lib/profile.js's syncProfile) rather than juggling an insert-or-update dance.
-- Seeded with a non-identifying 'Writer <id8>' fallback — never anything derived from the
-- account's email, since this row is publicly readable from the moment it's created.
create or replace function handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, 'Writer ' || substr(new.id::text, 1, 8));
  return new;
end;
$$ language plpgsql security definer set search_path = public;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ============================================================================================
-- published_books / reviews / follows — the Grand Library: public listings, ratings, and the
-- follow graph. A book's actual content stays only in kv_store (and locally in IndexedDB); this
-- is the public subset (title/blurb/genre/tags/price) other readers are allowed to see at all.
-- ============================================================================================

-- Single source of truth for the "no empty/near-empty listings" floor referenced by
-- published_books' and guild_published_books' insert/update policies below. Matches
-- MIN_PUBLISH_WORDS in src/library/publishing.jsx, which is this same number's client-side half —
-- that constant is what blocks a writer from reaching Step 4 of the Publishing Wizard at all, so
-- in normal use nobody actually hits the check here; this is the backstop for anything that skips
-- the wizard (a direct API call, or any future publish path that forgets to check client-side).
-- A plain function rather than a bare literal in every check clause below, so the number only
-- ever needs to change in one place.
create or replace function min_publish_word_count()
returns integer as $$
  select 5000;
$$ language sql immutable;

-- Anthologies are a group project — several contributors' submissions combined into one
-- published_books row (see publish_guild_anthology below) — so they get their own, higher floor
-- rather than sharing min_publish_word_count()'s solo-author number. Same single-source-of-truth
-- reasoning: only has to change in one place.
create or replace function min_anthology_publish_word_count()
returns integer as $$
  select 50000;
$$ language sql immutable;

create table if not exists published_books (
  id text primary key, -- matches the app's own local project id, so no id-mapping layer is needed
  author_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) <= 200),
  -- subtitle/series_name/cover/word_count mirror guild_published_books' columns below exactly —
  -- added so fetchPublishedBooksByAuthor (lib/library.js) can return a real author's books as
  -- full display cards (see library/authors-hall-screen.jsx's publicBooks) instead of a plain
  -- title/blurb/genre stub. published_books didn't carry these originally because nothing before
  -- the real-author-accounts work (see lib/profile.js's fetchPublicProfile) needed a full remote
  -- copy of a book's display metadata for a DIFFERENT device to render.
  subtitle text check (subtitle is null or char_length(subtitle) <= 200),
  series_name text check (series_name is null or char_length(series_name) <= 200),
  cover jsonb, -- the structured cover object (style/accent/motif/customImageUrl), not a URL
  blurb text check (blurb is null or char_length(blurb) <= 2000),
  genre text,
  tags jsonb,
  word_count integer default 0,
  -- No real payment processor exists yet (see publishing.jsx's own comment on this), so price is
  -- display-only today — but a negative value here is meaningless regardless, and free to
  -- disallow now rather than after real payments depend on it being trustworthy.
  price numeric default 0 check (price >= 0),
  -- Mirrors the app's own publishStatus values (see project-workspace.jsx's
  -- handleWizardPublishBook and publishing.jsx's PublishWizard) — nothing else in the app ever
  -- sets this to anything but 'guild' or 'inkroot', so the same check founder_guild_members.
  -- guild_id already gets below is added here too, instead of leaving it as a plain unconstrained
  -- text column.
  destination text not null default 'inkroot' check (destination in ('guild', 'inkroot')),
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table published_books enable row level security;

-- Unlike kv_store, a listing published to the Grand Library (destination = 'inkroot') is meant
-- to be public — that's the entire point of publishing there. Only the author can create/modify/
-- remove their own listings, regardless of destination.
--
-- The select policy below was originally "for select using (true)" — fully open, on the
-- (wrong) assumption that every row here was Grand-Library-public by definition. A row published
-- with destination = 'guild' is NOT meant to be public — see the Migration 90 section near the
-- end of this file (kept here, unmodified, only so a reader of this file top-to-bottom sees the
-- table's original shape before its later history, same pattern published_book_content's own
-- comment below already uses) — the DROP POLICY down there is what actually takes effect once
-- this whole file has run.
create policy "anyone can read published books" on published_books
  for select using (true);
create policy "author creates own listings" on published_books
  for insert with check (auth.uid() = author_id and not is_banned(auth.uid()) and word_count >= min_publish_word_count());
create policy "author updates own listings" on published_books
  for update using (auth.uid() = author_id and not is_banned(auth.uid()))
  with check (auth.uid() = author_id and not is_banned(auth.uid()) and word_count >= min_publish_word_count());
create policy "author deletes own listings" on published_books
  for delete using (auth.uid() = author_id);

create table if not exists reviews (
  id uuid primary key default gen_random_uuid(),
  book_id text not null references published_books(id) on delete cascade,
  reviewer_id uuid not null references auth.users(id) on delete cascade,
  -- Restored here after being dropped by accident during the schema_phase*.sql -> schema.sql
  -- consolidation — see 61_migration_reviews_rating_column.sql for the full story. Every client
  -- call that reads or writes a review (src/lib/library.js's submitReview/fetchBookStats/
  -- fetchAuthorRatingsSummary) has always assumed this column exists.
  rating smallint not null check (rating between 1 and 5),
  body text check (body is null or char_length(body) <= 4000),
  created_at timestamptz not null default now(),
  -- One review per reader per book — matches the app's own local `myRating` concept (a single
  -- rating value per reader), just made real across readers instead of only the local device.
  unique (book_id, reviewer_id)
);

alter table reviews enable row level security;

create policy "anyone can read reviews" on reviews
  for select using (true);
create policy "signed-in readers write their own review" on reviews
  for insert with check (auth.uid() = reviewer_id and not is_banned(auth.uid()));
create policy "reviewer updates own review" on reviews
  for update using (auth.uid() = reviewer_id and not is_banned(auth.uid()));
create policy "reviewer deletes own review" on reviews
  for delete using (auth.uid() = reviewer_id);

create table if not exists follows (
  follower_id uuid not null references auth.users(id) on delete cascade,
  followee_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, followee_id)
);

alter table follows enable row level security;

create policy "anyone can read follows" on follows
  for select using (true);
create policy "a reader manages their own follow" on follows
  for insert with check (auth.uid() = follower_id and not is_banned(auth.uid()));
create policy "a reader removes their own follow" on follows
  for delete using (auth.uid() = follower_id);

-- (book_id, created_at desc), not just (book_id) -- matches the actual query shape every caller
-- uses (fetchBookStats/fetchAuthorRatingsSummary in library.js: eq/in on book_id, ordered by
-- created_at desc), so Postgres can satisfy both the filter and the ordering directly from the
-- index instead of filtering on book_id then sorting the matches separately.
create index if not exists reviews_book_idx on reviews (book_id, created_at desc);
-- Same reasoning as reviews_book_idx above -- fetchFollowers (library.js) filters on followee_id
-- and orders by created_at desc.
create index if not exists follows_followee_idx on follows (followee_id, created_at desc);
create index if not exists published_books_author_idx on published_books (author_id);

-- ============================================================================================
-- published_book_content — the public, reader-facing mirror of a book's manuscript, written at
-- publish time (see 70_migration_published_book_content.sql for the full story of why this
-- exists: published_books above is the listing only, and a book's actual text otherwise lives
-- solely in kv_store, which is strictly private to its author — so nobody else's device ever
-- had anything to read). Deliberately a single jsonb blob shaped exactly like what
-- PublishedBookReader (author-reputation.jsx) needs to render — title/subtitle/seriesName/
-- author/cover/storyFormat/chapters — not a normalized per-chapter table, since nothing
-- server-side needs to query *inside* a chapter (same reasoning kv_store itself stays a blob).
--
-- Was fully public regardless of price when this table was first introduced ("reading is free by
-- product design" — grand-library-cards.jsx's own copy: "reading in full stays free either way";
-- Buy/tip supports the author, it isn't a paywall). That's still true for a FREE book (price <=
-- 0) — reading one in full has always been the point. A PRICED book no longer is: this table's
-- own select policy is replaced further down, in the Migration 89 section near the end of this
-- file (kept there rather than edited in place here, matching how Migrations 80+ are folded into
-- this consolidated file — every table this policy needs to reference, `purchases` included, has
-- to exist first) — see that section's header for the full story of the hole this closed and how
-- the "peek at the opening" preview keeps working for a priced, unpurchased book without
-- reopening it. Migration 90 (also near the end of this file) narrows Migration 89's own
-- "free book content is public" policy further still, so a guild-only book's content doesn't
-- leak the same way a priced one used to. Writable only by the book's own author, unchanged by
-- any of this.
-- ============================================================================================

create table if not exists published_book_content (
  book_id text primary key references published_books(id) on delete cascade,
  content jsonb not null,
  updated_at timestamptz not null default now(),
  check (octet_length(content::text) <= 20971520)
);

alter table published_book_content enable row level security;

-- Replaced below (Migration 89 section, near the end of this file) with three narrower
-- policies — kept here, unmodified, only so a reader of this file top-to-bottom sees the table's
-- original shape before its later history; the DROP POLICY down there is what actually takes
-- effect once this whole file has run.
create policy "anyone can read published book content" on published_book_content
  for select using (true);
create policy "author writes own book content" on published_book_content
  for insert with check (
    exists (select 1 from published_books b where b.id = book_id and b.author_id = auth.uid())
    and not is_banned(auth.uid())
  );
create policy "author updates own book content" on published_book_content
  for update using (
    exists (select 1 from published_books b where b.id = book_id and b.author_id = auth.uid())
    and not is_banned(auth.uid())
  )
  with check (
    exists (select 1 from published_books b where b.id = book_id and b.author_id = auth.uid())
    and not is_banned(auth.uid())
  );

create or replace function stamp_published_book_content()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists published_book_content_stamp on published_book_content;
create trigger published_book_content_stamp
  before insert or update on published_book_content
  for each row execute function stamp_published_book_content();

-- ============================================================================================
-- Founder Guilds — a fixed, permanent set of ten (see FOUNDER_GUILDS in guild-hall.jsx), so
-- guild_id below is a plain text id matching the app's own guild key strings (checked against
-- that fixed list) rather than a foreign key into a guilds table that doesn't exist.
--
-- founder_guild_members must exist before the Fireside/Bookshelf policies further down, since
-- those policies check membership against it.
-- ============================================================================================

create table if not exists founder_guild_members (
  guild_id text not null check (guild_id in (
    'fantasy', 'romance', 'scifi', 'historical', 'horror',
    'mystery', 'comedy', 'worldbuilders', 'poetry', 'general'
  )),
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (guild_id, user_id)
);

alter table founder_guild_members enable row level security;

-- Public read — membership itself isn't sensitive (unlike a Player Guild's invite_code), and
-- every policy below needs to check "is this uid a member of this guild_id" regardless of asker.
create policy "anyone can read founder guild members" on founder_guild_members
  for select using (true);
create policy "a writer joins a founder guild on their own behalf" on founder_guild_members
  for insert with check (auth.uid() = user_id and not is_banned(auth.uid()));
create policy "a writer leaves a founder guild on their own behalf" on founder_guild_members
  for delete using (auth.uid() = user_id);

-- No separate (guild_id) index here -- the primary key above is (guild_id, user_id), whose
-- leading column already covers a plain "guild_id = X" lookup exactly as well as a dedicated
-- single-column index would (see 20_migration_drop_redundant_guild_indexes.sql). A second index
-- on just guild_id would only add write overhead to every join/leave with no read benefit.

-- ============================================================================================
-- Fireside (guild discussion board) + Guild Bookshelf feedback — Founder Guilds only. Read/
-- write require actual founder_guild_members membership, not just "signed in" — an earlier
-- version of this schema only checked sign-in, before founder_guild_members existed to check
-- membership against.
-- ============================================================================================

create table if not exists fireside_posts (
  id uuid primary key default gen_random_uuid(),
  guild_id text not null,
  parent_id uuid references fireside_posts(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  category text,
  body text not null check (char_length(body) <= 8000),
  pinned boolean not null default false,
  created_at timestamptz not null default now()
);

alter table fireside_posts enable row level security;

create policy "guild members read fireside posts" on fireside_posts
  for select using (
    exists (
      select 1 from founder_guild_members m
      where m.guild_id = fireside_posts.guild_id and m.user_id = auth.uid()
    )
  );
-- Lets the moderation queue (src/moderation/moderation-queue.jsx) show a reported post's actual
-- text even when the reviewing moderator isn't a member of that guild — see profiles.is_moderator.
create policy "moderators read all fireside posts" on fireside_posts
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "guild members post to fireside" on fireside_posts
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = fireside_posts.guild_id and m.user_id = auth.uid()
    )
  );
-- Update is author-only (not "any guild member") — Postgres RLS can't cleanly restrict an
-- UPDATE to just the `pinned` column, and opening update to every member would let anyone edit
-- anyone's post body. Founder/moderator-only pinning of *other* members' posts is a reasonable
-- follow-up once a roles concept exists.
create policy "author updates own post" on fireside_posts
  for update using (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author deletes own post" on fireside_posts
  for delete using (auth.uid() = author_id);

create index if not exists fireside_posts_guild_idx on fireside_posts (guild_id, created_at desc);

-- Closes item 6 of the audit: fireside_posts caps body length at 8000 chars but had no
-- posting-frequency limit, so a member (or a script driving their session) could flood the
-- board with rapid-fire posts and replies — both are the same table, so one cooldown covers
-- both. A lightweight per-author cooldown, checked against the author's own most recent post
-- across every guild (flooding is flooding regardless of which board it lands on).
--
-- pg_advisory_xact_lock, same style as distribute_guild_revenue's own lock above — but keyed
-- per-author instead of per-sale, and for a different race: without it, two near-simultaneous
-- insert requests from the same author could both read "no recent post yet" (neither has
-- committed) and both slip through. Locking on the author serializes that check within the
-- same transaction scope, so the second request always sees the first's row.
create or replace function enforce_fireside_post_cooldown()
returns trigger as $$
declare
  v_last_post_at timestamptz;
  v_cooldown interval := interval '15 seconds';
begin
  perform pg_advisory_xact_lock(hashtext('fireside_post_cooldown:' || new.author_id::text));

  select max(created_at) into v_last_post_at
  from fireside_posts where author_id = new.author_id;

  if v_last_post_at is not null and now() - v_last_post_at < v_cooldown then
    raise exception 'You''re posting too quickly — please wait a few seconds before posting again.';
  end if;

  return new;
end;
$$ language plpgsql;

drop trigger if exists fireside_post_cooldown_trigger on fireside_posts;
create trigger fireside_post_cooldown_trigger
  before insert on fireside_posts
  for each row execute function enforce_fireside_post_cooldown();

-- One row per (post, reader, reaction kind) rather than a jsonb counter on the post — avoids
-- read-modify-write races when multiple guild members react around the same time.
create table if not exists fireside_reactions (
  post_id uuid not null references fireside_posts(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  reaction text not null,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id, reaction)
);

alter table fireside_reactions enable row level security;

-- No guild_id column of its own — membership is checked by joining back to the post reacted to.
create policy "guild members read reactions" on fireside_reactions
  for select using (
    exists (
      select 1 from fireside_posts p
      join founder_guild_members m on m.guild_id = p.guild_id and m.user_id = auth.uid()
      where p.id = fireside_reactions.post_id
    )
  );
create policy "guild members add their own reaction" on fireside_reactions
  for insert with check (
    auth.uid() = user_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from fireside_posts p
      join founder_guild_members m on m.guild_id = p.guild_id and m.user_id = auth.uid()
      where p.id = fireside_reactions.post_id
    )
  );
create policy "a reader removes their own reaction" on fireside_reactions
  for delete using (auth.uid() = user_id);

-- Enables Supabase Realtime for the Fireside — lets FiresideBoard subscribe to live inserts
-- instead of only refreshing on its own actions, so a guildmate's post appears without a reload.
alter publication supabase_realtime add table fireside_posts;
alter publication supabase_realtime add table fireside_reactions;

create table if not exists guild_book_feedback (
  id uuid primary key default gen_random_uuid(),
  guild_id text not null,
  book_id text not null,
  author_id uuid not null references auth.users(id) on delete cascade,
  stars smallint check (stars between 1 and 5),
  note text check (note is null or char_length(note) <= 4000),
  created_at timestamptz not null default now(),
  -- One feedback entry per guild member per book — matches the app's own local feedback concept
  -- (a single piece of feedback a member leaves a guildmate's book) and mirrors `reviews`' own
  -- `unique (book_id, reviewer_id)` above. Without this, addGuildBookFeedback's plain insert let
  -- the same member post unlimited feedback rows for the same book.
  unique (guild_id, book_id, author_id)
);

alter table guild_book_feedback enable row level security;

create policy "guild members read guild feedback" on guild_book_feedback
  for select using (
    exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );
-- Moderator bypass, same reasoning as fireside_posts' sibling policy above.
create policy "moderators read all guild feedback" on guild_book_feedback
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "guild members post guild feedback" on guild_book_feedback
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );
-- Update re-checks current membership (an author who's since left the guild can no longer edit
-- an old feedback row's content); delete stays plain author-only — retracting your own already-
-- posted feedback doesn't need the same gate as editing its content does.
create policy "guild members update own feedback" on guild_book_feedback
  for update using (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );
create policy "author deletes own feedback" on guild_book_feedback
  for delete using (auth.uid() = author_id);
-- Player Guild sibling policies (select/insert/update) for this table are added later in this
-- file, once player_guild_members exists (see 92_migration_player_guild_book_publishing.sql,
-- folded in near the end of this file alongside its guild_published_books/published_books
-- counterparts) — this table is defined before player_guild_members below, and a policy's
-- predicate is validated against real tables at creation time, so those siblings can't be
-- declared right here.

create index if not exists guild_feedback_book_idx on guild_book_feedback (guild_id, book_id, created_at desc);

-- ============================================================================================
-- Player Guilds — writer-created, joinable guilds with a real roster (unlike Founder Guilds'
-- fixed ten). invite_code is server-generated so uniqueness never needs client-side retry logic.
-- ============================================================================================

create table if not exists player_guilds (
  id uuid primary key,
  name text not null,
  motto text,
  crest_url text,
  owner_id uuid not null references auth.users(id) on delete cascade,
  invite_code text unique not null default substr(replace(gen_random_uuid()::text, '-', ''), 1, 8),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- One Player Guild per owner, unconditionally — the product only ever lets a writer found one
-- (ink-root.jsx's enterOwnGuild reuses the same locally-stored guild id after the first founding)
-- but that rule previously lived only in client state. This is the hard backstop: even a direct
-- insert that skips create_or_get_own_guild() below entirely cannot create a second row for the
-- same owner_id. See create_or_get_own_guild() for the friendly, catchable error this pairs with.
create unique index if not exists player_guilds_owner_id_key on player_guilds (owner_id);

alter table player_guilds enable row level security;

-- Read is restricted to the guild's owner and its actual members — NOT "anyone can read".
-- Postgres RLS can't hide individual columns from a `select('*')`, so any select policy open to
-- non-members would expose every guild's invite_code to every signed-in reader, defeating the
-- entire point of an invite-only guild. Joining by code is still possible without a public
-- row-level select: see join_player_guild_by_code() below, a security-definer function that
-- looks the row up server-side and never returns invite_code to a non-member.
create policy "owner or member can read their player guild" on player_guilds
  for select using (
    auth.uid() = owner_id
    or exists (
      select 1 from player_guild_members m
      where m.guild_id = player_guilds.id and m.user_id = auth.uid()
    )
  );
create policy "owner creates their guild" on player_guilds
  for insert with check (auth.uid() = owner_id and not is_banned(auth.uid()));
create policy "owner updates their guild" on player_guilds
  for update using (auth.uid() = owner_id);

create table if not exists player_guild_members (
  guild_id uuid not null references player_guilds(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (guild_id, user_id)
);

alter table player_guild_members enable row level security;

create policy "anyone can read player guild members" on player_guild_members
  for select using (true);
create policy "a writer joins on their own behalf" on player_guild_members
  for insert with check (auth.uid() = user_id and not is_banned(auth.uid()));
create policy "a writer leaves on their own behalf" on player_guild_members
  for delete using (auth.uid() = user_id);

-- No separate (guild_id) index -- same reasoning as founder_guild_members above: this table's
-- own primary key is (guild_id, user_id), so its leading column already serves a plain
-- "guild_id = X" lookup.

-- Lets a signed-in writer join a guild by invite code without ever needing a public select
-- policy on player_guilds. security definer means this function runs with the privileges of its
-- owner, not the caller — so it can look up the guild by invite_code internally (bypassing the
-- caller's own, restricted, RLS) and insert the membership row, but the only thing it ever
-- returns to the caller is the guild's non-secret fields. search_path is pinned so it can't be
-- hijacked by a same-named object elsewhere on the schema search path.
create or replace function join_player_guild_by_code(p_code text)
returns table (id uuid, name text, motto text, crest_url text, owner_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_guild player_guilds%rowtype;
begin
  select * into v_guild from player_guilds g where g.invite_code = lower(p_code);
  if not found then
    raise exception 'No guild found with that invite code.';
  end if;

  insert into player_guild_members (guild_id, user_id)
  values (v_guild.id, auth.uid())
  on conflict (guild_id, user_id) do nothing;

  -- owner_id is included here (unlike invite_code) because the client's join flow
  -- (ink-root.jsx's joinGuildByCode) records it locally as joinedGuild.ownerId — owner_id isn't
  -- secret the way invite_code is, so returning it doesn't reopen the gap this function closes.
  return query select v_guild.id, v_guild.name, v_guild.motto, v_guild.crest_url, v_guild.owner_id;
end;
$$;

-- A security-definer function typically runs as the table owner and so bypasses RLS on every
-- table it touches, including player_guild_members — but that's not a problem here because the
-- membership row this inserts always uses auth.uid() directly (never a caller-supplied user
-- id), so there's no way to call this to join a guild on someone else's behalf even with RLS
-- bypassed.
grant execute on function join_player_guild_by_code(text) to authenticated;

-- Friendly front door for founding/editing a writer's own Player Guild, replacing the direct
-- upsert syncPlayerGuild (src/lib/player-guild.js) used to do. The unique index above is the
-- unconditional guarantee; this function is what makes hitting it a clear, catchable error
-- instead of a raw unique-violation — it checks ownership itself first and raises a message the
-- client can actually show. Also folds in the player_guild_members "owner is a member too" row
-- syncPlayerGuild used to insert as a separate call, so founding a guild is one atomic step.
create or replace function create_or_get_own_guild(p_id uuid, p_name text, p_motto text, p_crest_url text)
returns setof player_guilds
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing player_guilds%rowtype;
begin
  if is_banned(auth.uid()) then
    raise exception 'Your account is suspended and can''t found or edit a guild.';
  end if;

  select * into v_existing from player_guilds where owner_id = auth.uid();
  -- Found is the giveaway of the bug this closes: a *different* locally-generated id (from a
  -- second device, or a cleared local profile) trying to found a second guild for the same
  -- owner. Same id just means "re-entering / editing my own guild" and always falls through to
  -- the upsert below, same as it always has.
  if found and v_existing.id <> p_id then
    raise exception 'You already own a Player Guild — a writer can only found one.';
  end if;

  insert into player_guilds (id, name, motto, crest_url, owner_id, updated_at)
  values (p_id, p_name, p_motto, p_crest_url, auth.uid(), now())
  on conflict (id) do update set
    name = excluded.name,
    motto = excluded.motto,
    crest_url = excluded.crest_url,
    updated_at = now();

  -- Same reasoning as join_player_guild_by_code() above: this always uses auth.uid() directly,
  -- never a caller-supplied user id, so bypassing RLS here can't be used to add anyone else.
  insert into player_guild_members (guild_id, user_id)
  values (p_id, auth.uid())
  on conflict (guild_id, user_id) do nothing;

  return query select * from player_guilds where id = p_id;
end;
$$;

grant execute on function create_or_get_own_guild(uuid, text, text, text) to authenticated;

-- ============================================================================================
-- Founder Guild parity — Founder Guilds materialized as real player_guilds rows.
--
-- Until now, everything hanging off player_guilds.id (guild_anthologies, guild_treasury_
-- transactions, guild_events, guild_event_hosting_fee_payments, guild_event_financial_
-- agreements — the entire money-moving side of a guild) only ever pointed at a Player Guild.
-- A Founder Guild (the 10 fixed lore guilds — see FOUNDER_GUILDS in guild-hall.jsx) had no row
-- here at all, so none of that could ever apply to one; its Anthology/Treasury tabs stayed
-- permanently simulated (see guild-order.jsx's HONESTY NOTE / ARCHITECTURE.md).
--
-- Rather than adding a parallel founder_guild_id column to every single one of those tables
-- (doubling every join, every RLS policy, and every RPC signature), this migration gives each
-- of the 10 Founder Guilds one real, fixed-id row in player_guilds itself. Every table and
-- function that already speaks "guild_id uuid references player_guilds(id)" now works for a
-- Founder Guild automatically, with zero further schema changes downstream.
--
-- A Founder Guild row is distinguished by is_founder_guild = true and a stable founder_slug
-- (matching FOUNDER_GUILDS[].id client-side: 'fantasy', 'romance', etc.) instead of an owner_id
-- — nobody personally owns a Founder Guild the way a Player Guild's founder does. Its "officer"
-- authority (treasury spend, revenue agreements, hosting fees — anywhere a Player Guild check
-- would look at owner_id) is delegated instead to whichever profile(s) carry is_platform_admin,
-- by Inkroot's own decision that the platform admin (and anyone they appoint via that same flag)
-- acts as every Founder Guild's officer. See is_guild_officer()/is_guild_member() below — the
-- single place this rule is decided, so every call site listed above agrees with the UI.
--
-- founder_guild_members (membership/roster — already real, see the Guild Presence migration) is
-- deliberately left untouched: it's still the one source of truth for who's actually in a
-- Founder Guild, keyed by the same text slug it always used. is_guild_member() below bridges the
-- two — reading player_guild_members for a Player Guild, founder_guild_members for a Founder
-- Guild — rather than migrating membership rows into player_guild_members, which would have
-- meant reshaping a table (and every trigger/RLS policy already built on it) that already works.
-- ============================================================================================

alter table player_guilds add column if not exists is_founder_guild boolean not null default false;
alter table player_guilds add column if not exists founder_slug text;
alter table player_guilds alter column owner_id drop not null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'player_guilds_owner_xor_founder') then
    alter table player_guilds add constraint player_guilds_owner_xor_founder check (
      (is_founder_guild and owner_id is null and founder_slug is not null)
      or (not is_founder_guild and owner_id is not null and founder_slug is null)
    );
  end if;
end $$;

create unique index if not exists player_guilds_founder_slug_idx on player_guilds (founder_slug)
  where founder_slug is not null;

-- Fixed, deterministic ids — never regenerated — so every reference to one of these 10 rows
-- (client-side and in any future migration) is stable across environments. Order/wording matches
-- FOUNDER_GUILDS in src/guild/guild-hall.jsx exactly; keep both in sync if a guild is ever
-- renamed. invite_code is meaningless for a Founder Guild (always open, never invite-only) but
-- the column is NOT NULL/unique, so each gets a fixed, obviously-synthetic value instead of a
-- random one.
insert into player_guilds (id, name, motto, owner_id, is_founder_guild, founder_slug, invite_code)
values
  ('00000000-f01d-4000-8000-000000000001', 'The Fantasy Guild', 'Where dragons rise and kingdoms are born.', null, true, 'fantasy', 'founder-fantasy'),
  ('00000000-f01d-4000-8000-000000000002', 'The Romance Guild', 'Every heart has a story worth telling.', null, true, 'romance', 'founder-romance'),
  ('00000000-f01d-4000-8000-000000000003', 'The Science Fiction Guild', 'Chart the unknown, one page at a time.', null, true, 'scifi', 'founder-scifi'),
  ('00000000-f01d-4000-8000-000000000004', 'The Historical Guild', 'The past deserves an eloquent witness.', null, true, 'historical', 'founder-historical'),
  ('00000000-f01d-4000-8000-000000000005', 'The Horror Guild', 'Fear is just another kind of honesty.', null, true, 'horror', 'founder-horror'),
  ('00000000-f01d-4000-8000-000000000006', 'The Mystery Guild', 'Every clue leads somewhere.', null, true, 'mystery', 'founder-mystery'),
  ('00000000-f01d-4000-8000-000000000007', 'The Comedy Guild', 'Laughter is the plot twist we all need.', null, true, 'comedy', 'founder-comedy'),
  ('00000000-f01d-4000-8000-000000000008', 'The Worldbuilders Guild', 'Maps, myths, and the bones of new worlds.', null, true, 'worldbuilders', 'founder-worldbuilders'),
  ('00000000-f01d-4000-8000-000000000009', 'The Poetry Guild', 'Say more with less.', null, true, 'poetry', 'founder-poetry'),
  ('00000000-f01d-4000-8000-00000000000a', 'The General Writers Guild', 'For stories that defy a single shelf.', null, true, 'general', 'founder-general')
on conflict (founder_slug) where founder_slug is not null do nothing;

-- The player_guilds select policy (owner-or-member only, to protect invite_code) doesn't cover
-- these — nobody is ever their owner_id, and Founder Guild members are never inserted into
-- player_guild_members. A Founder Guild's existence/name/motto/id isn't sensitive the way an
-- invite_code is (every writer already sees all 10 in FOUNDER_GUILDS client-side), so this is a
-- narrow, public, read-only allowance for exactly the founder rows — never invite_code-bearing
-- Player Guild rows, which stay exactly as restricted as before.
create policy "anyone can read the 10 founder guild rows" on player_guilds
  for select using (is_founder_guild);

-- language plpgsql (not sql) deliberately: its body references profiles.is_platform_admin and
-- is_inkroot_admin(), both defined later in this file (see the Inkroot Admin migration below) —
-- a plpgsql body is only checked at first call, not at CREATE FUNCTION time, so this forward
-- reference is safe as long as both exist by the time schema.sql finishes running, which they do.
--
-- is_guild_member — "is this caller allowed in at all" for a guild_id that could be either kind.
-- Player Guild: real player_guild_members row. Founder Guild: real founder_guild_members row,
-- looked up by the row's founder_slug (founder_guild_members itself is still keyed by that text
-- slug, unchanged by this migration).
create or replace function is_guild_member(p_guild_id uuid)
returns boolean
language plpgsql stable security definer set search_path = public
as $$
declare
  v_guild player_guilds%rowtype;
begin
  select * into v_guild from player_guilds where id = p_guild_id;
  if not found then
    return false;
  end if;
  if v_guild.is_founder_guild then
    return exists (
      select 1 from founder_guild_members m
      where m.guild_id = v_guild.founder_slug and m.user_id = auth.uid()
    );
  end if;
  return exists (
    select 1 from player_guild_members m where m.guild_id = v_guild.id and m.user_id = auth.uid()
  );
end;
$$;

revoke all on function is_guild_member(uuid) from public;
grant execute on function is_guild_member(uuid) to authenticated;

-- is_guild_officer — "is this caller allowed to act with this guild's authority" (approve/spend/
-- publish/host — everywhere a Player Guild check used to be a plain owner_id = auth.uid()).
-- Player Guild: the real owner. Founder Guild: any Inkroot admin (is_platform_admin) — see this
-- migration's own header for why a Founder Guild delegates officer authority that way instead of
-- to a single owner.
create or replace function is_guild_officer(p_guild_id uuid)
returns boolean
language plpgsql stable security definer set search_path = public
as $$
declare
  v_guild player_guilds%rowtype;
begin
  select * into v_guild from player_guilds where id = p_guild_id;
  if not found then
    return false;
  end if;
  if v_guild.is_founder_guild then
    return is_inkroot_admin() and auth.uid() is not null;
  end if;
  return v_guild.owner_id = auth.uid();
end;
$$;

revoke all on function is_guild_officer(uuid) from public;
grant execute on function is_guild_officer(uuid) to authenticated;

-- ============================================================================================
-- guild_member_stats — makes Guild Level/XP/Reputation a real sum across a Player Guild's
-- actual members, instead of each member's screen computing them from local activity alone.
-- Founder Guilds are NOT covered here — every other "member" shown there is still a simulated
-- presence (see guild-order.jsx's HONESTY NOTE), so there's no real roster to sum yet.
--
-- One row per (guild, member), holding that member's own raw contribution counts — not a
-- pre-computed XP or reputation number — so the reward formulas in guild-progression.jsx can
-- change later without a data migration.
--
-- Every value here is computed client-side with no server-side source of truth to verify
-- against, so both an absolute per-column ceiling (the `check` constraints) and a per-write
-- delta cap (the trigger below) exist to bound a bad or malicious push to a generous-but-
-- implausible range rather than leaving it unbounded.
-- ============================================================================================

create table if not exists guild_member_stats (
  guild_id uuid not null,
  user_id uuid not null,
  published_count integer not null default 0 check (published_count between 0 and 10000),
  quests_completed integer not null default 0 check (quests_completed between 0 and 50),
  quest_guild_xp integer not null default 0 check (quest_guild_xp between 0 and 100000),
  writing_day_count integer not null default 0 check (writing_day_count between 0 and 20000),
  fireside_post_count integer not null default 0 check (fireside_post_count between 0 and 200000),
  updated_at timestamptz not null default now(),
  primary key (guild_id, user_id),
  -- Ties every stats row to an actual current membership row, not just a valid guild — so
  -- leaving a guild (player_guild_members' row for this (guild_id, user_id) being deleted)
  -- cascades into deleting this stats row too, instead of it lingering and still counting
  -- toward the guild's total forever.
  foreign key (guild_id, user_id) references player_guild_members (guild_id, user_id) on delete cascade
);

alter table guild_member_stats enable row level security;

-- Read is restricted to fellow guild members — these numbers roll straight into a Level every
-- member's Guild Hall renders, so it's worth actually checking membership.
create policy "guild members read guild member stats" on guild_member_stats
  for select using (
    exists (
      select 1 from player_guild_members m
      where m.guild_id = guild_member_stats.guild_id and m.user_id = auth.uid()
    )
  );

-- A member may only write their own row, and only for a guild they're currently in. The FK
-- above enforces both directions of that at the database level already; this RLS check is kept
-- as a friendlier "permission denied" instead of a raw FK-violation error, and as defense in
-- depth.
create policy "a member inserts their own stats row" on guild_member_stats
  for insert with check (
    auth.uid() = user_id
    and not is_banned(auth.uid())
    and exists (select 1 from player_guild_members m where m.guild_id = guild_member_stats.guild_id and m.user_id = auth.uid())
  );
create policy "a member updates their own stats row" on guild_member_stats
  for update using (auth.uid() = user_id);

-- No separate (guild_id) index here either -- same reasoning as founder_guild_members/
-- player_guild_members above: the primary key (guild_id, user_id) already covers it.

-- Two layers on top of the absolute ceilings above:
--   1. Non-decreasing: every column the app only ever increments, so any UPDATE that lowers one
--      is clamped back up rather than allowed through — either a bug or an attempt to
--      manipulate a total downward.
--   2. Per-write delta caps: bounds how much a single write can add, independent of the
--      absolute ceiling, sized generously enough that a real device catching up after being
--      offline for a long stretch still succeeds — clamped down to the cap rather than rejected
--      outright, so an oversized push always succeeds and just catches up gradually over the
--      next few syncs instead of permanently stalling that column for that member.
--
-- Fires on INSERT as well as UPDATE (see 15_migration_guard_guild_member_stats_insert.sql for
-- deployments upgrading from an earlier version of this trigger). The stats row's own foreign
-- key ties it to a player_guild_members row and cascades on delete — so leaving and rejoining a
-- guild deletes and recreates this row, which used to mean the very first upsert after
-- rejoining hit INSERT, never UPDATE, and so never passed through this trigger at all: a single
-- write could jump straight to the absolute ceiling (e.g. 100,000 XP) instead of being bound by
-- the same per-write delta cap every subsequent UPDATE gets. Treating a fresh INSERT as a delta
-- from an implicit all-zero baseline closes that gap without changing behavior for the normal
-- UPDATE case at all.
create or replace function guard_guild_member_stats_delta()
returns trigger
language plpgsql
as $$
declare
  old_published integer := 0;
  old_quests integer := 0;
  old_xp integer := 0;
  old_writing_days integer := 0;
  old_fireside integer := 0;
begin
  if tg_op = 'UPDATE' then
    old_published := old.published_count;
    old_quests := old.quests_completed;
    old_xp := old.quest_guild_xp;
    old_writing_days := old.writing_day_count;
    old_fireside := old.fireside_post_count;
  end if;

  new.published_count := greatest(old_published, least(new.published_count, old_published + 50));
  -- quests_completed: there are 5 Guild Quests total today (GUILD_QUEST_DEFS in guild-hall.jsx);
  -- a generous cap of 10 leaves headroom for quests added later without needing a migration.
  new.quests_completed := greatest(old_quests, least(new.quests_completed, old_quests + 10));
  -- quest_guild_xp: today's 5 quests sum to 22,500 at most — a single write can't legitimately
  -- exceed that.
  new.quest_guild_xp := greatest(old_xp, least(new.quest_guild_xp, old_xp + 22500));
  -- writing_day_count: 60 covers two full months of offline catch-up in a single sync; a longer
  -- absence just takes an extra sync or two to fully catch up instead of failing outright.
  new.writing_day_count := greatest(old_writing_days, least(new.writing_day_count, old_writing_days + 60));
  -- fireside_post_count: a generous burst allowance for a very active catch-up sync.
  new.fireside_post_count := greatest(old_fireside, least(new.fireside_post_count, old_fireside + 500));

  return new;
end;
$$;

drop trigger if exists guild_member_stats_guard_delta on guild_member_stats;
create trigger guild_member_stats_guard_delta
  before insert or update on guild_member_stats
  for each row execute function guard_guild_member_stats_delta();

-- ============================================================================================
-- guild_published_books — the Guild Bookshelf's shared shelf: every book currently published to
-- a guild, from every member who's pushed one. Deliberately its own table rather than widening
-- published_books — that table is intentionally fully public (backs the open Grand Library),
-- and a Guild Bookshelf book is meant to stay guild-only. Originally Founder Guilds only, same
-- membership check as fireside_posts/guild_book_feedback above — extended to self-founded/joined
-- Player Guilds too by 92_migration_player_guild_book_publishing.sql (see the sibling policies
-- below each Founder Guild one, and near the end of this file for published_books/
-- published_book_content/published_book_samples' own matching read policies). Fireside itself
-- stays Founder-Guild-only; a Player Guild's Notice Board reads directly off it, unaffected by
-- and unrelated to this table.
-- ============================================================================================

create table if not exists guild_published_books (
  id uuid primary key default gen_random_uuid(),
  guild_id text not null,
  book_id text not null, -- matches the app's own local project id, same as published_books.id
  author_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) <= 200),
  subtitle text check (subtitle is null or char_length(subtitle) <= 200),
  series_name text check (series_name is null or char_length(series_name) <= 200),
  cover jsonb, -- the structured cover object (style/accent/motif/customImageUrl), not a URL
  genre text,
  blurb text check (blurb is null or char_length(blurb) <= 2000),
  tags jsonb,
  word_count integer default 0,
  story_format text default 'book',
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (guild_id, book_id)
);

alter table guild_published_books enable row level security;

create policy "guild members read guild published books" on guild_published_books
  for select using (
    exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
-- Player Guild sibling of the policy above (92_migration_player_guild_book_publishing.sql) — a
-- self-founded or joined Player Guild's own guild_published_books rows, keyed by the real
-- player_guilds.id (cast to text, since this table's own guild_id column is text so it can hold
-- either a Founder Guild's fixed slug or a Player Guild's real uuid without a second column).
-- ORed with the Founder Guild policy above, not a replacement for it — a request passes if
-- either matches.
create policy "player guild members read guild published books" on guild_published_books
  for select using (
    exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
-- Moderator bypass, same reasoning as fireside_posts' sibling policy above.
create policy "moderators read all guild published books" on guild_published_books
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "guild members publish own book to guild" on guild_published_books
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and word_count >= min_publish_word_count()
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
create policy "player guild members publish own book to guild" on guild_published_books
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and word_count >= min_publish_word_count()
    and exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
-- Update re-checks current membership, same reasoning as guild_book_feedback above. Delete stays
-- plain author-only — leaving a guild already has its own path to remove a listing
-- (unpublishBookFromGuildRemote in library-guild.js, scoped to book_id + author_id, no guild_id
-- needed), so this doesn't need the same gate.
create policy "guild members update own guild listing" on guild_published_books
  for update using (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  )
  with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and word_count >= min_publish_word_count()
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
create policy "player guild members update own guild listing" on guild_published_books
  for update using (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  )
  with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and word_count >= min_publish_word_count()
    and exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_published_books.guild_id and m.user_id = auth.uid()
    )
  );
create policy "author deletes own guild listing" on guild_published_books
  for delete using (auth.uid() = author_id);

create index if not exists guild_published_books_guild_idx on guild_published_books (guild_id, updated_at desc);

-- ============================================================================================
-- content_reports — lets a signed-in user flag published content (a book, a Fireside post, ...)
-- for review. This is what the DMCA/copyright-infringement process and prohibited-conduct
-- sections of the Terms of Service actually run on — before this table existed, there was no way
-- for anyone to flag anything, which meant those policy sections had no mechanism behind them.
--
-- Reviewed through the in-app moderation queue (src/moderation/moderation-queue.jsx) by any
-- account with profiles.is_moderator set — see that column's comment for how that's granted. A
-- regular (non-moderator) user can file a report and see their own filed-report history, and
-- nothing more; report contents (who reported what) are deliberately not visible to other
-- regular users, including the person being reported on.
-- ============================================================================================

create table if not exists content_reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete cascade,
  -- Matches the set of tables that hold user-published/shared content: a Grand Library or Guild
  -- book listing, a Fireside post, guild book feedback, or a review — plus 'account', for
  -- flagging a suspicious account itself (impersonation, a scam-y name/avatar) even when it
  -- hasn't posted anything yet to report individually. Only meaningful for a real account (see
  -- library/author-identity.jsx's PublicIdentityCard, which only renders this option when a real
  -- authorId is known — never for the local-only Grand Library's name-only "authors").
  content_type text not null check (content_type in (
    'published_book', 'guild_published_book', 'fireside_post', 'guild_book_feedback', 'review', 'account'
  )),
  -- text, not uuid — matches every OTHER content_type's id column type (published_books.id etc.
  -- are all text). For 'account', this holds the reported user's uuid cast to text.
  content_id text not null,
  -- Populated for guild-scoped content (fireside_post, guild_book_feedback,
  -- guild_published_book); null for a plain Grand Library published_book or an 'account' report.
  guild_id text,
  -- Kept in sync with lib/reports.js's REPORT_REASONS — see that file's comment for why
  -- 'impersonation' and 'scam' exist as their own reasons rather than falling under 'other'.
  reason text not null check (reason in ('impersonation', 'scam', 'copyright', 'harassment', 'spam', 'illegal', 'other')),
  -- Matches the 1000-char cap reports.js already applies client-side (details.trim().slice(0,
  -- 1000)) — that alone was cosmetic, since anyone calling the API directly bypasses client code
  -- entirely. This is what actually enforces it.
  details text check (details is null or char_length(details) <= 1000),
  status text not null default 'open' check (status in ('open', 'reviewed', 'dismissed', 'actioned')),
  -- Who actioned this report and when, for accountability — auto-populated by
  -- stamp_report_resolution below whenever status changes, never set directly by a client (see
  -- that trigger's comment). Both stay null while status is still 'open'.
  resolved_by uuid references auth.users(id) on delete set null,
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);

alter table content_reports enable row level security;

create policy "a user files their own report" on content_reports
  for insert with check (auth.uid() = reporter_id and not is_banned(auth.uid()));
create policy "a user reads their own filed reports" on content_reports
  for select using (auth.uid() = reporter_id);

-- In-app moderation queue (src/moderation/moderation-queue.jsx), gated on profiles.is_moderator
-- (see that column's comment below — same manually-granted, not-self-service model as
-- `verified`). A moderator can read and update the status of EVERY report, not just their own.
create policy "moderators read all reports" on content_reports
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "moderators update report status" on content_reports
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );

-- The update policy above is row-scoped, not column-scoped (same limitation as
-- protect_admin_profile_columns faces on profiles) — without this trigger, a moderator's update could
-- also silently rewrite reason/details/content_id/reporter_id, which would make the report
-- history untrustworthy. This locks every column except `status` to its existing value for any
-- non-service_role update, and auto-stamps resolved_by/resolved_at from the actual acting
-- moderator's own auth.uid() rather than trusting whatever the client sends for those two
-- columns — so "who actioned this" can't be misattributed, deliberately or by a stale client.
create or replace function stamp_report_resolution()
returns trigger as $$
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    new.reporter_id := old.reporter_id;
    new.content_type := old.content_type;
    new.content_id := old.content_id;
    new.guild_id := old.guild_id;
    new.reason := old.reason;
    new.details := old.details;
    new.created_at := old.created_at;
    if new.status is distinct from old.status then
      new.resolved_by := auth.uid();
      new.resolved_at := now();
    else
      new.resolved_by := old.resolved_by;
      new.resolved_at := old.resolved_at;
    end if;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists stamp_report_resolution_trigger on content_reports;
create trigger stamp_report_resolution_trigger
  before update on content_reports
  for each row execute function stamp_report_resolution();

-- Supports the moderation queue's default open-reports view, and a per-content lookup (e.g.
-- "how many open reports does this book have").
create index if not exists content_reports_status_idx on content_reports (status, created_at desc);
create index if not exists content_reports_content_idx on content_reports (content_type, content_id);

-- Closes item 5 of the audit: nothing stopped a user from filing unlimited duplicate reports
-- against the same content, or flooding the queue with reports across many different pieces of
-- content in a burst. Two layers, same "unconditional guarantee + friendly front door" pairing
-- used elsewhere in this schema (see player_guilds_owner_id_key / create_or_get_own_guild):
--
--   1. A partial unique index, scoped to `status = 'open'` rather than every row forever — a
--      reporter can't have two open reports for the same content_type/content_id/reporter_id at
--      once, but can file again later if an earlier report was resolved/dismissed and the
--      problem recurs. This is the unconditional guarantee.
--   2. enforce_content_report_rate_limit() below, checked before the index would ever be hit:
--      raises a clear, catchable duplicate message instead of a raw unique-violation, and
--      separately caps how many reports (on anything) one reporter can file per rolling hour —
--      the index alone doesn't stop a burst of reports against many DIFFERENT pieces of content.
--      10/hour is a deliberately generous ceiling for a real user moderating in good faith; only
--      meaningful against someone filing far more than that.
create unique index if not exists content_reports_no_duplicate_open_idx
  on content_reports (reporter_id, content_type, content_id)
  where status = 'open';

create or replace function enforce_content_report_rate_limit()
returns trigger as $$
declare
  v_recent_count integer;
begin
  if exists (
    select 1 from content_reports
    where reporter_id = new.reporter_id
      and content_type = new.content_type
      and content_id = new.content_id
      and status = 'open'
  ) then
    raise exception 'You already have an open report filed for this — no need to file it again.';
  end if;

  select count(*) into v_recent_count
  from content_reports
  where reporter_id = new.reporter_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 10 then
    raise exception 'You''ve filed several reports in the last hour — please wait a bit before filing another.';
  end if;

  return new;
end;
$$ language plpgsql;

drop trigger if exists content_reports_rate_limit_trigger on content_reports;
create trigger content_reports_rate_limit_trigger
  before insert on content_reports
  for each row execute function enforce_content_report_rate_limit();

-- ============================================================================================
-- Storage — avatars, guild crests, book covers, and in-manuscript images (character portraits,
-- location photos, map backgrounds), replacing the base64 data URLs these used to be stored as
-- directly in profiles.avatar_url / player_guilds.crest_url / guild_published_books.cover / a
-- project's own kv_store JSON.
--
-- Object path convention: <folder>/<user_id>/<filename>, e.g.
-- avatars/3fa85f64-.../1719345678-ab12cd.jpg.
--
-- Two buckets, split by whether the folder is meant to be public:
--   'media'          — avatars | guild-crests | book-covers. Meant to be public, matching the
--                       (public) columns they replace, so this bucket is created with
--                       `public = true` and gets a public-read policy.
--   'media-private'  — project-images only. These belong to a project's own kv_store row, which
--                       is private by default (see kv_store's RLS above), so this bucket is
--                       created with `public = false`. A public bucket in Supabase Storage
--                       serves every object in it through an unauthenticated public route
--                       regardless of any RLS policy on storage.objects — that route exists
--                       specifically to bypass authorization — so putting private content in
--                       the *same* public bucket as the others, gated only by a folder-scoped
--                       RLS select policy, would never actually make it private: RLS on
--                       storage.objects doesn't apply to a public bucket's public route at all.
--                       A genuinely non-public bucket is the only way to make owner-only RLS
--                       meaningful here. The app reads this bucket back via a signed URL (see
--                       mediaStorage.js) rather than a public one.
--
-- Size/type caps: an anon key + a valid session is all that's needed to call storage.upload()
-- directly, bypassing the app's own client-side compression, so a server-side cap matters. 5MB
-- is a generous multiple of the client's own ~1.2MB ceiling; mime types are capped to exactly
-- what the client's own image pipeline can ever produce (see mediaStorage.js).
-- ============================================================================================

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('media', 'media', true, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do nothing;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('media-private', 'media-private', false, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do nothing;

-- 'media' only ever holds avatars/guild-crests/book-covers (project-images lives in
-- 'media-private' instead). Read is a blanket "anyone can read" restricted to those three
-- folders.
--
-- The allowed-folder list itself lives in exactly one place — is_public_media_folder() below —
-- rather than being repeated as a literal array in each of the four policies that follow. This
-- list is security-relevant, not just a convenience: 'media' is a public bucket (see the header
-- above), so any folder it allows becomes world-readable through Storage's public route
-- regardless of RLS. Four hand-copied literals are four chances for one of them to drift from
-- the others — e.g. a future public folder added to the insert policy but missed on select
-- (silently breaks uploads of that folder) or missed on delete (silently leaves orphaned objects
-- undeletable) — exactly the kind of drift that a single function call everywhere else in this
-- file avoids by construction. Marked immutable: the set is a fixed, compile-time list, not
-- something that varies per row.
create or replace function is_public_media_folder(folder text)
returns boolean
language sql
immutable
as $$
  select folder in ('avatars', 'guild-crests', 'book-covers');
$$;

create policy "anyone can read public media" on storage.objects
  for select using (
    bucket_id = 'media' and is_public_media_folder((storage.foldername(name))[1])
  );

-- storage.foldername(name) splits an object path into its folder segments (excluding the
-- filename). For '<folder>/<user_id>/<filename>' that's index 2 — index 1 is <folder> itself.
-- Restricted to the three public folders so a client can't write into 'media' under a
-- 'project-images/' path and land in the wrong (public) bucket for that content.
create policy "a writer uploads their own media" on storage.objects
  for insert with check (
    bucket_id = 'media'
    and is_public_media_folder((storage.foldername(name))[1])
    and auth.uid()::text = (storage.foldername(name))[2]
  );

create policy "a writer updates their own media" on storage.objects
  for update using (
    bucket_id = 'media'
    and is_public_media_folder((storage.foldername(name))[1])
    and auth.uid()::text = (storage.foldername(name))[2]
  );

create policy "a writer deletes their own media" on storage.objects
  for delete using (
    bucket_id = 'media'
    and is_public_media_folder((storage.foldername(name))[1])
    and auth.uid()::text = (storage.foldername(name))[2]
  );

-- 'media-private' holds only 'project-images/<user_id>/<filename>'. Unlike 'media', this bucket
-- has `public = false`, so these RLS policies are the *only* way to read/write an object here —
-- there is no public route to bypass them.
create policy "a writer reads their own private media" on storage.objects
  for select using (
    bucket_id = 'media-private' and auth.uid()::text = (storage.foldername(name))[2]
  );

create policy "a writer uploads their own private media" on storage.objects
  for insert with check (
    bucket_id = 'media-private' and auth.uid()::text = (storage.foldername(name))[2]
  );

create policy "a writer updates their own private media" on storage.objects
  for update using (
    bucket_id = 'media-private' and auth.uid()::text = (storage.foldername(name))[2]
  );

create policy "a writer deletes their own private media" on storage.objects
  for delete using (
    bucket_id = 'media-private' and auth.uid()::text = (storage.foldername(name))[2]
  );

-- ============================================================================================
-- Account deletion — 30-day grace period, then a non-destructive purge.
--
-- "Delete my account" does NOT delete the auth.users row. Every content table below references
-- auth.users(id) on delete cascade (kv_store, published_books, reviews, fireside_posts,
-- guild_book_feedback, guild_published_books, ...) — actually deleting that row would cascade
-- through every single one of them instantly, ripping a departed member's replies out of guild
-- threads, their reviews out of other authors' rating summaries, their published books out of
-- guilds that promoted them, etc. mid-flight. That's the "breaks app structure" failure mode
-- this is built to avoid.
--
-- Instead: request → 30-day grace period (cancellable) → purge. Purge blocks the account from
-- ever signing in again and permanently removes what's exclusively theirs (private manuscripts,
-- guild memberships, follows), but *anonymizes* rather than deletes anything another user's view
-- depends on — it blanks their public profile and leaves every row they authored in place,
-- attributed to nobody. This isn't a gap in the UI: every place that reads an author's name
-- already falls back to a generic label when the profile is empty (reviewer_name || 'A reader'
-- in grand-library-cards.jsx, f.author ? ... : 'A guildmate' in guild-book-feedback-modal.jsx,
-- etc. — see the "no author_name here, looked up live" comment on publishBookRemote above) so
-- this displays correctly with zero other code changes.
-- ============================================================================================

create table if not exists account_deletions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  requested_at timestamptz not null default now(),
  scheduled_purge_at timestamptz not null,
  status text not null default 'pending' check (status in ('pending', 'cancelled', 'completed')),
  updated_at timestamptz not null default now()
);

alter table account_deletions enable row level security;

create policy "a user manages their own deletion request" on account_deletions
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- SECURITY DEFINER: this needs to touch auth.users and other users' rows aren't otherwise
-- writable by a regular signed-in caller, which is exactly why this can't just be an RLS-scoped
-- client call — it's meant to run only via the pg_cron schedule below, as the table owner, not on
-- demand from the client.
create or replace function purge_expired_account_deletions()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  for rec in
    select user_id from account_deletions
    where status = 'pending' and scheduled_purge_at <= now()
  loop
    -- Blank the public-facing profile rather than deleting the row. See the block comment above
    -- for why every reader of this data already handles an empty name gracefully.
    update profiles
    set pen_name = null, display_name = null, avatar_url = null, updated_at = now()
    where id = rec.user_id;

    -- Delete what's exclusively this person's own and doesn't leave a hole in anyone else's
    -- experience: their private manuscripts, their guild memberships (so they stop appearing in
    -- member lists — a guild's aggregate stats settling lower afterward is expected, not a
    -- "hole," the same as any member leaving normally), and their follow relationships.
    delete from kv_store where user_id = rec.user_id;
    delete from founder_guild_members where user_id = rec.user_id;
    delete from player_guild_members where user_id = rec.user_id;
    delete from follows where follower_id = rec.user_id or followee_id = rec.user_id;

    -- Deletes every object this person ever uploaded, across both buckets — avatars,
    -- guild-crests, book-covers ('media') and project-images ('media-private'). Every object in
    -- both buckets is stored at '<folder>/<user_id>/<filename>' (see is_public_media_folder's
    -- comment above), so (storage.foldername(name))[2] is the owner's user id regardless of
    -- which folder or bucket it's in — one condition covers all of it.
    delete from storage.objects
    where bucket_id in ('media', 'media-private')
      and (storage.foldername(name))[2] = rec.user_id::text;

    -- Block sign-in permanently. banned_until is the same field Supabase Auth's own Admin API
    -- (auth.admin.updateUserById with ban_duration) writes — setting it directly here avoids
    -- needing a separate service-role backend just for this one scheduled step.
    --
    -- Important limitation, straight from Supabase's own docs (Managing User Data): deleting a
    -- session does NOT retroactively invalidate an access token (JWT) that's already been
    -- issued — that token keeps working for the rest of its own lifetime regardless. What this
    -- DOES do: blocks all future sign-ins (banned_until) and blocks that session from being
    -- refreshed into a new token once the current one expires. The residual risk — a
    -- still-valid access token issued shortly before purge, usable for up to your project's JWT
    -- expiry window (Auth settings, default 1 hour) — is low here specifically because purge
    -- already deleted this person's private data and guild memberships in the statements above,
    -- so there's very little left for a lingering token to do. If you need the harder guarantee
    -- of immediate revocation, Supabase's documented approach is to validate the session_id JWT
    -- claim against auth.sessions on sensitive operations, or to shorten the JWT expiry —
    -- neither of which this app currently does.
    update auth.users set banned_until = 'infinity' where id = rec.user_id;
    delete from auth.sessions where user_id = rec.user_id;
    delete from auth.refresh_tokens where user_id = rec.user_id::text;

    update account_deletions set status = 'completed', updated_at = now() where user_id = rec.user_id;
  end loop;
end;
$$;

-- Requires the pg_cron extension. On Supabase, enable it once via Database > Extensions in the
-- dashboard (or `create extension if not exists pg_cron;` if your project role has permission) —
-- then this schedule call takes effect. Runs daily at 03:00 UTC; re-running
-- purge_expired_account_deletions() is always safe since it only ever touches rows that are
-- still 'pending' and past their scheduled_purge_at.
select cron.schedule('purge-expired-account-deletions', '0 3 * * *', $$select purge_expired_account_deletions();$$);

-- ============================================================================================
-- device_signals — anti-impersonation piece 6 / ban-evasion signal. NOT a ban mechanism itself
-- and never blocks anything on its own — see shared-utils/device-signal.js's comment for the
-- full reasoning on why a real device-level ban isn't achievable for a web app, and why this is
-- deliberately built as a soft correlation signal for a moderator's judgment instead. Records
-- that a given (locally-generated, easily-cleared) device id has been used to sign in as a given
-- account. lib/moderation.js's fetchDeviceCorrelation uses this to answer "what OTHER accounts
-- have used any of the same device ids as this one" for a moderator reviewing a report — most
-- usefully, whether any of them are already banned.
-- ============================================================================================

create table if not exists device_signals (
  device_id text not null check (char_length(device_id) <= 100),
  user_id uuid not null references auth.users(id) on delete cascade,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  primary key (device_id, user_id)
);

-- Supports fetchDeviceCorrelation's "which other user_ids share any of this account's device
-- ids" lookup — that query starts from device_id, not the primary key's leading user_id column.
create index if not exists device_signals_device_id_idx on device_signals (device_id);

alter table device_signals enable row level security;

-- A user may record/update a signal for their OWN account only — this is what
-- shared-utils/device-signal.js's recordDeviceSignal writes on sign-in. No general select policy
-- for regular users: nobody (the account holder included) can read this table's contents through
-- the client — only see it exists, via the insert/update they themselves performed. That's
-- deliberate: this data's only purpose is moderator correlation, and it's more private held that
-- way (an account holder browsing their own "linked devices" list isn't a feature this needs).
create policy "a user records their own device signal" on device_signals
  for insert with check (auth.uid() = user_id and not is_banned(auth.uid()));
create policy "a user updates their own device signal" on device_signals
  for update using (auth.uid() = user_id);

-- Moderator-only read — the entire reason this table exists. See fetchDeviceCorrelation in
-- lib/moderation.js.
create policy "moderators read all device signals" on device_signals
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );

-- ============================================================================================
-- Naira payments (Paystack) — see supabase/history/32_migration_naira_payments.sql for the
-- full "why" behind this section; consolidated here unchanged for fresh installs.
-- ============================================================================================

create table if not exists bank_accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  bank_code text not null,
  bank_name text not null,
  account_number text not null check (account_number ~ '^[0-9]{10}$'),
  -- Returned by Paystack's account-resolve call, not typed by the user — this is what confirms
  -- the account number actually belongs to a real account before anything is saved.
  account_name text not null,
  paystack_recipient_code text not null unique,
  is_default boolean not null default true,
  created_at timestamptz not null default now(),
  unique (user_id, bank_code, account_number)
);

alter table bank_accounts enable row level security;

create policy "a user reads their own saved bank accounts" on bank_accounts
  for select using (auth.uid() = user_id);
-- Insert/update/delete happen through the Edge Functions using the service role (so the
-- Paystack recipient_code is always created/retired in lockstep with the row) — no direct client
-- insert/update policy. Delete is safe to allow directly since it's just removing a saved
-- convenience, not something that needs Paystack coordination first.
create policy "a user deletes their own saved bank account" on bank_accounts
  for delete using (auth.uid() = user_id);

-- Only one default per user — the app always has exactly one "the" saved account to withdraw to
-- unless the user is mid-way through adding a second.
create unique index if not exists bank_accounts_one_default_per_user
  on bank_accounts (user_id) where is_default;

create or replace function set_default_bank_account(target_account_id uuid)
returns void as $$
begin
  if not exists (select 1 from bank_accounts where id = target_account_id and user_id = auth.uid()) then
    raise exception 'Not your saved bank account';
  end if;
  update bank_accounts set is_default = false where user_id = auth.uid();
  update bank_accounts set is_default = true where id = target_account_id;
end;
$$ language plpgsql security definer set search_path = public;

revoke all on function set_default_bank_account(uuid) from public;
grant execute on function set_default_bank_account(uuid) to authenticated;

-- ============================================================================================
-- purchases — a completed (or pending/failed) Naira payment from a reader: either a book
-- purchase or a tip to an author. One row per Paystack transaction attempt. amount_kobo is the
-- full amount the reader paid; author_amount_kobo is what the author is credited after
-- Inkroot's platform fee (see PLATFORM_FEE_BPS in the paystack-webhook function) — kept as its
-- own column rather than computed at read time so a later change to the fee percentage never
-- reclassifies a past sale's payout.
-- ============================================================================================

create table if not exists purchases (
  id uuid primary key default gen_random_uuid(),
  paystack_reference text not null unique,
  buyer_id uuid not null references auth.users(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check (kind in ('book', 'tip')),
  book_id text references published_books(id) on delete set null,
  amount_kobo bigint not null check (amount_kobo > 0),
  author_amount_kobo bigint not null check (author_amount_kobo >= 0),
  status text not null default 'pending' check (status in ('pending', 'success', 'failed')),
  created_at timestamptz not null default now(),
  paid_at timestamptz
);

alter table purchases enable row level security;

create policy "buyer reads their own purchases" on purchases
  for select using (auth.uid() = buyer_id);
create policy "author reads sales of their own work" on purchases
  for select using (auth.uid() = author_id);
-- No client insert/update policy at all: a purchase row is only ever created (pending) by
-- paystack-init-purchase and only ever confirmed (success/failed) by paystack-webhook, both
-- running as service_role — a client claiming its own payment "succeeded" is worth exactly
-- nothing without Paystack itself having said so server-side.

create index if not exists purchases_author_id_status_idx on purchases (author_id, status);

-- ============================================================================================
-- withdrawals — an author cashing out to a saved bank account. Mirrors purchases: one row per
-- payout attempt, created pending by either paystack-withdraw (method='paystack', moved to
-- success/failed by paystack-webhook) or manual-withdraw (method='manual', settled by hand via
-- admin_settle_manual_withdrawal — see 62_migration_manual_withdrawals.sql for why a second method
-- exists at all: Paystack Transfers need a business-verified account, which requires a TIN).
-- ============================================================================================

create table if not exists withdrawals (
  id uuid primary key default gen_random_uuid(),
  paystack_transfer_code text unique,
  user_id uuid not null references auth.users(id) on delete cascade,
  bank_account_id uuid not null references bank_accounts(id) on delete restrict,
  amount_kobo bigint not null check (amount_kobo > 0),
  status text not null default 'pending' check (status in ('pending', 'success', 'failed')),
  failure_reason text,
  method text not null default 'paystack' check (method in ('paystack', 'manual')),
  -- A platform admin's note when settling a manual request by hand — a reference on success, a
  -- reason on failure (also mirrored into failure_reason on failure, so every existing failure
  -- display works unchanged regardless of method).
  admin_note text check (admin_note is null or char_length(admin_note) <= 500),
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

alter table withdrawals enable row level security;

create policy "a user reads their own withdrawals" on withdrawals
  for select using (auth.uid() = user_id);
-- Same reasoning as purchases: created/updated only by the paystack-withdraw and
-- paystack-webhook Edge Functions (service_role) — never directly by a client, since a
-- withdrawal must be checked against the author's actual available balance server-side first.

create index if not exists withdrawals_user_id_idx on withdrawals (user_id);

-- ============================================================================================
-- guild_treasury_transactions — a Player Guild's real money ledger (see
-- 33_migration_guild_treasury.sql for the full rationale). Append-only, one row per financial
-- event; every balance below is a query over this table, never a stored/incrementable column.
-- Scoped to Player Guilds only — same reasoning as guild_member_stats: a Founder Guild's roster
-- is still simulated, so there's no real membership to check a treasury against yet.
-- ============================================================================================

create table if not exists guild_treasury_transactions (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  -- 'guild' = the guild's own collective purse. 'member' = a specific member's earnings, held
  -- here in trust — credited by an Anthology sale's per-contributor share
  -- (distribute_guild_revenue, see the Guild Revenue Distribution migration) and released back
  -- out to that member's own withdrawable balance by withdraw_guild_member_earnings (see the
  -- Guild Member Earnings migration).
  bucket text not null check (bucket in ('guild', 'member')),
  member_id uuid references auth.users(id) on delete set null,
  direction text not null check (direction in ('credit', 'debit')),
  -- Every kind here is real and live: contribution/spend/release_to_member (see the Guild
  -- Member Earnings migration) plus anthology_share and event_revenue, the two "verified sale"
  -- revenue kinds distribute_guild_revenue() writes (see the Guild Revenue Distribution and
  -- Guild Events migrations).
  kind text not null check (kind in ('contribution', 'spend', 'anthology_share', 'event_revenue', 'release_to_member')),
  amount_kobo bigint not null check (amount_kobo > 0),
  -- Only NGN moves through Inkroot today (see the payments table below) — amount_kobo is already
  -- NGN's minor unit; this just says so explicitly rather than leaving it implicit.
  currency text not null default 'NGN' check (currency = 'NGN'),
  -- Explicit, fixed-vocabulary record of where the money came from / is going, set by the RPCs
  -- below (never accepted as a client argument) — same "never trust a classification the client
  -- could lie about" stance as everything else these functions check server-side. Every kind
  -- above has its own source/destination pair defined here.
  source text not null check (source in ('member_balance', 'guild_treasury', 'anthology_sale', 'event_sale', 'member_earnings_held')),
  destination text not null check (destination in ('guild_treasury', 'member_balance', 'member_earnings_held', 'external')),
  -- The Guild Event this transaction belongs to, if any (null for a plain contribution/spend or
  -- an Anthology sale, which uses anthology_id below instead). Foreign-keyed to guild_events via
  -- a constraint added further down this file, after that table exists — see the Guild Events
  -- migration for why it can't be declared inline here (guild_events doesn't exist yet at this
  -- point in a fresh install).
  project_event_id uuid,
  status text not null default 'success' check (status in ('pending', 'success', 'failed')),
  title text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  settled_at timestamptz,
  -- A caller-supplied token identifying one logical request, not a row id. Nullable — a call
  -- made without one gets no replay protection — so idempotency is opt-in per call, not forced.
  idempotency_key text,
  check ((bucket = 'member') = (member_id is not null))
);

alter table guild_treasury_transactions enable row level security;

create policy "guild members read guild-owned treasury transactions" on guild_treasury_transactions
  for select using (
    bucket = 'guild'
    and is_guild_member(guild_treasury_transactions.guild_id)
  );
create policy "a member reads their own member-earnings treasury rows" on guild_treasury_transactions
  for select using (bucket = 'member' and member_id = auth.uid());
-- No insert/update/delete policy for any client role: every write goes through
-- contribute_to_guild_treasury()/spend_from_guild_treasury() below, which re-check membership,
-- ownership, and the real balance server-side first. A client cannot move a kobo by writing to
-- this table directly.

create index if not exists guild_treasury_transactions_guild_id_idx
  on guild_treasury_transactions (guild_id, created_at desc);
create index if not exists guild_treasury_transactions_member_id_idx
  on guild_treasury_transactions (member_id) where member_id is not null;
-- Partial (not plain) unique: Postgres already treats every NULL as distinct from every other
-- NULL in a unique index, so this exists to keep the index itself scoped to only the rows that
-- actually carry a key, not to specially permit multiple nulls (that's already the default).
create unique index if not exists guild_treasury_transactions_idempotency_key_idx
  on guild_treasury_transactions (idempotency_key) where idempotency_key is not null;
create index if not exists guild_treasury_transactions_project_event_idx
  on guild_treasury_transactions (project_event_id) where project_event_id is not null;

-- ---------- Immutability ----------
-- "Permanent ledger" enforced for real: fires for every role unconditionally, including
-- service_role and the table owner — RLS (above) governs whether a statement is allowed to run
-- at all for a given role, but doesn't restrict service_role; this trigger governs what happens
-- once a statement runs, full stop. Insert is untouched, only update/delete are blocked. This
-- does mean settled_at's pending -> success/failed transition can't happen by updating a pending
-- row in place — a future async-settlement source needs its own append-only completion event
-- instead of rewriting the original row.
create or replace function forbid_guild_treasury_transactions_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'guild_treasury_transactions is a permanent, append-only ledger -- rows can never be updated or deleted. Insert a new row to record a correction or reversal instead.';
end;
$$;

drop trigger if exists guild_treasury_transactions_immutable on guild_treasury_transactions;
create trigger guild_treasury_transactions_immutable
  before update or delete on guild_treasury_transactions
  for each row execute function forbid_guild_treasury_transactions_mutation();

-- Guild-owned funds: everything the guild has ever earned into its own bucket (lifetime settled
-- credits) — the guild's total treasury income, not what's left to spend.
create or replace function guild_treasury_owned_kobo(p_guild_id uuid)
returns bigint as $$
  select coalesce(sum(amount_kobo), 0) from guild_treasury_transactions
  where guild_id = p_guild_id and bucket = 'guild' and direction = 'credit' and status = 'success';
$$ language sql stable security definer set search_path = public;

-- Available funds: guild-owned funds minus every guild-bucket debit already spent or in flight —
-- what the guild can actually authorize a new spend against right now.
create or replace function guild_treasury_available_kobo(p_guild_id uuid)
returns bigint as $$
  select
    guild_treasury_owned_kobo(p_guild_id)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where guild_id = p_guild_id and bucket = 'guild' and direction = 'debit'
                and status in ('pending', 'success')), 0);
$$ language sql stable security definer set search_path = public;

-- Pending funds: anything, in either bucket, still waiting on settlement for this guild.
create or replace function guild_treasury_pending_kobo(p_guild_id uuid)
returns bigint as $$
  select coalesce(sum(amount_kobo), 0) from guild_treasury_transactions
  where guild_id = p_guild_id and status = 'pending';
$$ language sql stable security definer set search_path = public;

-- Member earnings: total currently held in this guild's treasury on behalf of members
-- collectively — money that passed through the guild but belongs to individual writers, not the
-- guild itself.
create or replace function guild_treasury_member_earnings_kobo(p_guild_id uuid)
returns bigint as $$
  select
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where guild_id = p_guild_id and bucket = 'member' and direction = 'credit' and status = 'success'), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where guild_id = p_guild_id and bucket = 'member' and direction = 'debit'
                and status in ('pending', 'success')), 0);
$$ language sql stable security definer set search_path = public;

-- One round trip for everything a Treasury tab needs, including the caller's own held earnings
-- within this guild specifically (member_earnings_mine_kobo) alongside the guild-wide total.
create or replace function guild_treasury_summary(p_guild_id uuid)
returns table (
  guild_owned_kobo bigint,
  available_kobo bigint,
  pending_kobo bigint,
  member_earnings_kobo bigint,
  member_earnings_mine_kobo bigint
)
language plpgsql security definer set search_path = public as $$
begin
  if not is_guild_member(p_guild_id) then
    raise exception 'Not a member of this guild.';
  end if;
  return query select
    guild_treasury_owned_kobo(p_guild_id),
    guild_treasury_available_kobo(p_guild_id),
    guild_treasury_pending_kobo(p_guild_id),
    guild_treasury_member_earnings_kobo(p_guild_id),
    (
      coalesce((select sum(amount_kobo) from guild_treasury_transactions
                where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid()
                  and direction = 'credit' and status = 'success'), 0)
      -
      coalesce((select sum(amount_kobo) from guild_treasury_transactions
                where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid()
                  and direction = 'debit' and status in ('pending', 'success')), 0)
    );
end;
$$;

revoke all on function guild_treasury_owned_kobo(uuid) from public;
revoke all on function guild_treasury_available_kobo(uuid) from public;
revoke all on function guild_treasury_pending_kobo(uuid) from public;
revoke all on function guild_treasury_member_earnings_kobo(uuid) from public;
revoke all on function guild_treasury_summary(uuid) from public;
grant execute on function guild_treasury_owned_kobo(uuid) to authenticated;
grant execute on function guild_treasury_available_kobo(uuid) to authenticated;
grant execute on function guild_treasury_pending_kobo(uuid) to authenticated;
grant execute on function guild_treasury_member_earnings_kobo(uuid) to authenticated;
grant execute on function guild_treasury_summary(uuid) to authenticated;

-- ============================================================================================
-- author_balance_kobo — an author's current withdrawable balance in kobo: total received from
-- successful sales/tips, minus withdrawals already paid out or in flight, minus their own
-- successful/pending contributions into any guild treasury (see contribute_to_guild_treasury
-- below — without this subtraction the same kobo would count toward both balances at once). A
-- function rather than a stored column on purpose (same reasoning as this codebase's other
-- derived-not-duplicated state, e.g. guild_member_stats' comments) — there is no separate ledger
-- balance that can ever drift from the purchases/withdrawals/guild_treasury_transactions rows
-- themselves.
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(author_amount_kobo) from purchases
              where author_id = check_user_id and status = 'success'), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0);
$$ language sql stable security definer set search_path = public;

-- security definer so a caller can check their own balance without needing broad read access to
-- other authors' purchases/withdrawals rows — grant execute, not table access.
revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- ============================================================================================
-- Writes — the only two ways a kobo moves in or out of a guild treasury today. Both start by
-- re-deriving every fact they act on (membership, ownership, current balance) from the database
-- itself, never trusting an argument the client could lie about beyond the amount requested.
-- ============================================================================================

-- Both functions below take an optional p_idempotency_key: if supplied, a row with that key is
-- looked up FIRST, before any lock or balance check — the common case (a plain retry of an
-- already-completed request) costs one cheap read and never risks a second, possibly-different
-- balance check. The insert itself also carries `on conflict (idempotency_key) ... do nothing`
-- as a second layer, for the rare case where two calls carrying the same key genuinely race each
-- other and both pass the first check before either has inserted — exactly one wins the insert;
-- the other's `if not found` branch reads back the winner's row instead of erroring, so both
-- callers see the same successful result either way. A call made without a key gets no replay
-- protection, same as before this existed.

-- A member moves part of their own real, already-earned balance into their guild's purse.
create or replace function contribute_to_guild_treasury(
  p_guild_id uuid, p_amount_kobo bigint, p_note text default null,
  p_idempotency_key text default null, p_project_event_id uuid default null
)
returns guild_treasury_transactions
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_treasury_transactions;
begin
  if p_idempotency_key is not null then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
    if found then
      return v_row;
    end if;
  end if;

  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not is_guild_member(p_guild_id) then
    raise exception 'Not a member of this guild.';
  end if;
  -- Serializes concurrent contributions from the same writer so two simultaneous requests can't
  -- both read the same starting balance and together overdraw it.
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text));
  if author_balance_kobo(auth.uid()) < p_amount_kobo then
    raise exception 'That would exceed your available balance.';
  end if;

  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     project_event_id, status, title, created_by, idempotency_key)
  values
    (p_guild_id, 'guild', null, 'credit', 'contribution', p_amount_kobo, 'NGN', 'member_balance',
     'guild_treasury', p_project_event_id, 'success', p_note, auth.uid(), p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_row;

  if not found then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
  end if;
  return v_row;
end;
$$;

-- The guild owner authorizes a spend from the guild's own available funds. Scoped to
-- player_guilds.owner_id — the one real, server-known authority for a Player Guild today (see
-- 33_migration_guild_treasury.sql). GO_PERMISSIONS' richer Council/rung system (guild-order.jsx)
-- has no server-side counterpart yet, so it isn't checked here.
create or replace function spend_from_guild_treasury(
  p_guild_id uuid, p_amount_kobo bigint, p_title text,
  p_idempotency_key text default null, p_project_event_id uuid default null
)
returns guild_treasury_transactions
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_treasury_transactions;
begin
  if p_idempotency_key is not null then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
    if found then
      return v_row;
    end if;
  end if;

  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can authorize a treasury spend.';
  end if;
  perform pg_advisory_xact_lock(hashtext(p_guild_id::text));
  if guild_treasury_available_kobo(p_guild_id) < p_amount_kobo then
    raise exception 'That would exceed the guild''s available treasury balance.';
  end if;

  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     project_event_id, status, title, created_by, idempotency_key)
  values
    (p_guild_id, 'guild', null, 'debit', 'spend', p_amount_kobo, 'NGN', 'guild_treasury',
     'external', p_project_event_id, 'success', p_title, auth.uid(), p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_row;

  if not found then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
  end if;
  return v_row;
end;
$$;

revoke all on function contribute_to_guild_treasury(uuid, bigint, text, text, uuid) from public;
revoke all on function spend_from_guild_treasury(uuid, bigint, text, text, uuid) from public;
grant execute on function contribute_to_guild_treasury(uuid, bigint, text, text, uuid) to authenticated;
grant execute on function spend_from_guild_treasury(uuid, bigint, text, text, uuid) to authenticated;

-- ============================================================================================
-- guild_anthologies / guild_anthology_submissions — a Player Guild's collaborative book, made
-- of submissions from multiple members (see supabase/history/35_migration_guild_anthologies.sql
-- for the full rationale). Publishing one inserts exactly one published_books row — the same
-- table every solo book already publishes through — rather than a separate book system.
-- ============================================================================================

create table if not exists guild_anthologies (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  title text not null check (char_length(title) <= 200),
  description text check (description is null or char_length(description) <= 2000),
  cover jsonb,
  price numeric not null default 0 check (price >= 0),
  submission_deadline timestamptz,
  status text not null default 'open' check (status in ('open', 'reviewing', 'published', 'cancelled')),
  published_book_id text references published_books(id) on delete set null,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  published_at timestamptz,
  unique (published_book_id)
);

alter table guild_anthologies enable row level security;

create policy "guild members read guild anthologies" on guild_anthologies
  for select using (
    is_guild_member(guild_anthologies.guild_id)
  );

create policy "guild owner creates an anthology" on guild_anthologies
  for insert with check (
    auth.uid() = created_by
    and not is_banned(auth.uid())
    and is_guild_officer(guild_anthologies.guild_id)
  );

create policy "guild owner updates their anthology" on guild_anthologies
  for update using (
    is_guild_officer(guild_anthologies.guild_id)
  );

create index if not exists guild_anthologies_guild_idx on guild_anthologies (guild_id, created_at desc);

create or replace function guard_guild_anthology_mutation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(current_setting('inkroot.trusted_anthology_rpc', true), '') = 'true' then
    return new;
  end if;
  if old.status = 'published' then
    raise exception 'A published anthology''s listing lives on published_books now — edit it there.';
  end if;
  new.status := old.status;
  new.published_book_id := old.published_book_id;
  new.published_at := old.published_at;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists guild_anthology_guard on guild_anthologies;
create trigger guild_anthology_guard
  before update on guild_anthologies
  for each row execute function guard_guild_anthology_mutation();

create table if not exists guild_anthology_submissions (
  id uuid primary key default gen_random_uuid(),
  anthology_id uuid not null references guild_anthologies(id) on delete cascade,
  contributor_id uuid not null references auth.users(id) on delete cascade,
  project_id text not null,
  title text not null check (char_length(title) <= 200),
  blurb text check (blurb is null or char_length(blurb) <= 2000),
  word_count integer not null default 0 check (word_count >= 0),
  -- The contributor's actual manuscript — chapters only ({id,title,text}, same shape
  -- buildPublishedBookContent in ink-root.jsx sends for a solo book), sent from their own
  -- device at submit/edit time (see 91_migration_anthology_submission_content.sql). Nullable:
  -- a row created before that migration has none yet, which is exactly what
  -- publish_guild_anthology()'s own missing-content guard below checks for. Same 20MB cap and
  -- same reasoning as published_book_content's own check — one contributor's manuscript, not a
  -- second copy of the whole anthology.
  content jsonb,
  review_status text not null default 'pending' check (review_status in ('pending', 'approved', 'rejected', 'withdrawn')),
  review_note text check (review_note is null or char_length(review_note) <= 1000),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  submitted_at timestamptz not null default now(),
  check (content is null or octet_length(content::text) <= 20971520)
);

alter table guild_anthology_submissions enable row level security;

create unique index if not exists guild_anthology_submissions_active_idx
  on guild_anthology_submissions (anthology_id, contributor_id) where review_status <> 'withdrawn';

create index if not exists guild_anthology_submissions_anthology_idx
  on guild_anthology_submissions (anthology_id, review_status);

create policy "guild members read anthology submissions" on guild_anthology_submissions
  for select using (
    exists (
      select 1 from guild_anthologies a
      where a.id = guild_anthology_submissions.anthology_id
        and is_guild_member(a.guild_id)
    )
  );

create policy "guild members submit to an open anthology" on guild_anthology_submissions
  for insert with check (
    auth.uid() = contributor_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from guild_anthologies a
      where a.id = guild_anthology_submissions.anthology_id
        and is_guild_member(a.guild_id)
        and a.status = 'open'
        and (a.submission_deadline is null or now() <= a.submission_deadline)
    )
  );

create policy "contributor or guild owner update a submission" on guild_anthology_submissions
  for update using (
    auth.uid() = contributor_id
    or exists (
      select 1 from guild_anthologies a
      where a.id = guild_anthology_submissions.anthology_id and is_guild_officer(a.guild_id)
    )
  );

create or replace function guard_anthology_submission_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_is_owner boolean;
begin
  if coalesce(auth.role(), '') = 'service_role' then
    return new;
  end if;

  select exists (
    select 1 from guild_anthologies a
    where a.id = old.anthology_id and is_guild_officer(a.guild_id)
  ) into v_is_owner;

  if v_is_owner and auth.uid() <> old.contributor_id then
    new.title := old.title;
    new.blurb := old.blurb;
    new.project_id := old.project_id;
    new.word_count := old.word_count;
    new.content := old.content;
    new.contributor_id := old.contributor_id;
    new.submitted_at := old.submitted_at;
    if new.review_status is distinct from old.review_status then
      if new.review_status not in ('approved', 'rejected') then
        raise exception 'A guild owner may only approve or reject a submission.';
      end if;
      new.reviewed_by := auth.uid();
      new.reviewed_at := now();
    end if;
  elsif auth.uid() = old.contributor_id then
    if new.review_status is distinct from old.review_status and new.review_status <> 'withdrawn' then
      raise exception 'You may only withdraw your own submission.';
    end if;
    if old.review_status <> 'pending'
       and (new.title is distinct from old.title or new.blurb is distinct from old.blurb
            or new.project_id is distinct from old.project_id or new.word_count is distinct from old.word_count
            or new.content is distinct from old.content) then
      raise exception 'This submission has already been reviewed — withdraw and resubmit instead of editing it.';
    end if;
    new.review_note := old.review_note;
    new.reviewed_by := old.reviewed_by;
    new.reviewed_at := old.reviewed_at;
  else
    raise exception 'Not authorized to update this submission.';
  end if;
  return new;
end;
$$;

drop trigger if exists guild_anthology_submission_guard on guild_anthology_submissions;
create trigger guild_anthology_submission_guard
  before update on guild_anthology_submissions
  for each row execute function guard_anthology_submission_update();

create or replace function guild_anthology_contributors(p_anthology_id uuid)
returns table (contributor_id uuid, project_id text, title text, word_count integer, submitted_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not exists (
    select 1 from guild_anthologies a
    where a.id = p_anthology_id and is_guild_member(a.guild_id)
  ) then
    raise exception 'Not a member of this anthology''s guild.';
  end if;
  return query
    select s.contributor_id, s.project_id, s.title, s.word_count, s.submitted_at
    from guild_anthology_submissions s
    where s.anthology_id = p_anthology_id and s.review_status = 'approved'
    order by s.submitted_at asc;
end;
$$;

revoke all on function guild_anthology_contributors(uuid) from public;
grant execute on function guild_anthology_contributors(uuid) to authenticated;

create or replace function close_guild_anthology_submissions(p_anthology_id uuid)
returns guild_anthologies
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_anthologies%rowtype;
begin
  if not exists (
    select 1 from guild_anthologies a
    where a.id = p_anthology_id and is_guild_officer(a.guild_id)
  ) then
    raise exception 'Only the guild owner can close submissions.';
  end if;
  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies set status = 'reviewing'
    where id = p_anthology_id and status = 'open'
    returning * into v_row;
  if not found then
    raise exception 'This anthology is not currently open for submissions.';
  end if;
  return v_row;
end;
$$;

create or replace function reopen_guild_anthology_submissions(p_anthology_id uuid)
returns guild_anthologies
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_anthologies%rowtype;
begin
  if not exists (
    select 1 from guild_anthologies a
    where a.id = p_anthology_id and is_guild_officer(a.guild_id)
  ) then
    raise exception 'Only the guild owner can reopen submissions.';
  end if;
  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies set status = 'open'
    where id = p_anthology_id and status = 'reviewing'
    returning * into v_row;
  if not found then
    raise exception 'This anthology is not currently under review.';
  end if;
  return v_row;
end;
$$;

create or replace function cancel_guild_anthology(p_anthology_id uuid)
returns guild_anthologies
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_anthologies%rowtype;
begin
  if not exists (
    select 1 from guild_anthologies a
    where a.id = p_anthology_id and is_guild_officer(a.guild_id)
  ) then
    raise exception 'Only the guild owner can cancel this anthology.';
  end if;
  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies set status = 'cancelled'
    where id = p_anthology_id and status in ('open', 'reviewing')
    returning * into v_row;
  if not found then
    raise exception 'This anthology has already been published or cancelled.';
  end if;
  return v_row;
end;
$$;

create or replace function publish_guild_anthology(p_anthology_id uuid)
returns published_books
language plpgsql security definer set search_path = public as $$
declare
  v_anth guild_anthologies%rowtype;
  v_owner uuid;
  v_word_count integer;
  v_book_id text;
  v_book published_books%rowtype;
begin
  select * into v_anth from guild_anthologies where id = p_anthology_id for update;
  if not found then
    raise exception 'Anthology not found.';
  end if;

  if not is_guild_officer(v_anth.guild_id) then
    raise exception 'Only the guild owner can publish this anthology.';
  end if;
  if v_anth.status <> 'reviewing' then
    raise exception 'Close submissions and finish reviewing before publishing.';
  end if;
  if v_anth.published_book_id is not null then
    raise exception 'This anthology has already been published.';
  end if;

  select coalesce(sum(word_count), 0) into v_word_count
  from guild_anthology_submissions where anthology_id = p_anthology_id and review_status = 'approved';
  if v_word_count = 0 then
    raise exception 'At least one approved submission is required before publishing.';
  end if;

  v_book_id := 'anthology-' || p_anthology_id::text;

  insert into published_books (id, author_id, title, blurb, cover, price, word_count, destination)
  values (v_book_id, auth.uid(), v_anth.title, v_anth.description, v_anth.cover, v_anth.price, v_word_count, 'guild')
  returning * into v_book;

  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies
    set status = 'published', published_book_id = v_book_id, published_at = now()
    where id = p_anthology_id;

  return v_book;
end;
$$;

revoke all on function close_guild_anthology_submissions(uuid) from public;
revoke all on function reopen_guild_anthology_submissions(uuid) from public;
revoke all on function cancel_guild_anthology(uuid) from public;
revoke all on function publish_guild_anthology(uuid) from public;
grant execute on function close_guild_anthology_submissions(uuid) to authenticated;
grant execute on function reopen_guild_anthology_submissions(uuid) to authenticated;
grant execute on function cancel_guild_anthology(uuid) to authenticated;
grant execute on function publish_guild_anthology(uuid) to authenticated;
-- Migration 36: Guild Anthology Revenue Agreements — how an anthology's price actually gets
-- split among its contributors, made explicit, approved, and then frozen.
--
-- The core guarantee this migration is built around: nobody — not the guild owner proposing the
-- split, not Inkroot itself — has any code path that changes a contributor's share without that
-- contributor seeing it happen and re-approving. Two things make that true, not just documented:
--   1. guild_anthology_revenue_shares has NO update policy that lets anyone but the contributor
--      themself touch their own row, and guard_anthology_revenue_share_update() below lets that
--      one path change only approved_at — never share_bps, never whose row it is. There is no
--      escape hatch in that trigger for service_role, an admin flag, or anything else: the ONLY
--      way share_bps ever changes is a full re-propose (see next point), which is visible to
--      everyone, not a quiet edit.
--   2. Every re-propose (propose_anthology_revenue_agreement) deletes and fully regenerates every
--      contributor's share AND resets every approved_at to null, unconditionally — even if a
--      contributor's own number happened not to change. An agreement someone already approved can
--      never end up published with a different number under their name; the only way forward
--      after any edit is everyone approving again.
--
-- Reuses guild_anthologies (owner authority, status machine) and guild_anthology_submissions
-- (the approved contributor set + word counts) exactly as already built in migration 35 — no
-- second contributor list, no duplicated word-count tracking. publish_guild_anthology is
-- extended in place (same pattern author_balance_kobo was extended twice in the Treasury
-- migrations) to require a fully-approved agreement and to lock it at the moment revenue can
-- actually begin — the moment the anthology becomes a live published_books row.

-- ============================================================================================
-- guild_anthology_revenue_agreements — one per anthology. `revision` bumps on every re-propose;
-- that bump is what invalidates every existing approval, since approvals are just a timestamp on
-- the shares row from the LAST propose call — there's no revision number on the shares to compare
-- against because a re-propose always deletes and reinserts them from scratch (see the RPC below).
-- ============================================================================================

create table if not exists guild_anthology_revenue_agreements (
  id uuid primary key default gen_random_uuid(),
  anthology_id uuid not null unique references guild_anthologies(id) on delete cascade,
  split_type text not null check (split_type in ('equal', 'custom', 'contribution')),
  revision integer not null default 1,
  locked boolean not null default false,
  locked_at timestamptz,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table guild_anthology_revenue_agreements enable row level security;

create policy "guild members read revenue agreements" on guild_anthology_revenue_agreements
  for select using (
    exists (
      select 1 from guild_anthologies a
      where a.id = guild_anthology_revenue_agreements.anthology_id and is_guild_member(a.guild_id)
    )
  );

-- Deliberately no insert/update/delete policy — exactly guild_treasury_transactions' own stance
-- (see 33_migration_guild_treasury.sql). The only writers are propose_anthology_revenue_
-- agreement() and publish_guild_anthology() below, both security definer.

-- ============================================================================================
-- guild_anthology_revenue_shares — one row per contributor per agreement. share_bps is basis
-- points (10000 = 100%) so an equal three-way split can be exact (3334/3333/3333) without
-- floating point. approved_at is the ONLY column a contributor may ever move themselves, and
-- only while the agreement isn't locked.
-- ============================================================================================

create table if not exists guild_anthology_revenue_shares (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references guild_anthology_revenue_agreements(id) on delete cascade,
  contributor_id uuid not null references auth.users(id) on delete cascade,
  share_bps integer not null check (share_bps >= 0 and share_bps <= 10000),
  approved_at timestamptz,
  unique (agreement_id, contributor_id)
);

alter table guild_anthology_revenue_shares enable row level security;

create policy "guild members read revenue shares" on guild_anthology_revenue_shares
  for select using (
    exists (
      select 1 from guild_anthology_revenue_agreements ag
      join guild_anthologies a on a.id = ag.anthology_id
      where ag.id = guild_anthology_revenue_shares.agreement_id and is_guild_member(a.guild_id)
    )
  );

-- Row-scoped to the contributor themself; guard_anthology_revenue_share_update() below is what
-- restricts this to *only* approved_at. No policy at all lets the guild owner touch this table —
-- their sole lever is proposing a new revision, which resets every approval, in full view.
create policy "contributor manages their own approval" on guild_anthology_revenue_shares
  for update using (auth.uid() = contributor_id);

-- Deliberately no insert/delete policy — only propose_anthology_revenue_agreement() (security
-- definer) writes rows here, always as a full delete-and-reinsert of the whole set.

create or replace function guard_anthology_revenue_share_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- No bypass of any kind here — not for service_role, not for a trusted-RPC flag. This path may
  -- only ever be a contributor flipping their own approval, and that is the whole point.
  if auth.uid() is null or auth.uid() <> old.contributor_id then
    raise exception 'Not authorized to update this share.';
  end if;
  if new.agreement_id is distinct from old.agreement_id
     or new.contributor_id is distinct from old.contributor_id
     or new.share_bps is distinct from old.share_bps then
    raise exception 'A contributor may only approve or withdraw approval of their own share — never change the number itself.';
  end if;
  if exists (select 1 from guild_anthology_revenue_agreements ag where ag.id = old.agreement_id and ag.locked) then
    raise exception 'This revenue agreement is locked and can no longer be changed.';
  end if;
  return new;
end;
$$;

drop trigger if exists guild_anthology_revenue_share_guard on guild_anthology_revenue_shares;
create trigger guild_anthology_revenue_share_guard
  before update on guild_anthology_revenue_shares
  for each row execute function guard_anthology_revenue_share_update();

-- ============================================================================================
-- propose_anthology_revenue_agreement — owner-only. Always computes shares for every CURRENT
-- approved contributor (from guild_anthology_submissions, the one real source for who's in this
-- anthology) and always wipes every prior approval, whatever the split_type or whether any
-- number actually changed. That's what makes a re-propose safe rather than a backdoor: it can
-- never publish under an approval that was given for a different set of numbers.
-- ============================================================================================

create or replace function propose_anthology_revenue_agreement(
  p_anthology_id uuid,
  p_split_type text,
  p_custom_shares jsonb default null -- required for 'custom': [{"contributor_id": "...", "share_bps": 5000}, ...]
)
returns guild_anthology_revenue_agreements
language plpgsql security definer set search_path = public as $$
declare
  v_anth guild_anthologies%rowtype;
  v_owner uuid;
  v_agreement guild_anthology_revenue_agreements%rowtype;
  v_agreement_exists boolean;
  v_contributor_count integer;
  v_custom_count integer;
  v_custom_sum bigint;
begin
  select * into v_anth from guild_anthologies where id = p_anthology_id for update;
  if not found then
    raise exception 'Anthology not found.';
  end if;

  if not is_guild_officer(v_anth.guild_id) then
    raise exception 'Only the guild owner can propose a revenue agreement.';
  end if;
  if v_anth.status = 'published' then
    raise exception 'This anthology is already published — its revenue agreement is locked.';
  end if;
  if p_split_type not in ('equal', 'custom', 'contribution') then
    raise exception 'Unknown split type.';
  end if;

  select count(*) into v_contributor_count from (
    select distinct contributor_id from guild_anthology_submissions
    where anthology_id = p_anthology_id and review_status = 'approved'
  ) c;
  if v_contributor_count = 0 then
    raise exception 'At least one approved contributor is required before proposing a revenue agreement.';
  end if;

  select * into v_agreement from guild_anthology_revenue_agreements where anthology_id = p_anthology_id for update;
  v_agreement_exists := found;
  if v_agreement_exists and v_agreement.locked then
    raise exception 'This anthology''s revenue agreement is locked and can no longer be changed.';
  end if;

  if p_split_type = 'custom' then
    if p_custom_shares is null then
      raise exception 'Custom shares are required for a custom split.';
    end if;
    select count(*), coalesce(sum((r->>'share_bps')::integer), 0)
      into v_custom_count, v_custom_sum
      from jsonb_array_elements(p_custom_shares) r;
    if v_custom_count <> v_contributor_count then
      raise exception 'Custom shares must name exactly the anthology''s % approved contributor(s) — no more, no fewer.', v_contributor_count;
    end if;
    if exists (
      select 1 from jsonb_array_elements(p_custom_shares) r
      where not exists (
        select 1 from guild_anthology_submissions s
        where s.anthology_id = p_anthology_id and s.review_status = 'approved'
          and s.contributor_id = (r->>'contributor_id')::uuid
      )
    ) then
      raise exception 'Custom shares include someone who isn''t an approved contributor on this anthology.';
    end if;
    if exists (select 1 from jsonb_array_elements(p_custom_shares) r where (r->>'share_bps')::integer < 0) then
      raise exception 'A share cannot be negative.';
    end if;
    if v_custom_sum <> 10000 then
      raise exception 'Custom shares must add up to exactly 100%% of the anthology''s revenue — got %%.', round(v_custom_sum / 100.0, 2);
    end if;
  end if;

  if v_agreement_exists then
    update guild_anthology_revenue_agreements
      set split_type = p_split_type, revision = v_agreement.revision + 1, updated_at = now()
      where id = v_agreement.id
      returning * into v_agreement;
  else
    insert into guild_anthology_revenue_agreements (anthology_id, split_type, revision, created_by)
      values (p_anthology_id, p_split_type, 1, auth.uid())
      returning * into v_agreement;
  end if;

  -- Always start clean: whatever was here before (including anyone's approval) is gone the
  -- moment a new split is proposed, by design — see this migration's header.
  delete from guild_anthology_revenue_shares where agreement_id = v_agreement.id;

  if p_split_type = 'equal' then
    with contributors as (
      select distinct contributor_id from guild_anthology_submissions
      where anthology_id = p_anthology_id and review_status = 'approved'
    ),
    ranked as (
      select contributor_id, row_number() over (order by contributor_id) as rn from contributors
    )
    insert into guild_anthology_revenue_shares (agreement_id, contributor_id, share_bps, approved_at)
    select v_agreement.id, contributor_id,
           -- integer division leaves a remainder of at most (n-1) basis points; hand those out
           -- one apiece, in a fixed order, so the total is always exactly 10000.
           (10000 / v_contributor_count) + case when rn <= (10000 % v_contributor_count) then 1 else 0 end,
           null
    from ranked;

  elsif p_split_type = 'contribution' then
    with words as (
      select s.contributor_id, sum(s.word_count) as words
      from guild_anthology_submissions s
      where s.anthology_id = p_anthology_id and s.review_status = 'approved'
      group by s.contributor_id
    ),
    total as (
      select greatest(sum(words), 1) as total_words from words
    ),
    raw as (
      select w.contributor_id, (w.words::numeric / t.total_words) * 10000 as raw_share
      from words w cross join total t
    ),
    based as (
      select contributor_id, floor(raw_share)::integer as base, raw_share - floor(raw_share) as frac
      from raw
    ),
    ranked as (
      select contributor_id, base, frac,
             row_number() over (order by frac desc, contributor_id) as rn,
             (10000 - sum(base) over ())::integer as remainder
      from based
    )
    -- Largest-remainder method: proportional shares almost never land on whole basis points, so
    -- the leftover after flooring everyone goes to whoever was closest to rounding up, largest
    -- fraction first — the standard way to make a proportional split add up to exactly 100%
    -- without arbitrarily favoring the first row alphabetically.
    insert into guild_anthology_revenue_shares (agreement_id, contributor_id, share_bps, approved_at)
    select v_agreement.id, contributor_id, base + case when rn <= remainder then 1 else 0 end, null
    from ranked;

  else -- custom, already fully validated above
    insert into guild_anthology_revenue_shares (agreement_id, contributor_id, share_bps, approved_at)
    select v_agreement.id, (r->>'contributor_id')::uuid, (r->>'share_bps')::integer, null
    from jsonb_array_elements(p_custom_shares) r;
  end if;

  return v_agreement;
end;
$$;

revoke all on function propose_anthology_revenue_agreement(uuid, text, jsonb) from public;
grant execute on function propose_anthology_revenue_agreement(uuid, text, jsonb) to authenticated;

-- ============================================================================================
-- publish_guild_anthology — extended in place (same table it already wrote to in migration 35;
-- CREATE OR REPLACE keeps the function's identity and grants, only the body changes). Now
-- requires a revenue agreement that covers exactly the current approved contributors and has
-- every one of their approvals, and locks that agreement in the same transaction as the moment
-- it goes live — "once revenue begins" is exactly publish time, since that's the first moment a
-- sale (and therefore any actual revenue) becomes possible.
--
-- Also extended in place again later (item 4 follow-up, group-project floor): the old check only
-- required a nonzero word count ("at least one approved submission"). An anthology is several
-- contributors' work combined into one listing, so it gets its own, higher floor —
-- min_anthology_publish_word_count() (50,000 combined words) — rather than the solo-author
-- min_publish_word_count() used by published_books'/guild_published_books' own insert policies.
--
-- Extended in place a third time (91_migration_anthology_submission_content.sql — release
-- blocker): this function only ever inserted the published_books LISTING row, never a
-- published_book_content row — so a published anthology hit the exact "book has no content
-- mirror" hole 70_migration_published_book_content.sql closed for a solo book, just never
-- closed here. Fixed by refusing to publish while any approved submission is still missing its
-- own contributor's manuscript (content — see guild_anthology_submissions' own column comment),
-- then assembling all of them, in submission order, into the one published_book_content row a
-- reader actually opens.
-- ============================================================================================

create or replace function publish_guild_anthology(p_anthology_id uuid)
returns published_books
language plpgsql security definer set search_path = public as $$
declare
  v_anth guild_anthologies%rowtype;
  v_word_count integer;
  v_book_id text;
  v_book published_books%rowtype;
  v_agreement guild_anthology_revenue_agreements%rowtype;
  v_pending_count integer;
  v_mismatch_count integer;
  v_missing_content_count integer;
  v_guild_name text;
  v_chapters jsonb := '[]'::jsonb;
  v_sub record;
  v_author_name text;
  v_chap jsonb;
begin
  select * into v_anth from guild_anthologies where id = p_anthology_id for update;
  if not found then
    raise exception 'Anthology not found.';
  end if;

  if not is_guild_officer(v_anth.guild_id) then
    raise exception 'Only the guild owner can publish this anthology.';
  end if;
  if v_anth.status <> 'reviewing' then
    raise exception 'Close submissions and finish reviewing before publishing.';
  end if;
  if v_anth.published_book_id is not null then
    raise exception 'This anthology has already been published.';
  end if;

  select coalesce(sum(word_count), 0) into v_word_count
  from guild_anthology_submissions where anthology_id = p_anthology_id and review_status = 'approved';
  if v_word_count < min_anthology_publish_word_count() then
    raise exception 'This anthology''s approved submissions total % words — at least % are needed before publishing.', v_word_count, min_anthology_publish_word_count();
  end if;

  -- New: every approved contributor's actual manuscript text has to be here before this can
  -- become a real, readable book — see guild_anthology_submissions.content's own column comment
  -- for why a row could reach 'approved' with content still null (submitted before this column
  -- existed).
  select count(*) into v_missing_content_count
  from guild_anthology_submissions
  where anthology_id = p_anthology_id and review_status = 'approved' and content is null;
  if v_missing_content_count > 0 then
    raise exception '% approved contributor(s) haven''t attached their manuscript yet — ask them to open "Submit your work" again (or Edit their entry) before publishing.', v_missing_content_count;
  end if;

  select * into v_agreement from guild_anthology_revenue_agreements where anthology_id = p_anthology_id for update;
  if not found then
    raise exception 'Propose a revenue agreement and get every contributor''s approval before publishing.';
  end if;

  -- Guard against the agreement having gone stale — e.g. a submission was approved or rejected
  -- after the agreement was last proposed, so its contributor set no longer matches. Re-proposing
  -- (which always resets approvals) is the only way past this, on purpose: nobody's share should
  -- ever go live for a contributor list that isn't the one they actually approved.
  select count(*) into v_mismatch_count from (
    select contributor_id from (
      select contributor_id from guild_anthology_revenue_shares where agreement_id = v_agreement.id
      union all
      select contributor_id from guild_anthology_submissions
        where anthology_id = p_anthology_id and review_status = 'approved'
    ) all_ids
    group by contributor_id
    having count(*) <> 2
  ) mismatches;
  if v_mismatch_count > 0 then
    raise exception 'The revenue agreement''s contributors no longer match this anthology''s approved submissions — propose it again before publishing.';
  end if;

  select count(*) into v_pending_count
  from guild_anthology_revenue_shares where agreement_id = v_agreement.id and approved_at is null;
  if v_pending_count > 0 then
    raise exception '% contributor(s) still need to approve the revenue agreement before this can be published.', v_pending_count;
  end if;

  -- Assemble the actual manuscript, one approved contributor at a time in submission order —
  -- same "chapters: [{id,title,text}]" shape buildPublishedBookContent (ink-root.jsx) already
  -- sends for a solo book, so PublishedBookReader renders an anthology with no changes of its
  -- own. Each contributor's entry opens with a short byline section (their own submission title
  -- plus "By <name>", since the book itself has one shared title/cover/author line and would
  -- otherwise give a reader no way to tell whose work they're reading) followed by their actual
  -- chapters, unmodified.
  select g.name into v_guild_name from player_guilds g where g.id = v_anth.guild_id;

  for v_sub in
    select s.id, s.contributor_id, s.title, s.blurb, s.content
    from guild_anthology_submissions s
    where s.anthology_id = p_anthology_id and s.review_status = 'approved'
    order by s.submitted_at asc
  loop
    select coalesce(p.pen_name, p.display_name) into v_author_name from profiles p where p.id = v_sub.contributor_id;
    if v_author_name is null then
      v_author_name := 'Writer ' || substr(v_sub.contributor_id::text, 1, 8);
    end if;

    v_chapters := v_chapters || jsonb_build_array(jsonb_build_object(
      'id', 'section-' || v_sub.id::text,
      'title', v_sub.title,
      'text', '<p><em>By ' || v_author_name || '</em></p>'
        || case when v_sub.blurb is not null and v_sub.blurb <> '' then '<p>' || v_sub.blurb || '</p>' else '' end
    ));

    for v_chap in select * from jsonb_array_elements(coalesce(v_sub.content -> 'chapters', '[]'::jsonb))
    loop
      v_chapters := v_chapters || jsonb_build_array(jsonb_build_object(
        'id', v_sub.id::text || '-' || coalesce(v_chap ->> 'id', gen_random_uuid()::text),
        'title', coalesce(v_chap ->> 'title', ''),
        'text', coalesce(v_chap ->> 'text', '')
      ));
    end loop;
  end loop;

  v_book_id := 'anthology-' || p_anthology_id::text;

  insert into published_books (id, author_id, title, blurb, cover, price, word_count, destination)
  values (v_book_id, auth.uid(), v_anth.title, v_anth.description, v_anth.cover, v_anth.price, v_word_count, 'guild')
  returning * into v_book;

  -- The actual fix: without this insert, published_books above was the only row an anthology
  -- ever got — a listing with no content mirror behind it, same hole 70_migration_published_
  -- book_content.sql closed for a solo book, just never closed for this path.
  insert into published_book_content (book_id, content)
  values (v_book_id, jsonb_build_object(
    'title', v_anth.title,
    'subtitle', null,
    'seriesName', null,
    'author', coalesce(v_guild_name, 'The Guild') || ' — a Guild Anthology',
    'cover', v_anth.cover,
    'storyFormat', 'book',
    'chapters', v_chapters
  ))
  on conflict (book_id) do update set content = excluded.content;

  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies
    set status = 'published', published_book_id = v_book_id, published_at = now()
    where id = p_anthology_id;

  -- Revenue can begin the moment this row commits (the book is now purchasable) — so the
  -- agreement locks in the same breath, not as a separate later step someone could skip.
  update guild_anthology_revenue_agreements
    set locked = true, locked_at = now()
    where id = v_agreement.id;

  return v_book;
end;
$$;

-- Safe to run anytime: every object here is created with if-not-exists/or-replace, and the only
-- pre-existing function this touches (publish_guild_anthology) keeps its exact signature, so
-- nothing that already calls it needs to change.

-- Migration 37: Guild revenue distribution — connects a verified sale to the Guild Treasury.
--
-- Closes a gap migration 36 (guild_anthology_revenue_agreements) left open by its own design:
-- proposing and approving a revenue split was real, but nothing ever paid it out. An anthology
-- sale still flows through the same `purchases` row every solo book uses — `author_id` on that
-- row is whoever called publish_guild_anthology (the guild owner), so until this migration, a
-- successful anthology sale's entire `author_amount_kobo` landed in the owner's own personal
-- withdrawable balance via author_balance_kobo(), in full, regardless of what the contributors
-- had agreed to split it. Nobody's row was wrong on its own — purchases/author_balance_kobo
-- never knew an anthology was a different kind of sale — but the two features were never wired
-- together.
--
-- What this migration adds:
--   1. Two new columns on guild_treasury_transactions (source_purchase_id, anthology_id) so a
--      distribution row can point back at the exact verified sale and anthology that produced
--      it — needed for both the dedup check below and an honest ledger/UI.
--   2. distribute_guild_revenue() — a generic, source-agnostic engine: given a guild, an
--      already-fee-applied gross amount, and a set of {contributor_id, share_bps} shares, it
--      credits each contributor's earnings (bucket='member', held in trust — see migration 33's
--      original comment on that bucket), credits whatever's left over to the guild's own bucket,
--      and does both as permanent ledger rows. Nothing about it is anthology-specific; a future
--      Guild Events feature can call it the same way with source='event_sale' once one exists —
--      see the header of that reserved vocabulary in migration 33's guild_treasury_transactions
--      comments. Deliberately NOT granted to authenticated/public: it trusts its arguments
--      completely (guild_id, shares, amount), so it may only ever be called from another
--      security-definer function that has independently re-derived those facts itself — never
--      directly by a client.
--   3. distribute_anthology_sale_to_treasury() — a trigger on `purchases`, firing only on the
--      genuine pending -> success transition (the same transition paystack-webhook alone can
--      cause), which is the concrete wiring: for a sale of an anthology's published book, look
--      up its locked revenue agreement's shares and call the engine above. An ordinary solo
--      book's sale finds no matching guild_anthologies row and is untouched — this is also the
--      "clean hook" for a future event trigger to follow the same shape.
--   4. author_balance_kobo() updated in place to stop counting anthology-book purchases toward
--      the *personal* balance of whoever's on the purchases row — that money is now distributed
--      through the treasury instead, and counting it in both places would pay it out twice.
--   5. A one-time backfill: any anthology purchase that was already 'success' before this
--      migration ran (so its money is already sitting in the owner's personal balance, never
--      distributed) gets distributed now, the same way a new sale would be — see the comment
--      on the backfill block below for what this means for that balance going forward.
--
-- Duplicate-processing protection, three independent layers:
--   a. paystack-webhook's own update is scoped `.eq('status', 'pending')` — a retried webhook
--      event for an already-'success' row updates zero rows, so the trigger below never re-fires
--      for it in the first place.
--   b. The trigger's own WHEN clause only fires on an actual old-status-is-not-success ->
--      new-status-is-success transition, not on every UPDATE.
--   c. distribute_guild_revenue() itself checks, under an advisory lock keyed to the specific
--      purchase, whether any guild_treasury_transactions row already references this
--      source_purchase_id before writing anything — belt-and-suspenders even if (a) and (b) were
--      ever bypassed by a direct, unanticipated call.
--
-- Safe to run once on an existing deployment; a fresh install gets all of this from schema.sql
-- with nothing extra to run.

-- ============================================================================================
-- 1. New columns
-- ============================================================================================

alter table guild_treasury_transactions
  add column if not exists source_purchase_id uuid references purchases(id) on delete set null;
alter table guild_treasury_transactions
  add column if not exists anthology_id uuid references guild_anthologies(id) on delete set null;

create index if not exists guild_treasury_transactions_source_purchase_idx
  on guild_treasury_transactions (source_purchase_id) where source_purchase_id is not null;
create index if not exists guild_treasury_transactions_anthology_idx
  on guild_treasury_transactions (anthology_id) where anthology_id is not null;

-- ============================================================================================
-- 2. The generic distribution engine
-- ============================================================================================

create or replace function distribute_guild_revenue(
  p_guild_id uuid,
  p_gross_amount_kobo bigint,     -- already platform-fee-applied — see the header above
  p_shares jsonb,                 -- [{"contributor_id": uuid, "share_bps": int}, ...], sum <= 10000
  p_kind text,                    -- 'anthology_share' today; 'event_revenue' reserved for later
  p_source text,                  -- 'anthology_sale' today; 'event_sale' reserved for later
  p_source_purchase_id uuid,      -- the verified purchases.id this revenue came from — the dedup key
  p_anthology_id uuid default null,
  p_project_event_id uuid default null,
  p_title text default null
)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_already_processed boolean;
  v_shares_sum integer;
  v_member_credited bigint;
  v_guild_share bigint;
begin
  if p_gross_amount_kobo is null or p_gross_amount_kobo <= 0 then
    return; -- nothing to distribute
  end if;
  if p_source_purchase_id is null then
    raise exception 'A source purchase id is required — every distribution must trace back to one verified sale.';
  end if;

  -- Locked to this specific sale, not the whole guild, so an anthology sale and a (future) event
  -- sale for the same guild can be distributed concurrently without blocking on each other.
  perform pg_advisory_xact_lock(hashtext('guild_revenue_distribution:' || p_source_purchase_id::text));

  select exists(
    select 1 from guild_treasury_transactions where source_purchase_id = p_source_purchase_id
  ) into v_already_processed;
  if v_already_processed then
    return; -- this exact sale has already been distributed — never pay it out twice
  end if;

  select coalesce(sum((s->>'share_bps')::integer), 0) into v_shares_sum
  from jsonb_array_elements(p_shares) s;
  if v_shares_sum < 0 or v_shares_sum > 10000 then
    raise exception 'Contributor shares must add up to no more than 100%% of the sale.';
  end if;

  -- Largest-remainder distribution, same method propose_anthology_revenue_agreement's
  -- 'contribution' split already uses: floor everyone first, then hand the leftover kobo (at
  -- most one per contributor) to whoever was closest to rounding up. Guarantees every member
  -- credit plus the guild's own share sums to exactly p_gross_amount_kobo — no kobo invented or
  -- lost to rounding.
  with shares as (
    select (s->>'contributor_id')::uuid as contributor_id, (s->>'share_bps')::integer as share_bps
    from jsonb_array_elements(p_shares) s
    where (s->>'share_bps')::integer > 0
  ),
  amounts as (
    select contributor_id, share_bps,
      floor(p_gross_amount_kobo * share_bps::numeric / 10000)::bigint as base,
      (p_gross_amount_kobo * share_bps::numeric / 10000) - floor(p_gross_amount_kobo * share_bps::numeric / 10000) as frac
    from shares
  ),
  total_base as (
    select coalesce(sum(base), 0)::bigint as sum_base from amounts
  ),
  ranked as (
    select a.contributor_id, a.base, a.frac,
           row_number() over (order by a.frac desc, a.contributor_id) as rn,
           (p_gross_amount_kobo - t.sum_base) as leftover
    from amounts a cross join total_base t
  )
  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     project_event_id, status, title, source_purchase_id, anthology_id)
  select p_guild_id, 'member', contributor_id, 'credit', p_kind,
         base + case when rn <= leftover then 1 else 0 end, 'NGN', p_source, 'member_earnings_held',
         p_project_event_id, 'success', p_title, p_source_purchase_id, p_anthology_id
  from ranked
  where base + case when rn <= leftover then 1 else 0 end > 0;

  select coalesce(sum(amount_kobo), 0) into v_member_credited
  from guild_treasury_transactions
  where source_purchase_id = p_source_purchase_id and bucket = 'member';

  v_guild_share := p_gross_amount_kobo - v_member_credited;
  if v_guild_share > 0 then
    insert into guild_treasury_transactions
      (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
       project_event_id, status, title, source_purchase_id, anthology_id)
    values
      (p_guild_id, 'guild', null, 'credit', p_kind, v_guild_share, 'NGN', p_source, 'guild_treasury',
       p_project_event_id, 'success', p_title, p_source_purchase_id, p_anthology_id);
  end if;
end;
$$;

-- Deliberately no grant to authenticated/public — see the header above. Only a security-definer
-- function that has already re-derived guild_id/shares/amount itself (never from a client
-- argument) may call this.
revoke all on function distribute_guild_revenue(uuid, bigint, jsonb, text, text, uuid, uuid, uuid, text) from public;

-- ============================================================================================
-- 3. Wiring: anthology sales
-- ============================================================================================

create or replace function distribute_anthology_sale_to_treasury()
returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_anth guild_anthologies%rowtype;
  v_agreement guild_anthology_revenue_agreements%rowtype;
  v_shares jsonb;
begin
  if new.status <> 'success' or old.status = 'success' or new.book_id is null then
    return new;
  end if;

  select * into v_anth from guild_anthologies where published_book_id = new.book_id;
  if not found then
    return new; -- an ordinary solo book sale — untouched, exactly today's existing behavior
  end if;

  select * into v_agreement from guild_anthology_revenue_agreements where anthology_id = v_anth.id;
  if not found or not v_agreement.locked then
    -- publish_guild_anthology requires a locked, fully-approved agreement before an anthology
    -- can go live at all, so this shouldn't happen — but if it somehow does, don't guess: leave
    -- the sale exactly as it landed rather than distributing against a stale or missing split.
    return new;
  end if;

  select coalesce(jsonb_agg(jsonb_build_object('contributor_id', contributor_id, 'share_bps', share_bps)), '[]'::jsonb)
    into v_shares
  from guild_anthology_revenue_shares
  where agreement_id = v_agreement.id;

  perform distribute_guild_revenue(
    p_guild_id := v_anth.guild_id,
    p_gross_amount_kobo := new.author_amount_kobo,
    p_shares := v_shares,
    p_kind := 'anthology_share',
    p_source := 'anthology_sale',
    p_source_purchase_id := new.id,
    p_anthology_id := v_anth.id,
    p_title := 'Anthology sale — ' || v_anth.title
  );

  return new;
end;
$$;

drop trigger if exists purchases_distribute_anthology_sale on purchases;
create trigger purchases_distribute_anthology_sale
  after update on purchases
  for each row
  when (new.status = 'success' and old.status is distinct from 'success')
  execute function distribute_anthology_sale_to_treasury();

-- ============================================================================================
-- 4. author_balance_kobo — stop double-counting anthology sales
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(p.author_amount_kobo) from purchases p
              where p.author_id = check_user_id and p.status = 'success'
                -- An anthology sale's proceeds are distributed through the guild treasury (see
                -- distribute_anthology_sale_to_treasury above) instead of landing in the
                -- publishing owner's personal balance whole — counting it here too would pay the
                -- same sale out twice. A solo book (the vast majority of purchases rows) has no
                -- matching guild_anthologies row and is completely unaffected.
                and not exists (
                  select 1 from guild_anthologies a where a.published_book_id = p.book_id
                )), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0);
$$ language sql stable security definer set search_path = public;

revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- ============================================================================================
-- 5. One-time backfill for anthology sales that already succeeded before this migration
-- ============================================================================================
-- Without this, any anthology sale that completed before today keeps its proceeds sitting in the
-- owner's personal balance (already paid out under the old, unwired behavior) while
-- author_balance_kobo above stops counting it going forward — silently shrinking that balance
-- with nothing to explain why. Running the exact same distribution for those past sales now
-- means: the owner's balance moves to reflect only their own contributor share (if any) plus
-- whatever the guild's cut is, same as a sale processed today would; every other contributor
-- gets the treasury credit they were always owed by the locked agreement they approved.
do $$
declare
  r record;
  v_agreement guild_anthology_revenue_agreements%rowtype;
  v_shares jsonb;
begin
  for r in
    select p.id as purchase_id, p.author_amount_kobo, a.id as anthology_id, a.guild_id, a.title
    from purchases p
    join guild_anthologies a on a.published_book_id = p.book_id
    where p.status = 'success'
      and not exists (
        select 1 from guild_treasury_transactions t where t.source_purchase_id = p.id
      )
  loop
    select * into v_agreement from guild_anthology_revenue_agreements where anthology_id = r.anthology_id;
    if not found or not v_agreement.locked then
      continue; -- shouldn't happen for a published anthology, but skip rather than guess
    end if;

    select coalesce(jsonb_agg(jsonb_build_object('contributor_id', contributor_id, 'share_bps', share_bps)), '[]'::jsonb)
      into v_shares
    from guild_anthology_revenue_shares
    where agreement_id = v_agreement.id;

    perform distribute_guild_revenue(
      p_guild_id := r.guild_id,
      p_gross_amount_kobo := r.author_amount_kobo,
      p_shares := v_shares,
      p_kind := 'anthology_share',
      p_source := 'anthology_sale',
      p_source_purchase_id := r.purchase_id,
      p_anthology_id := r.anthology_id,
      p_title := 'Anthology sale — ' || r.title
    );
  end loop;
end $$;

-- ============================================================================================
-- Migration 38 — see supabase/history/38_migration_rising_star_scoring.sql for the full narrative
-- header (why book_read_events/follow_events/book_publish_events exist, and the three gaming
-- vectors this closes). Rising Star scoring: recent momentum, computed server-side, configurable
-- via rising_star_config, never a lifetime total.
-- ============================================================================================


create table if not exists book_read_events (
  id uuid primary key default gen_random_uuid(),
  book_id text not null references published_books(id) on delete cascade,
  reader_id uuid not null references auth.users(id) on delete cascade,
  -- One row per reader per book per UTC day, enforced below — this is what stops "recent
  -- readers" from being farmable by one account just re-opening the same book in a loop.
  read_day date not null default ((now() at time zone 'utc')::date),
  created_at timestamptz not null default now(),
  unique (book_id, reader_id, read_day)
);

alter table book_read_events enable row level security;

-- A reader logs their own read, never someone else's, never a book's own author reading their
-- own work (that would let an author farm their own "recent readers" for free) — and never a
-- banned account, same gate every other content-adjacent insert policy in this schema uses.
create policy "a reader logs their own read" on book_read_events
  for insert with check (
    auth.uid() = reader_id
    and not is_banned(auth.uid())
    and not exists (select 1 from published_books b where b.id = book_id and b.author_id = auth.uid())
  );
-- Only a reader's own read history is readable directly — the aggregate a Rising Star score
-- needs is only ever produced through compute_rising_stars() below (security definer), never by
-- a client reading and summing this table itself.
create policy "a reader reads their own read history" on book_read_events
  for select using (auth.uid() = reader_id);

create index if not exists book_read_events_book_day_idx on book_read_events (book_id, read_day);
create index if not exists book_read_events_reader_day_idx on book_read_events (reader_id, read_day);

-- ============================================================================================
-- 2. follow_events — an insert-only ledger of genuinely NEW follows, separate from the mutable
--    `follows` table (which only ever reflects CURRENT follow state and is deleted on unfollow).
-- ============================================================================================

create table if not exists follow_events (
  id uuid primary key default gen_random_uuid(),
  follower_id uuid not null references auth.users(id) on delete cascade,
  followee_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  -- The whole anti-cycling guard: only the first follow a given pair has EVER produced can ever
  -- insert here. See log_follow_event() below for the on-conflict-do-nothing that enforces it.
  unique (follower_id, followee_id)
);

alter table follow_events enable row level security;
-- Public read, same as `follows` itself — "who gained a follower recently" isn't sensitive, and
-- this is what a future client-side display (not just compute_rising_stars()) could read
-- directly without needing its own RPC.
create policy "anyone can read follow events" on follow_events
  for select using (true);
-- Deliberately no insert policy for authenticated: this table is only ever written by the
-- trigger below (security definer), so a client can't backdate a follow_event or otherwise
-- spoof "gained a follower" without an actual row in `follows` having caused it.

create or replace function log_follow_event()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.follower_id = new.followee_id then
    return new; -- defensive only — the app never offers a self-follow button, but never ledger
                -- one even if some future path allowed it.
  end if;
  insert into follow_events (follower_id, followee_id)
  values (new.follower_id, new.followee_id)
  on conflict (follower_id, followee_id) do nothing;
  return new;
end;
$$;

drop trigger if exists follows_log_event on follows;
create trigger follows_log_event
  after insert on follows
  for each row execute function log_follow_event();

create index if not exists follow_events_followee_idx on follow_events (followee_id, created_at desc);

-- ============================================================================================
-- 3. book_publish_events — pins each book_id's TRUE first-ever publish moment, permanently,
--    independent of published_books (which is deleted on unpublish and freely re-upserted with
--    a client-supplied published_at on republish — see this migration's header, gaming vector c).
-- ============================================================================================

create table if not exists book_publish_events (
  -- No foreign key to published_books(id) on purpose: unlike every other new table here, this
  -- one has to OUTLIVE the published_books row it describes (survive an unpublish), which an
  -- `on delete cascade` FK would defeat entirely.
  book_id text primary key,
  author_id uuid not null references auth.users(id) on delete cascade,
  first_published_at timestamptz not null default now()
);

alter table book_publish_events enable row level security;
create policy "anyone can read book publish events" on book_publish_events
  for select using (true);
-- No insert policy for authenticated — written only by the trigger below.

create or replace function log_book_publish_event()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into book_publish_events (book_id, author_id, first_published_at)
  values (new.id, new.author_id, now())
  on conflict (book_id) do nothing; -- pins the true first publish; a later unpublish + republish
                                     -- of the same book_id (or any ordinary re-upsert/update) is
                                     -- an INSERT again from published_books' point of view but
                                     -- never moves this row.
  return new;
end;
$$;

drop trigger if exists published_books_log_publish_event on published_books;
create trigger published_books_log_publish_event
  after insert on published_books
  for each row execute function log_book_publish_event();

-- One-time backfill so books already published before this migration ran aren't invisible to it
-- — best-effort, using each book's existing published_at as its first-known publish moment,
-- same spirit as migration 37's own backfill block.
insert into book_publish_events (book_id, author_id, first_published_at)
select id, author_id, published_at from published_books
on conflict (book_id) do nothing;

-- ============================================================================================
-- 4. rising_star_config — the one moderator-tunable row every window, floor, cap, and weight
--    below is read from. Singleton pattern (id boolean primary key default true check (id)):
--    there is exactly one row, ever.
-- ============================================================================================

create table if not exists rising_star_config (
  id boolean primary key default true check (id),
  window_days integer not null default 7 check (window_days between 1 and 90),
  compare_window_days integer not null default 7 check (compare_window_days between 1 and 90),
  min_distinct_recent_readers integer not null default 3 check (min_distinct_recent_readers >= 0),
  max_counted_publishes_per_window integer not null default 3 check (max_counted_publishes_per_window between 1 and 50),
  result_limit integer not null default 10 check (result_limit between 1 and 100),
  weight_recent_readers numeric not null default 3.0 check (weight_recent_readers >= 0),
  weight_reading_growth numeric not null default 4.0 check (weight_reading_growth >= 0),
  weight_followers_gained numeric not null default 2.5 check (weight_followers_gained >= 0),
  weight_book_engagement numeric not null default 2.0 check (weight_book_engagement >= 0),
  weight_publishing_activity numeric not null default 1.5 check (weight_publishing_activity >= 0),
  updated_at timestamptz not null default now()
);

insert into rising_star_config (id) values (true) on conflict (id) do nothing;

alter table rising_star_config enable row level security;
-- Same trust tier as the moderation queue and content bans — a moderator can retune Rising Star
-- scoring the same way they moderate content, without needing the service-role key or a
-- separate deploy. Not publicly readable: the exact floors/caps are part of what makes this hard
-- to game, and there's no legitimate reader-facing reason to expose them.
create policy "moderators read rising star config" on rising_star_config
  for select using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));
create policy "moderators update rising star config" on rising_star_config
  for update using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));

-- ============================================================================================
-- 5. compute_rising_stars() — the score itself. security definer so it can read across every
--    author's rows for aggregation (book_read_events/follow_events select policies are
--    deliberately narrow — see above), but it only ever returns aggregates, never a raw row from
--    any of those tables, so it can't be used to reconstruct anyone's individual read/follow
--    history.
-- ============================================================================================

create or replace function compute_rising_stars(p_window_days integer default null, p_result_limit integer default null)
returns table (
  author_id uuid,
  pen_name text,
  display_name text,
  avatar_url text,
  recent_unique_readers integer,
  reading_growth integer,
  followers_gained integer,
  book_engagement numeric,
  recent_publishes integer,
  reputation_gained numeric,
  score numeric
)
language sql
stable
security definer
set search_path = public
as $$
  with cfg as (
    select * from rising_star_config limit 1
  ),
  params as (
    select
      -- p_window_days/p_result_limit let a caller preview a different window/size, but every
      -- WEIGHT and FLOOR below always comes from cfg — never from an argument — so a client can
      -- narrow what it asks for but can never change what a signal is worth.
      greatest(1, least(90, coalesce(p_window_days, (select window_days from cfg), 7)))::int as window_days,
      coalesce((select compare_window_days from cfg), 7)::int as compare_window_days,
      greatest(1, least(100, coalesce(p_result_limit, (select result_limit from cfg), 10)))::int as result_limit,
      coalesce((select min_distinct_recent_readers from cfg), 3)::int as min_readers,
      coalesce((select max_counted_publishes_per_window from cfg), 3)::int as max_pub,
      coalesce((select weight_recent_readers from cfg), 3.0)::numeric as w_readers,
      coalesce((select weight_reading_growth from cfg), 4.0)::numeric as w_growth,
      coalesce((select weight_followers_gained from cfg), 2.5)::numeric as w_followers,
      coalesce((select weight_book_engagement from cfg), 2.0)::numeric as w_engagement,
      coalesce((select weight_publishing_activity from cfg), 1.5)::numeric as w_publishing
  ),
  windows as (
    select
      now() - make_interval(days => window_days) as cur_start,
      now() - make_interval(days => window_days + compare_window_days) as prev_start,
      now() - make_interval(days => window_days) as prev_end
    from params
  ),
  -- Only currently-published, non-content-banned authors are candidates at all.
  eligible_authors as (
    select distinct b.author_id
    from published_books b
    join profiles p on p.id = b.author_id
    where coalesce(p.banned, false) = false
  ),
  reads_cur as (
    select b.author_id, count(distinct r.reader_id) as readers
    from book_read_events r
    join published_books b on b.id = r.book_id, windows w
    where r.created_at >= w.cur_start
    group by b.author_id
  ),
  reads_prev as (
    select b.author_id, count(distinct r.reader_id) as readers
    from book_read_events r
    join published_books b on b.id = r.book_id, windows w
    where r.created_at >= w.prev_start and r.created_at < w.prev_end
    group by b.author_id
  ),
  followers_cur as (
    select f.followee_id as author_id, count(*) as gained
    from follow_events f, windows w
    where f.created_at >= w.cur_start and f.follower_id <> f.followee_id
    group by f.followee_id
  ),
  reviews_cur as (
    -- Never a book's own author reviewing themselves — reviews' own unique(book_id,
    -- reviewer_id) already stops a reader from reviewing the same book twice, but this still
    -- guards the self-review case defensively at the scoring layer.
    select b.author_id, count(*) as ct
    from reviews rv
    join published_books b on b.id = rv.book_id, windows w
    where rv.created_at >= w.cur_start and rv.reviewer_id <> b.author_id
    group by b.author_id
  ),
  purchases_cur as (
    -- status = 'success' only — a pending or failed purchase can't be faked into existing
    -- without Paystack itself confirming real money moved (see purchases' own comment on why it
    -- has no client insert/update policy at all), so this is already about as hard to fake as a
    -- signal can be.
    select pu.author_id, count(*) as ct
    from purchases pu, windows w
    where pu.status = 'success' and pu.created_at >= w.cur_start and pu.buyer_id <> pu.author_id
    group by pu.author_id
  ),
  publishes_cur as (
    -- The immutable ledger (section 3 above), not published_books.published_at directly — this
    -- is what makes recent publishing activity immune to the unpublish/republish loophole.
    select e.author_id, count(*) as ct
    from book_publish_events e, windows w
    where e.first_published_at >= w.cur_start
    group by e.author_id
  )
  select
    ea.author_id,
    p.pen_name, p.display_name, p.avatar_url,
    coalesce(rc.readers, 0)::integer as recent_unique_readers,
    greatest(coalesce(rc.readers, 0) - coalesce(rp.readers, 0), 0)::integer as reading_growth,
    coalesce(fc.gained, 0)::integer as followers_gained,
    -- Same diminishing curve (value * sqrt(count)) and the same real per-action values
    -- (review = 8, purchase = 4) as REPUTATION_VALUES in author-reputation.jsx — reviews and
    -- purchases are real, live signals, just not yet folded into lifetime Reputation there (see
    -- that file's own REPUTATION_SOURCES comment); this is the "book engagement" bullet of the
    -- Rising Star spec, computed on the same recent-window basis as everything else here.
    round(
      (case when coalesce(rv.ct, 0) > 0 then 8.0 * sqrt(coalesce(rv.ct, 0)) else 0 end)
      + (case when coalesce(pc.ct, 0) > 0 then 4.0 * sqrt(coalesce(pc.ct, 0)) else 0 end)
    , 2) as book_engagement,
    least(coalesce(pb.ct, 0), (select max_pub from params))::integer as recent_publishes,
    -- Informational only, not summed a second time into `score` below (followers_gained and
    -- recent_publishes already each have their own independently-weighted score term) — this
    -- mirrors what those two signals would be worth under the app's real lifetime-Reputation
    -- formula (follow = 2, publishedBook = 40), just scoped to this recent window instead of a
    -- lifetime total, so the UI can show "recent reputation-equivalent points earned" honestly.
    round(
      (case when coalesce(fc.gained, 0) > 0 then 2.0 * sqrt(coalesce(fc.gained, 0)) else 0 end)
      + (case when coalesce(pb.ct, 0) > 0 then 40.0 * sqrt(least(coalesce(pb.ct, 0), (select max_pub from params))) else 0 end)
    , 2) as reputation_gained,
    round(
      -- Reading-related terms are floored to zero entirely below min_distinct_recent_readers —
      -- the anti-collusion guard described in this migration's header.
      (case when coalesce(rc.readers, 0) >= (select min_readers from params)
        then (select w_readers from params) * sqrt(coalesce(rc.readers, 0))
             + (select w_growth from params) * sqrt(greatest(coalesce(rc.readers, 0) - coalesce(rp.readers, 0), 0))
        else 0 end)
      + (select w_followers from params) * (case when coalesce(fc.gained, 0) > 0 then sqrt(coalesce(fc.gained, 0)) else 0 end)
      + (select w_engagement from params) *
          ((case when coalesce(rv.ct, 0) > 0 then sqrt(coalesce(rv.ct, 0)) else 0 end)
           + (case when coalesce(pc.ct, 0) > 0 then sqrt(coalesce(pc.ct, 0)) else 0 end))
      + (select w_publishing from params) * least(coalesce(pb.ct, 0), (select max_pub from params))
    , 4) as score
  from eligible_authors ea
  join profiles p on p.id = ea.author_id
  left join reads_cur rc on rc.author_id = ea.author_id
  left join reads_prev rp on rp.author_id = ea.author_id
  left join followers_cur fc on fc.author_id = ea.author_id
  left join reviews_cur rv on rv.author_id = ea.author_id
  left join purchases_cur pc on pc.author_id = ea.author_id
  left join publishes_cur pb on pb.author_id = ea.author_id
  -- No recent signal of any kind at all -- not a Rising Star this window, full stop, rather than
  -- a 0-score row cluttering the result.
  where coalesce(rc.readers, 0) + coalesce(fc.gained, 0) + coalesce(rv.ct, 0) + coalesce(pc.ct, 0) + coalesce(pb.ct, 0) > 0
  order by score desc, ea.author_id
  limit (select result_limit from params);
$$;

revoke all on function compute_rising_stars(integer, integer) from public;
grant execute on function compute_rising_stars(integer, integer) to authenticated;

-- Lets a reader log a read without needing to know book_read_events' shape or handle the
-- same-day unique-constraint conflict itself — see src/lib/rising-stars.js's logBookRead, which
-- calls this instead of inserting directly.
-- Deliberately NOT security definer, unlike compute_rising_stars() above and the trigger
-- functions in sections 2/3 — this one runs as the CALLING user on purpose, so book_read_events'
-- own insert policy (own account only, never a banned account, never a book's own author) is the
-- thing actually enforcing the self-read guard, not this function pretending to. A security
-- definer version here would run as the function owner and bypass that RLS check entirely,
-- silently defeating the "an author can't farm reads on their own book" protection this
-- migration's header promises.
create or replace function log_book_read(p_book_id text)
returns void
language plpgsql
set search_path = public
as $$
begin
  insert into book_read_events (book_id, reader_id)
  values (p_book_id, auth.uid())
  on conflict (book_id, reader_id, read_day) do nothing;
exception
  -- Catches both: (a) the insert policy (own account, not banned, not this book's own author)
  -- denying the insert via RLS — still enforced here since this function runs as the caller, not
  -- as a security definer bypass — for a reader who, say, opened their own published book; and
  -- (b) a foreign-key violation for a book_id that isn't in published_books at all, e.g. a book
  -- still local-only/never published, or read from an app version that passes a raw project id.
  -- Either way this is a fire-and-forget signal, not something that should ever interrupt an
  -- actual read — any failure here just means this open doesn't count toward Rising Star.
  when others then
    return;
end;
$$;

revoke all on function log_book_read(text) from public;
grant execute on function log_book_read(text) to authenticated;

-- ============================================================================================
-- Migration 39 — see supabase/history/39_migration_best_sellers_most_read.sql for the full
-- narrative header (why the recency-decay formula, the anti-collusion floors, and the
-- self-purchase exclusion exist). Best Sellers ranks verified purchases, Most Read ranks
-- verified book_read_events (migration 38) — both server-side, both recency-weighted, neither
-- editable by an author or guild.
-- ============================================================================================

create table if not exists book_ranking_config (
  id boolean primary key default true check (id),
  lookback_days integer not null default 90 check (lookback_days between 1 and 365),
  half_life_days numeric not null default 5 check (half_life_days > 0 and half_life_days <= 90),
  min_distinct_buyers integer not null default 2 check (min_distinct_buyers >= 0),
  min_distinct_readers integer not null default 3 check (min_distinct_readers >= 0),
  result_limit integer not null default 8 check (result_limit between 1 and 100),
  updated_at timestamptz not null default now()
);

insert into book_ranking_config (id) values (true) on conflict (id) do nothing;

alter table book_ranking_config enable row level security;
-- Same trust tier and same reasoning as rising_star_config in migration 38 — moderator-only, not
-- publicly readable (the exact floors are part of what makes both rankings hard to game).
create policy "moderators read book ranking config" on book_ranking_config
  for select using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));
create policy "moderators update book ranking config" on book_ranking_config
  for update using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));

-- ============================================================================================
-- 2. compute_best_sellers() — ranked by verified, recency-weighted purchase activity.
-- ============================================================================================

create or replace function compute_best_sellers(p_result_limit integer default null)
returns table (
  book_id text,
  title text,
  author_id uuid,
  author_name text,
  genre text,
  distinct_buyers integer,
  verified_sales_units integer,
  verified_revenue_kobo bigint,
  score numeric
)
language sql
stable
security definer
set search_path = public
as $$
  with cfg as (
    select * from book_ranking_config limit 1
  ),
  params as (
    select
      -- p_result_limit lets a caller ask for fewer/more rows; it can never change the lookback,
      -- decay, or floor below — those only ever come from cfg.
      coalesce((select lookback_days from cfg), 90)::int as lookback_days,
      coalesce((select half_life_days from cfg), 5)::numeric as half_life_days,
      coalesce((select min_distinct_buyers from cfg), 2)::int as min_buyers,
      greatest(1, least(100, coalesce(p_result_limit, (select result_limit from cfg), 8)))::int as result_limit
  ),
  lookback as (
    select now() - make_interval(days => lookback_days) as cutoff from params
  ),
  verified_sales as (
    select pu.book_id, pu.buyer_id, pu.author_id, pu.amount_kobo, pu.author_amount_kobo, pu.created_at
    from purchases pu, lookback l
    where pu.kind = 'book' and pu.status = 'success' and pu.created_at >= l.cutoff
      and pu.book_id is not null
      -- The one gaming vector real money alone doesn't close — an author buying their own book
      -- back with their own money, at a net cost of only the platform's fee, to fake demand.
      and pu.buyer_id <> pu.author_id
  ),
  per_buyer as (
    select
      book_id, buyer_id,
      count(*) as units,
      sum(author_amount_kobo) as buyer_author_revenue_kobo,
      max(created_at) as most_recent
    from verified_sales
    group by book_id, buyer_id
  ),
  per_book as (
    select
      pb.book_id,
      count(distinct pb.buyer_id)::integer as distinct_buyers,
      sum(pb.units)::integer as verified_sales_units,
      sum(pb.buyer_author_revenue_kobo)::bigint as verified_revenue_kobo,
      -- Per buyer: sqrt(their own unit count) \u00d7 half-life decay from THEIR most recent
      -- purchase of it, summed across buyers. A buyer who bought once, long ago, and never
      -- returned fades out at the same rate a single old purchase would on its own.
      sum(
        sqrt(pb.units) * exp(ln(0.5) * (extract(epoch from (now() - pb.most_recent)) / 86400.0) / (select half_life_days from params))
      ) as decayed_score
    from per_buyer pb
    group by pb.book_id
  )
  select
    b.id as book_id, b.title, b.author_id,
    coalesce(p.pen_name, p.display_name, 'A writer') as author_name, b.genre,
    per.distinct_buyers, per.verified_sales_units, coalesce(per.verified_revenue_kobo, 0)::bigint,
    round(per.decayed_score, 4) as score
  from per_book per
  join published_books b on b.id = per.book_id
  join profiles p on p.id = b.author_id
  -- Hard floor, not a soft discount — see this migration's header, point 2b.
  where per.distinct_buyers >= (select min_buyers from params)
  order by score desc, per.verified_sales_units desc, per.book_id
  limit (select result_limit from params);
$$;

revoke all on function compute_best_sellers(integer) from public;
grant execute on function compute_best_sellers(integer) to authenticated;

-- ============================================================================================
-- 3. compute_most_read() — ranked by verified, recency-weighted reader-open activity.
-- ============================================================================================

create or replace function compute_most_read(p_result_limit integer default null)
returns table (
  book_id text,
  title text,
  author_id uuid,
  author_name text,
  genre text,
  distinct_readers integer,
  verified_read_events integer,
  score numeric
)
language sql
stable
security definer
set search_path = public
as $$
  with cfg as (
    select * from book_ranking_config limit 1
  ),
  params as (
    select
      coalesce((select lookback_days from cfg), 90)::int as lookback_days,
      coalesce((select half_life_days from cfg), 5)::numeric as half_life_days,
      coalesce((select min_distinct_readers from cfg), 3)::int as min_readers,
      greatest(1, least(100, coalesce(p_result_limit, (select result_limit from cfg), 8)))::int as result_limit
  ),
  lookback as (
    select now() - make_interval(days => lookback_days) as cutoff from params
  ),
  per_reader as (
    select r.book_id, r.reader_id, count(*) as read_days, max(r.created_at) as most_recent
    from book_read_events r, lookback l
    where r.created_at >= l.cutoff
    group by r.book_id, r.reader_id
  ),
  per_book as (
    select
      pr.book_id,
      count(distinct pr.reader_id)::integer as distinct_readers,
      sum(pr.read_days)::integer as verified_read_events,
      sum(
        sqrt(pr.read_days) * exp(ln(0.5) * (extract(epoch from (now() - pr.most_recent)) / 86400.0) / (select half_life_days from params))
      ) as decayed_score
    from per_reader pr
    group by pr.book_id
  )
  select
    b.id as book_id, b.title, b.author_id,
    coalesce(p.pen_name, p.display_name, 'A writer') as author_name, b.genre,
    per.distinct_readers, per.verified_read_events,
    round(per.decayed_score, 4) as score
  from per_book per
  join published_books b on b.id = per.book_id
  join profiles p on p.id = b.author_id
  where per.distinct_readers >= (select min_readers from params)
  order by score desc, per.verified_read_events desc, per.book_id
  limit (select result_limit from params);
$$;

revoke all on function compute_most_read(integer) from public;
grant execute on function compute_most_read(integer) to authenticated;

-- Migration 64: Trending — real, short-window buzz, computed server-side. See that migration's
-- own header for why this is deliberately a lighter, faster-decaying signal than the two
-- rankings above, and for how it stays hard to fake despite reading a lower-bar source table.

create table if not exists trending_config (
  id boolean primary key default true check (id),
  lookback_hours integer not null default 72 check (lookback_hours between 1 and 720),
  half_life_hours numeric not null default 18 check (half_life_hours > 0 and half_life_hours <= 720),
  min_distinct_signed_in_viewers integer not null default 2 check (min_distinct_signed_in_viewers >= 0),
  anon_weight numeric not null default 0.15 check (anon_weight >= 0 and anon_weight <= 1),
  result_limit integer not null default 8 check (result_limit between 1 and 100),
  updated_at timestamptz not null default now()
);

insert into trending_config (id) values (true) on conflict (id) do nothing;

alter table trending_config enable row level security;
create policy "moderators read trending config" on trending_config
  for select using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));
create policy "moderators update trending config" on trending_config
  for update using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));

create or replace function compute_trending(p_result_limit integer default null)
returns table (
  book_id text,
  title text,
  author_id uuid,
  author_name text,
  genre text,
  distinct_signed_in_viewers integer,
  view_events integer,
  score numeric
)
language sql
stable
security definer
set search_path = public
as $$
  with cfg as (
    select * from trending_config limit 1
  ),
  params as (
    select
      coalesce((select lookback_hours from cfg), 72)::int as lookback_hours,
      coalesce((select half_life_hours from cfg), 18)::numeric as half_life_hours,
      coalesce((select min_distinct_signed_in_viewers from cfg), 2)::int as min_viewers,
      coalesce((select anon_weight from cfg), 0.15)::numeric as anon_weight,
      greatest(1, least(100, coalesce(p_result_limit, (select result_limit from cfg), 8)))::int as result_limit
  ),
  lookback as (
    select now() - make_interval(hours => (select lookback_hours from params)) as cutoff
  ),
  recent_events as (
    select v.book_id, v.viewer_id, v.created_at, b.author_id as book_author_id
    from book_view_events v, lookback l
    join published_books b on b.id = v.book_id
    where v.created_at >= l.cutoff
      and (v.viewer_id is null or v.viewer_id <> b.author_id)
  ),
  per_signed_in_viewer as (
    select book_id, viewer_id, count(*) as events, max(created_at) as most_recent
    from recent_events
    where viewer_id is not null
    group by book_id, viewer_id
  ),
  signed_in_per_book as (
    select
      book_id,
      count(distinct viewer_id)::integer as distinct_signed_in_viewers,
      sum(events)::integer as signed_in_events,
      sum(
        sqrt(events) * exp(ln(0.5) * (extract(epoch from (now() - most_recent)) / 3600.0) / (select half_life_hours from params))
      ) as signed_in_score
    from per_signed_in_viewer
    group by book_id
  ),
  anon_per_book as (
    select
      book_id,
      count(*)::integer as anon_events,
      sum(
        (select anon_weight from params) * exp(ln(0.5) * (extract(epoch from (now() - created_at)) / 3600.0) / (select half_life_hours from params))
      ) as anon_score
    from recent_events
    where viewer_id is null
    group by book_id
  )
  select
    b.id as book_id, b.title, b.author_id,
    coalesce(p.pen_name, p.display_name, 'A writer') as author_name, b.genre,
    coalesce(s.distinct_signed_in_viewers, 0) as distinct_signed_in_viewers,
    (coalesce(s.signed_in_events, 0) + coalesce(a.anon_events, 0)) as view_events,
    round(coalesce(s.signed_in_score, 0) + coalesce(a.anon_score, 0), 4) as score
  from signed_in_per_book s
  left join anon_per_book a on a.book_id = s.book_id
  join published_books b on b.id = s.book_id
  join profiles p on p.id = b.author_id
  where s.distinct_signed_in_viewers >= (select min_viewers from params)
  order by score desc, view_events desc, b.id
  limit (select result_limit from params);
$$;

revoke all on function compute_trending(integer) from public;
grant execute on function compute_trending(integer) to authenticated;

-- Migration 40: Guilds on the Rise — recent guild momentum, computed server-side, not guild size.
--
-- Living Universe's existing "Guilds on the Rise" section (living-universe-screen.jsx) has, up to
-- now, only ever ranked Founder Guilds by combined participant counts across the on-device Guild
-- Events simulation (see useLuGuildEvents) — flavor, not a real ranking, and Founder Guilds have
-- no real multi-member roster to begin with (see guild-progression.jsx's own honesty note: every
-- *other* member of a Founder Guild is a simulated presence). This migration adds the real thing,
-- scoped to what actually has a real, joinable roster today: Player Guilds
-- (player_guilds/player_guild_members, Phase 5). A new function, compute_guilds_on_rise(), gives
-- any signed-in client a genuine top-N list, computed entirely server-side from real tables, so no
-- client can hand the app a pre-computed score and have it trusted.
--
-- Signals used, all recent-window only (see point 1 below), matching the spec this migration was
-- written against:
--   - New members       -> guild_join_events (new table below)
--   - Reputation growth  -> shown alongside the score (see point 2), reusing computeGuildReputation's
--                          own weights (publishedBook=40, completedProject=10 -- author-reputation.jsx)
--   - Reading activity   -> book_read_events (migration 38), scoped to current members' books
--   - Books published    -> book_publish_events (migration 38), scoped to current members
--   - Event activity     -> guild_quest_events (new table below). Guild Quests are the one *real*,
--                          shared, guild-scoped activity with a live backend signal today -- actual
--                          Guild Events (contests/sprints) are still on-device only (see
--                          useLuGuildEvents), and GUILD_REPUTATION_SOURCES already lists "Writing
--                          Events" as not-yet-tracked honestly. Using quest completions here, under
--                          an "event activity" label, is that same honesty: it's the real thing
--                          this app can currently measure in that category, not a stand-in dressed
--                          up as something it isn't.
--   - Anthology activity -> guild_anthologies + guild_anthology_submissions (migration 35), both
--                          already real, already access-controlled, already timestamped.
--
-- Three design commitments, same shape as migration 38's Rising Star scoring:
--
--   1. RECENT MOMENTUM, NOT GUILD SIZE. Every signal below is filtered to a configurable recent
--      window (default 7 days) and nothing here is a lifetime total or a raw membership count. A
--      guild with hundreds of long-idle members but zero activity this window scores zero and
--      simply doesn't appear -- this function has no lifetime column to fall back on, same as
--      compute_rising_stars().
--
--   2. HARD TO FAKE. Gaming vectors this migration specifically closes:
--        a. Leave/rejoin cycling to keep re-earning "new member" credit -- player_guild_members
--           rows are freely deleted on leave and re-inserted on rejoin (Phase 5), so without a
--           separate ledger a guild could farm "new members" by having the same person leave and
--           rejoin on a loop. guild_join_events below mirrors follow_events' fix exactly: an
--           insert-only ledger with unique (guild_id, user_id), so only the FIRST join a person has
--           ever made to a given guild counts, forever, no matter how many times they leave and
--           come back.
--        b. Spamming self-reads or self-purchases to inflate a member's book's reading activity --
--           already impossible; book_read_events (migration 38) refuses a book's own author a read
--           on their own work, and this function additionally never awards a book's own author
--           credit for reading their own guildmate's book (reader_id <> the book's author_id is
--           already guaranteed upstream, but this migration also never lets an author's OWN reads
--           of their OWN book count here, closing the same loop for the guild-level aggregate).
--        c. Faking quest-completion bursts -- guild_quest_events only ever logs a POSITIVE
--           increase actually written to guild_member_stats.quests_completed, which is itself
--           already bounded by guard_guild_member_stats_delta() (migrations 06/15): a single write
--           can't jump quests_completed by more than that trigger's own ceiling allows. This
--           migration inherits that protection rather than re-implementing it.
--        d. A single-account "guild" gaming its way onto the list -- guilds_on_rise_config.min_members
--           hard-floors eligibility to guilds with at least that many CURRENT members (default 2):
--           a shell guild with one member farming its own signals in isolation is not eligible at
--           all, regardless of score.
--        e. One member spamming anthology submissions, or a burst of publishes from one prolific
--           member, to dominate a guild's ranking alone -- every count-based term uses the same
--           diminishing-returns curve (value * sqrt(count)) as the rest of this app's real anti-farm
--           mechanic (diminishingPoints, author-reputation.jsx), and each raw count is capped before
--           the sqrt is taken (guilds_on_rise_config's max_counted_* columns), same shape as Rising
--           Star's max_counted_publishes_per_window.
--        f. Reading activity specifically also carries Rising Star's own collusion floor: a
--           guild-wide minimum-distinct-recent-readers floor (min_distinct_recent_readers) below
--           which the reading term is hard-zeroed, not just reduced -- a couple of colluding
--           accounts opening a guildmate's book back and forth can't manufacture "reading activity"
--           on their own.
--      Deliberately NOT attempted, same stance migration 39 already took for Best Sellers/Most
--      Read: detecting "this reader is in the same guild as this author" and discounting it. A
--      guild's own readers genuinely reading a guildmate's book is real demand, not gaming --
--      that's the community support Guild Halls exist to encourage.
--
--   3. CONFIGURABLE, SERVER-SIDE. Every window, floor, cap, and weight lives in the new
--      guilds_on_rise_config singleton row, moderator-tunable the same way rising_star_config and
--      book_ranking_config already are -- never hard-coded, never client-supplied.
--
-- ============================================================================================
-- 1. guild_join_events — an insert-only ledger of genuinely NEW guild memberships, separate from
--    the mutable player_guild_members (which reflects only CURRENT membership and is deleted on
--    leave).
-- ============================================================================================

create table if not exists guild_join_events (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  -- The whole anti-cycling guard: only the first join a given person has EVER made to this guild
  -- can ever insert here. See log_guild_join_event() below for the on-conflict-do-nothing that
  -- enforces it.
  unique (guild_id, user_id)
);

alter table guild_join_events enable row level security;
-- Public read, same reasoning as follow_events/book_publish_events -- "who recently joined this
-- guild" isn't sensitive, and this is what a future client-side display could read directly
-- without needing its own RPC.
create policy "anyone can read guild join events" on guild_join_events
  for select using (true);
-- Deliberately no insert policy for authenticated: only the trigger below (security definer)
-- writes here, so a client can't backdate a join or otherwise spoof "new member" without an
-- actual row in player_guild_members having caused it.

create or replace function log_guild_join_event()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into guild_join_events (guild_id, user_id)
  values (new.guild_id, new.user_id)
  on conflict (guild_id, user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists player_guild_members_log_join_event on player_guild_members;
create trigger player_guild_members_log_join_event
  after insert on player_guild_members
  for each row execute function log_guild_join_event();

create index if not exists guild_join_events_guild_idx on guild_join_events (guild_id, created_at desc);

-- ============================================================================================
-- 2. guild_quest_events — an insert-only ledger of genuine, positive increases to
--    guild_member_stats.quests_completed, giving "event activity" (Guild Quests) a real
--    timestamped history that the plain running-total column doesn't carry on its own.
-- ============================================================================================

create table if not exists guild_quest_events (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null,
  user_id uuid not null,
  -- Always > 0 -- see log_guild_quest_event() below, which never logs a non-positive delta.
  delta integer not null check (delta > 0),
  created_at timestamptz not null default now(),
  foreign key (guild_id, user_id) references player_guild_members (guild_id, user_id) on delete cascade
);

alter table guild_quest_events enable row level security;
-- Fellow-member-only read, same trust tier as guild_member_stats itself (the table this is
-- derived from) rather than book_publish_events' public-read shape above -- per-member quest
-- activity is guild-internal the same way guild_member_stats already is.
create policy "guild members read their guild's quest events" on guild_quest_events
  for select using (
    exists (
      select 1 from player_guild_members m
      where m.guild_id = guild_quest_events.guild_id and m.user_id = auth.uid()
    )
  );
-- Deliberately no insert policy for authenticated -- only the trigger below (security definer)
-- writes here, and only ever with a delta that guard_guild_member_stats_delta() has already
-- capped upstream.

create or replace function log_guild_quest_event()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_delta integer;
begin
  v_delta := new.quests_completed - (case when TG_OP = 'UPDATE' then old.quests_completed else 0 end);
  if v_delta > 0 then
    insert into guild_quest_events (guild_id, user_id, delta)
    values (new.guild_id, new.user_id, v_delta);
  end if;
  return new;
end;
$$;

drop trigger if exists guild_member_stats_log_quest_event on guild_member_stats;
create trigger guild_member_stats_log_quest_event
  after insert or update on guild_member_stats
  for each row execute function log_guild_quest_event();

create index if not exists guild_quest_events_guild_idx on guild_quest_events (guild_id, created_at desc);

-- ============================================================================================
-- 3. guilds_on_rise_config — the one moderator-tunable row every window, floor, cap, and weight
--    below is read from. Singleton pattern, same shape as rising_star_config / book_ranking_config.
-- ============================================================================================

create table if not exists guilds_on_rise_config (
  id boolean primary key default true check (id),
  window_days integer not null default 7 check (window_days between 1 and 90),
  min_members integer not null default 2 check (min_members >= 1),
  min_distinct_recent_readers integer not null default 3 check (min_distinct_recent_readers >= 0),
  max_counted_publishes_per_window integer not null default 10 check (max_counted_publishes_per_window between 1 and 200),
  max_counted_quest_events_per_window integer not null default 20 check (max_counted_quest_events_per_window between 1 and 500),
  max_counted_anthology_events_per_window integer not null default 10 check (max_counted_anthology_events_per_window between 1 and 200),
  result_limit integer not null default 6 check (result_limit between 1 and 100),
  weight_new_members numeric not null default 3.0 check (weight_new_members >= 0),
  weight_reading_activity numeric not null default 2.0 check (weight_reading_activity >= 0),
  weight_publishing_activity numeric not null default 3.0 check (weight_publishing_activity >= 0),
  weight_quest_activity numeric not null default 2.0 check (weight_quest_activity >= 0),
  weight_anthology_activity numeric not null default 2.5 check (weight_anthology_activity >= 0),
  updated_at timestamptz not null default now()
);

insert into guilds_on_rise_config (id) values (true) on conflict (id) do nothing;

alter table guilds_on_rise_config enable row level security;
-- Same trust tier as rising_star_config / book_ranking_config -- moderator-only, not publicly
-- readable (the exact floors/caps are part of what makes this hard to game).
create policy "moderators read guilds on rise config" on guilds_on_rise_config
  for select using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));
create policy "moderators update guilds on rise config" on guilds_on_rise_config
  for update using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));

-- ============================================================================================
-- 4. compute_guilds_on_rise() — the score itself. security definer so it can read across every
--    guild's member roster and activity ledgers for aggregation, but it only ever returns
--    per-guild aggregates, never a raw per-member row.
-- ============================================================================================

create or replace function compute_guilds_on_rise(p_window_days integer default null, p_result_limit integer default null)
returns table (
  guild_id uuid,
  guild_name text,
  guild_motto text,
  crest_url text,
  member_count integer,
  new_members integer,
  reading_activity integer,
  books_published integer,
  quest_activity integer,
  anthology_activity integer,
  reputation_growth numeric,
  score numeric
)
language sql
stable
security definer
set search_path = public
as $$
  with cfg as (
    select * from guilds_on_rise_config limit 1
  ),
  params as (
    select
      -- p_window_days/p_result_limit let a caller preview a different window/size, but every
      -- WEIGHT, FLOOR, and CAP below always comes from cfg -- never from an argument.
      greatest(1, least(90, coalesce(p_window_days, (select window_days from cfg), 7)))::int as window_days,
      greatest(1, least(100, coalesce(p_result_limit, (select result_limit from cfg), 6)))::int as result_limit,
      coalesce((select min_members from cfg), 2)::int as min_members,
      coalesce((select min_distinct_recent_readers from cfg), 3)::int as min_readers,
      coalesce((select max_counted_publishes_per_window from cfg), 10)::int as max_pub,
      coalesce((select max_counted_quest_events_per_window from cfg), 20)::int as max_quest,
      coalesce((select max_counted_anthology_events_per_window from cfg), 10)::int as max_anth,
      coalesce((select weight_new_members from cfg), 3.0)::numeric as w_members,
      coalesce((select weight_reading_activity from cfg), 2.0)::numeric as w_reading,
      coalesce((select weight_publishing_activity from cfg), 3.0)::numeric as w_publishing,
      coalesce((select weight_quest_activity from cfg), 2.0)::numeric as w_quest,
      coalesce((select weight_anthology_activity from cfg), 2.5)::numeric as w_anthology
  ),
  windows as (
    select now() - make_interval(days => window_days) as cur_start from params
  ),
  -- Only guilds with a real, current roster at or above the anti-shell-guild floor are eligible
  -- at all -- see this migration's header, gaming vector d.
  eligible_guilds as (
    select g.id as guild_id, g.name, g.motto, g.crest_url, count(m.user_id)::integer as member_count
    from player_guilds g
    join player_guild_members m on m.guild_id = g.id
    group by g.id, g.name, g.motto, g.crest_url
    having count(m.user_id) >= (select min_members from params)
  ),
  joins_cur as (
    select j.guild_id, count(*) as ct
    from guild_join_events j, windows w
    where j.created_at >= w.cur_start
    group by j.guild_id
  ),
  member_books as (
    -- Every currently-published book belonging to a current member of each guild -- a writer in
    -- more than one guild contributes to each, honestly (they're a real member of both).
    select eg.guild_id, b.id as book_id, b.author_id
    from eligible_guilds eg
    join player_guild_members m on m.guild_id = eg.guild_id
    join published_books b on b.author_id = m.user_id
  ),
  reads_cur as (
    select mb.guild_id, count(distinct r.reader_id) as readers
    from member_books mb
    join book_read_events r on r.book_id = mb.book_id
    , windows w
    where r.created_at >= w.cur_start
      -- Never a book's own author reading their own work counted toward their own guild's
      -- reading activity -- book_read_events' insert policy already refuses this at the source,
      -- this is defensive-only at the aggregate layer (this migration's header, gaming vector b).
      and r.reader_id <> mb.author_id
    group by mb.guild_id
  ),
  publishes_cur as (
    select mb.guild_id, count(distinct e.book_id) as ct
    from member_books mb
    join book_publish_events e on e.book_id = mb.book_id
    , windows w
    where e.first_published_at >= w.cur_start
    group by mb.guild_id
  ),
  quests_cur as (
    select q.guild_id, sum(q.delta) as ct
    from guild_quest_events q, windows w
    where q.created_at >= w.cur_start
    group by q.guild_id
  ),
  anthologies_cur as (
    select a.guild_id, count(*) as ct
    from guild_anthologies a, windows w
    where a.created_at >= w.cur_start
    group by a.guild_id
  ),
  submissions_cur as (
    select a.guild_id, count(*) as ct
    from guild_anthology_submissions s
    join guild_anthologies a on a.id = s.anthology_id
    , windows w
    where s.submitted_at >= w.cur_start
    group by a.guild_id
  )
  select
    eg.guild_id, eg.name, eg.motto, eg.crest_url, eg.member_count,
    coalesce(jc.ct, 0)::integer as new_members,
    coalesce(rc.readers, 0)::integer as reading_activity,
    coalesce(pc.ct, 0)::integer as books_published,
    coalesce(qc.ct, 0)::integer as quest_activity,
    (coalesce(ac.ct, 0) + coalesce(sc.ct, 0))::integer as anthology_activity,
    -- Informational only, not summed a second time into `score` below (books_published and
    -- quest_activity already each have their own independently-weighted score term) -- mirrors
    -- what this recent-window activity would be worth under Guild Reputation's own real formula
    -- (computeGuildReputation: publishedBook=40, completedProject=10, author-reputation.jsx),
    -- same "reputation_gained" pattern as compute_rising_stars().
    round(
      (case when coalesce(pc.ct, 0) > 0 then 40.0 * sqrt(least(coalesce(pc.ct, 0), (select max_pub from params))) else 0 end)
      + (case when coalesce(qc.ct, 0) > 0 then 10.0 * sqrt(least(coalesce(qc.ct, 0), (select max_quest from params))) else 0 end)
    , 2) as reputation_growth,
    round(
      (select w_members from params) * (case when coalesce(jc.ct, 0) > 0 then sqrt(coalesce(jc.ct, 0)) else 0 end)
      -- Reading term is floored to zero entirely below min_distinct_recent_readers -- the
      -- anti-collusion guard described in this migration's header, gaming vector f.
      + (case when coalesce(rc.readers, 0) >= (select min_readers from params)
          then (select w_reading from params) * sqrt(coalesce(rc.readers, 0))
          else 0 end)
      + (select w_publishing from params) * sqrt(least(coalesce(pc.ct, 0), (select max_pub from params)))
      + (select w_quest from params) * sqrt(least(coalesce(qc.ct, 0), (select max_quest from params)))
      + (select w_anthology from params) * sqrt(least(coalesce(ac.ct, 0) + coalesce(sc.ct, 0), (select max_anth from params)))
    , 4) as score
  from eligible_guilds eg
  left join joins_cur jc on jc.guild_id = eg.guild_id
  left join reads_cur rc on rc.guild_id = eg.guild_id
  left join publishes_cur pc on pc.guild_id = eg.guild_id
  left join quests_cur qc on qc.guild_id = eg.guild_id
  left join anthologies_cur ac on ac.guild_id = eg.guild_id
  left join submissions_cur sc on sc.guild_id = eg.guild_id
  -- No recent signal of any kind at all -- not "on the rise" this window, full stop, rather than
  -- a 0-score row cluttering the result (same convention as compute_rising_stars()).
  where coalesce(jc.ct, 0) + coalesce(rc.readers, 0) + coalesce(pc.ct, 0) + coalesce(qc.ct, 0) + coalesce(ac.ct, 0) + coalesce(sc.ct, 0) > 0
  order by score desc, eg.guild_id
  limit (select result_limit from params);
$$;

revoke all on function compute_guilds_on_rise(integer, integer) from public;
grant execute on function compute_guilds_on_rise(integer, integer) to authenticated;


-- ============================================================================================
-- Migration 41: Guild Member Earnings — the withdrawal half of the Guild Treasury's 'member'
-- bucket (see the Guild Treasury and Guild Revenue Distribution migrations above). Until now a
-- member could see their held earnings total via guild_treasury_summary() (member_earnings_
-- mine_kobo) but had no way to ever get that money out — 'release_to_member' was reserved in
-- the original kind check constraint but nothing wrote one. This is what writes it.
--
-- Design choice: releasing earnings is a two-step handoff, not a new payout pipeline of its own.
--   1. withdraw_guild_member_earnings() below moves kobo out of a member's held-in-trust balance
--      in ONE guild's treasury and into their own, already-existing, cross-guild withdrawable
--      balance (author_balance_kobo) — instantly and synchronously, the same way
--      contribute_to_guild_treasury() moves it the other direction. This is pure bookkeeping: no
--      bank, no Paystack call, nothing that can fail asynchronously, so it's safe to record as a
--      single 'success' ledger row exactly like every other synchronous write this table
--      already has.
--   2. Actually paying it out to a bank account reuses paystack-withdraw / the withdrawals table
--      completely unchanged — the same pipeline every ordinary book-sale withdrawal already
--      goes through. This is deliberate: withdrawals already has its own correct
--      pending -> success/failed lifecycle via a mutable row + the Paystack webhook, which
--      guild_treasury_transactions can no longer support for a new row now that it's append-only
--      (see the Guild Treasury Ledger Hardening migration's own comment on why an async
--      settlement needs a new row, not an update). Building a second, parallel
--      pending/success/failed payout pipeline just for guild-sourced kobo would duplicate that
--      entire lifecycle for no real benefit — once released, a Naira is a Naira, indistinguishable
--      from one earned by a solo book sale.
--
-- "Verified available earnings" (what a member may actually withdraw) means settled
-- (status = 'success') member-bucket credits, minus anything already released or in flight —
-- never a still-pending credit. See guild_treasury_member_earnings_mine_kobo below.
--
-- Never allows withdrawing another member's funds: every balance this migration checks is
-- derived from auth.uid() alone, server-side, inside a security definer function — there is no
-- argument a client can pass to check or move a balance belonging to anyone else. Same posture
-- every other write in this table already takes.

-- ============================================================================================
-- Balances — "mine, in this one guild" versions of the existing guild-wide member-earnings
-- queries, scoped to auth.uid() the same way guild_treasury_summary()'s existing
-- member_earnings_mine_kobo field already computes inline. Pulled into their own functions here
-- so withdraw_guild_member_earnings() and guild_member_earnings_summary() both use the exact
-- same definition rather than two copies of the same query drifting apart.
-- ============================================================================================

-- Available: settled credits minus anything already released or in flight — what's actually
-- withdrawable right now. Same shape as guild_treasury_member_earnings_kobo(), just scoped to
-- the caller instead of every member of the guild combined.
create or replace function guild_treasury_member_earnings_mine_kobo(p_guild_id uuid)
returns bigint as $$
  select
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid()
                and direction = 'credit' and status = 'success'), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid()
                and direction = 'debit' and status in ('pending', 'success')), 0);
$$ language sql stable security definer set search_path = public;

-- Pending: the caller's own member-bucket rows in this guild still waiting on settlement —
-- mirrors guild_treasury_pending_kobo()'s "any status = 'pending' row counts, regardless of
-- direction" convention, just scoped to one member instead of the whole guild.
create or replace function guild_treasury_member_pending_kobo(p_guild_id uuid)
returns bigint as $$
  select coalesce(sum(amount_kobo), 0) from guild_treasury_transactions
  where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid() and status = 'pending';
$$ language sql stable security definer set search_path = public;

-- Lifetime: every kobo this member has ever been credited in this guild's treasury, gross —
-- never reduced by a later release. "Lifetime earnings" means what was earned, not what's still
-- held.
create or replace function guild_treasury_member_lifetime_kobo(p_guild_id uuid)
returns bigint as $$
  select coalesce(sum(amount_kobo), 0) from guild_treasury_transactions
  where guild_id = p_guild_id and bucket = 'member' and member_id = auth.uid()
    and direction = 'credit' and status = 'success';
$$ language sql stable security definer set search_path = public;

-- One round trip for the Member Earnings panel — same "bundle everything one screen needs into
-- one RPC" shape as guild_treasury_summary() above.
create or replace function guild_member_earnings_summary(p_guild_id uuid)
returns table (
  available_kobo bigint,
  pending_kobo bigint,
  lifetime_kobo bigint
)
language plpgsql security definer set search_path = public as $$
begin
  if not is_guild_member(p_guild_id) then
    raise exception 'Not a member of this guild.';
  end if;
  return query select
    guild_treasury_member_earnings_mine_kobo(p_guild_id),
    guild_treasury_member_pending_kobo(p_guild_id),
    guild_treasury_member_lifetime_kobo(p_guild_id);
end;
$$;

revoke all on function guild_treasury_member_earnings_mine_kobo(uuid) from public;
revoke all on function guild_treasury_member_pending_kobo(uuid) from public;
revoke all on function guild_treasury_member_lifetime_kobo(uuid) from public;
revoke all on function guild_member_earnings_summary(uuid) from public;
grant execute on function guild_treasury_member_earnings_mine_kobo(uuid) to authenticated;
grant execute on function guild_treasury_member_pending_kobo(uuid) to authenticated;
grant execute on function guild_treasury_member_lifetime_kobo(uuid) to authenticated;
grant execute on function guild_member_earnings_summary(uuid) to authenticated;

-- ============================================================================================
-- withdraw_guild_member_earnings — releases part of the caller's own held-in-trust earnings in
-- one guild's treasury into their own author_balance_kobo (see the migration header above for
-- why this is a release, not a direct bank payout). Same idempotency-key shape as
-- contribute_to_guild_treasury()/spend_from_guild_treasury(): if p_idempotency_key is supplied,
-- a matching row is looked up first and returned as-is on any retry, never moving the kobo
-- twice.
-- ============================================================================================

create or replace function withdraw_guild_member_earnings(
  p_guild_id uuid, p_amount_kobo bigint, p_idempotency_key text default null
)
returns guild_treasury_transactions
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_treasury_transactions;
begin
  if p_idempotency_key is not null then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
    if found then
      return v_row;
    end if;
  end if;

  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not is_guild_member(p_guild_id) then
    raise exception 'Not a member of this guild.';
  end if;
  -- Same lock key contribute_to_guild_treasury() uses (keyed to the writer, not the guild) —
  -- deliberately serializes with a concurrent contribution too, since both read and act on this
  -- same writer's balances.
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text));
  if guild_treasury_member_earnings_mine_kobo(p_guild_id) < p_amount_kobo then
    raise exception 'That would exceed your verified available earnings in this guild.';
  end if;

  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     status, title, created_by, idempotency_key)
  values
    (p_guild_id, 'member', auth.uid(), 'debit', 'release_to_member', p_amount_kobo, 'NGN',
     'member_earnings_held', 'member_balance', 'success', 'Released to your withdrawable balance',
     auth.uid(), p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_row;

  if not found then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
  end if;
  return v_row;
end;
$$;

revoke all on function withdraw_guild_member_earnings(uuid, bigint, text) from public;
grant execute on function withdraw_guild_member_earnings(uuid, bigint, text) to authenticated;

-- ============================================================================================
-- author_balance_kobo — extended once more (same function, same signature, still the one place
-- a writer's withdrawable balance is computed) to add back in any earnings they've released
-- from a guild treasury via withdraw_guild_member_earnings() above. Without this, a release
-- would move the kobo out of member_earnings_kobo but into nowhere — not lost, since the ledger
-- row exists, but not withdrawable from anywhere either.
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(p.author_amount_kobo) from purchases p
              where p.author_id = check_user_id and p.status = 'success'
                and not exists (
                  select 1 from guild_anthologies a where a.published_book_id = p.book_id
                )), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0)
    +
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where member_id = check_user_id and kind = 'release_to_member' and status = 'success'), 0);
$$ language sql stable security definer set search_path = public;

revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- Safe to run anytime: every function above is created with or-replace,
-- withdraw_guild_member_earnings is a new function nothing previously called, and
-- author_balance_kobo's added term is 0 for every writer who has never released guild-held
-- earnings — this doesn't change any existing balance on deployment.


-- ============================================================================================
-- Migration 42: Guild Events — the second real revenue source the Guild Treasury's generic
-- distribute_guild_revenue() engine (see the Guild Revenue Distribution migration) was always
-- built to support via its reserved kind='event_revenue'/source='event_sale' vocabulary. Two
-- funding shapes, both landing in the same place once verified:
--   - host = 'guild': the guild itself hosts a competition with a real entry fee. Anyone signed
--     in can pay to enter (guild_event_entries, a small purchases-shaped table with its own
--     Paystack reference and the exact same pending -> success/failed webhook lifecycle
--     `purchases` already has). Inkroot's platform fee (PLATFORM_FEE_BPS, same constant and same
--     formula as an ordinary book sale) is applied per entry as it's paid, not at settlement, so
--     a later fee-schedule change never reclassifies an already-paid entry.
--   - host = 'inkroot': Inkroot itself funds a cash prize for a guild's members directly — no
--     entry fee, no reader payment, so no platform fee applies (Inkroot isn't taking a cut of its
--     own money). Only ever created and settled by Inkroot directly (there's no admin role or
--     admin UI in this app to gate it behind, so this is enforced the only way that's actually
--     true today: create_guild_event()/settle_guild_event() both refuse to act on a host='inkroot'
--     row for any caller with a real auth.uid() — i.e. any signed-in app user — leaving only a
--     direct service-role/SQL action, run by Inkroot outside the app, able to do it).
--
-- Either way, "settling" an event is the one moment real money moves: the guild owner (or,
-- for an Inkroot-hosted prize, Inkroot itself) declares winner shares among that guild's own
-- members, and settle_guild_event() computes the verified pool (summed successful entry fees,
-- net of the platform fee already applied per entry; or the fixed cash prize) and hands it to
-- distribute_guild_revenue() — the exact same engine, same rounding, same permanent-ledger
-- guarantee an Anthology sale already goes through. "Credit each member's earnings" + "credit
-- the guild's share" + "record every transaction in the ledger" all happen inside that one
-- shared function, not duplicated here.
--
-- Duplicate-processing protection, layered the same way the Anthology wiring documents it:
--   a. guild_events.status only ever moves open -> closed -> settled (or open -> settled), and
--      settle_guild_event() re-checks that status under an advisory lock keyed to the event
--      before doing anything, so two concurrent settle calls can't both pass.
--   b. distribute_guild_revenue() itself (modified below to accept an event, not just a
--      purchase, as its dedup key) independently checks whether any ledger row already
--      references this event before writing anything — belt-and-suspenders even if (a) were
--      ever bypassed.
--   c. Each entry fee payment has its own paystack_reference-scoped, `.eq('status','pending')`
--      webhook update, same as a purchases row — a retried Paystack webhook event can't mark
--      (or pay for) the same entry twice.
--   d. A person can enter a given guild-hosted event at most once (unique (event_id,
--      entrant_id)) — a deliberate scope choice (one ticket per person), not a technical
--      limitation of the underlying tables.
--
-- Winners must be real members of the guild whose event this is — settle_guild_event() checks
-- every declared contributor_id against player_guild_members before distributing anything,
-- same "never trust a client-supplied id" posture as everywhere else in this ledger.

-- ============================================================================================
-- 1. guild_events — one row per competition, either kind.
-- ============================================================================================

create table if not exists guild_events (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  host text not null check (host in ('inkroot', 'guild')),
  title text not null check (char_length(title) <= 200),
  -- Exactly one funding amount is set, matching which host this is: a guild-hosted event's pot
  -- is whatever verified entry fees actually come in (not fixed up front), while an
  -- Inkroot-hosted prize is a fixed amount Inkroot is granting outright.
  entry_fee_kobo bigint check (entry_fee_kobo > 0),
  cash_prize_kobo bigint check (cash_prize_kobo > 0),
  check (
    (host = 'guild' and entry_fee_kobo is not null and cash_prize_kobo is null) or
    (host = 'inkroot' and cash_prize_kobo is not null and entry_fee_kobo is null)
  ),
  status text not null default 'open' check (status in ('open', 'closed', 'settled')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  settled_at timestamptz
);

alter table guild_events enable row level security;

-- Same "publicly browsable" posture as published_books — anyone signed in can see an event
-- (including non-members, since a guild-hosted event's entry fee is open to any reader, exactly
-- like an anthology's book is open to any buyer) and decide whether to enter.
create policy "anyone can read guild events" on guild_events
  for select using (true);
-- No client insert/update policy: every write goes through create_guild_event()/
-- close_guild_event()/settle_guild_event() below, which re-check ownership and host server-side.

create index if not exists guild_events_guild_id_idx on guild_events (guild_id, created_at desc);
create index if not exists guild_events_status_idx on guild_events (status) where status = 'open';

-- ============================================================================================
-- 2. guild_event_entries — one row per paid (or attempted) entry into a host='guild' event.
-- Same shape and lifecycle as `purchases`: created pending by paystack-init-event-entry, only
-- ever flipped to success/failed by paystack-webhook once Paystack itself confirms the charge.
-- ============================================================================================

create table if not exists guild_event_entries (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references guild_events(id) on delete cascade,
  entrant_id uuid not null references auth.users(id) on delete cascade,
  paystack_reference text not null unique,
  amount_kobo bigint not null check (amount_kobo > 0),      -- what the entrant paid
  net_kobo bigint not null check (net_kobo >= 0),            -- after Inkroot's platform fee — this is what counts toward the event's pool at settlement
  status text not null default 'pending' check (status in ('pending', 'success', 'failed')),
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  unique (event_id, entrant_id)
);

alter table guild_event_entries enable row level security;

create policy "entrant reads their own event entries" on guild_event_entries
  for select using (auth.uid() = entrant_id);
create policy "guild owner reads entries for their own events" on guild_event_entries
  for select using (
    exists (
      select 1 from guild_events e
      where e.id = guild_event_entries.event_id and is_guild_officer(e.guild_id)
    )
  );
-- No client insert/update policy — see purchases' own comment; the same reasoning applies here:
-- only paystack-init-event-entry (pending) and paystack-webhook (success/failed), both
-- service_role, ever write this table.

create index if not exists guild_event_entries_event_id_status_idx
  on guild_event_entries (event_id, status);

-- ============================================================================================
-- 3. project_event_id finally gets its foreign key — see its original comment in
-- guild_treasury_transactions ("no FK yet ... add one once they do"). Safe to add now: no caller
-- anywhere in the app has ever passed a real value for it (contribute_to_guild_treasury/
-- spend_from_guild_treasury's own p_project_event_id has always defaulted to null in every
-- existing call site), so there is no existing row this constraint could possibly reject.
-- ============================================================================================

alter table guild_treasury_transactions
  add constraint guild_treasury_transactions_project_event_id_fkey
  foreign key (project_event_id) references guild_events(id) on delete set null;

-- ============================================================================================
-- 4. distribute_guild_revenue — extended to accept an event, not just a purchase, as its dedup
-- key. p_source_purchase_id becomes optional; exactly one of it or p_project_event_id must be
-- given (whichever the caller actually has). Every existing call site (the Anthology trigger)
-- still passes p_source_purchase_id and is completely unaffected — this only adds a second,
-- equally-enforced path for a source that was never a single purchase to begin with.
-- ============================================================================================

create or replace function distribute_guild_revenue(
  p_guild_id uuid,
  p_gross_amount_kobo bigint,
  p_shares jsonb,
  p_kind text,
  p_source text,
  p_source_purchase_id uuid default null,
  p_anthology_id uuid default null,
  p_project_event_id uuid default null,
  p_title text default null
)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_dedup_key text;
  v_already_processed boolean;
  v_shares_sum integer;
  v_member_credited bigint;
  v_guild_share bigint;
begin
  if p_gross_amount_kobo is null or p_gross_amount_kobo <= 0 then
    return; -- nothing to distribute
  end if;
  if p_source_purchase_id is null and p_project_event_id is null then
    raise exception 'A source purchase or a guild event id is required — every distribution must trace back to one verified source.';
  end if;

  -- Locked to this specific source (one purchase, or one event's settlement), not the whole
  -- guild, so unrelated distributions for the same guild never block on each other.
  v_dedup_key := coalesce(p_source_purchase_id::text, p_project_event_id::text);
  perform pg_advisory_xact_lock(hashtext('guild_revenue_distribution:' || v_dedup_key));

  if p_source_purchase_id is not null then
    select exists(
      select 1 from guild_treasury_transactions where source_purchase_id = p_source_purchase_id
    ) into v_already_processed;
  else
    select exists(
      select 1 from guild_treasury_transactions where project_event_id = p_project_event_id
    ) into v_already_processed;
  end if;
  if v_already_processed then
    return; -- this exact source has already been distributed — never pay it out twice
  end if;

  select coalesce(sum((s->>'share_bps')::integer), 0) into v_shares_sum
  from jsonb_array_elements(p_shares) s;
  if v_shares_sum < 0 or v_shares_sum > 10000 then
    raise exception 'Contributor shares must add up to no more than 100%% of the sale.';
  end if;

  -- Largest-remainder distribution, same method propose_anthology_revenue_agreement's
  -- 'contribution' split already uses: floor everyone first, then hand the leftover kobo (at
  -- most one per contributor) to whoever was closest to rounding up. Guarantees every member
  -- credit plus the guild's own share sums to exactly p_gross_amount_kobo — no kobo invented or
  -- lost to rounding.
  with shares as (
    select (s->>'contributor_id')::uuid as contributor_id, (s->>'share_bps')::integer as share_bps
    from jsonb_array_elements(p_shares) s
    where (s->>'share_bps')::integer > 0
  ),
  amounts as (
    select contributor_id, share_bps,
      floor(p_gross_amount_kobo * share_bps::numeric / 10000)::bigint as base,
      (p_gross_amount_kobo * share_bps::numeric / 10000) - floor(p_gross_amount_kobo * share_bps::numeric / 10000) as frac
    from shares
  ),
  total_base as (
    select coalesce(sum(base), 0)::bigint as sum_base from amounts
  ),
  ranked as (
    select a.contributor_id, a.base, a.frac,
           row_number() over (order by a.frac desc, a.contributor_id) as rn,
           (p_gross_amount_kobo - t.sum_base) as leftover
    from amounts a cross join total_base t
  ),
  -- Capturing exactly what this statement just inserted (via RETURNING), rather than a second,
  -- separate SELECT keyed off source_purchase_id/project_event_id, sidesteps ever having to
  -- write a WHERE clause that means "whichever dedup key this call used" twice in one function —
  -- one place to get right instead of two that could drift apart.
  inserted as (
    insert into guild_treasury_transactions
      (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
       project_event_id, status, title, source_purchase_id, anthology_id)
    select p_guild_id, 'member', contributor_id, 'credit', p_kind,
           base + case when rn <= leftover then 1 else 0 end, 'NGN', p_source, 'member_earnings_held',
           p_project_event_id, 'success', p_title, p_source_purchase_id, p_anthology_id
    from ranked
    where base + case when rn <= leftover then 1 else 0 end > 0
    returning amount_kobo
  )
  select coalesce(sum(amount_kobo), 0) into v_member_credited from inserted;

  v_guild_share := p_gross_amount_kobo - v_member_credited;
  if v_guild_share > 0 then
    insert into guild_treasury_transactions
      (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
       project_event_id, status, title, source_purchase_id, anthology_id)
    values
      (p_guild_id, 'guild', null, 'credit', p_kind, v_guild_share, 'NGN', p_source, 'guild_treasury',
       p_project_event_id, 'success', p_title, p_source_purchase_id, p_anthology_id);
  end if;
end;
$$;

revoke all on function distribute_guild_revenue(uuid, bigint, jsonb, text, text, uuid, uuid, uuid, text) from public;

-- ============================================================================================
-- 5. create_guild_event / close_guild_event — guild-owner tools for the host='guild' path only.
-- An Inkroot-hosted row is never created through this (or any) authenticated-callable function —
-- see the migration header above.
-- ============================================================================================

create or replace function create_guild_event(
  p_guild_id uuid, p_title text, p_host text,
  p_entry_fee_kobo bigint default null, p_cash_prize_kobo bigint default null
)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_events;
begin
  if p_host is distinct from 'guild' then
    raise exception 'Inkroot-hosted events are created by Inkroot directly.';
  end if;
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can host a guild event.';
  end if;
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'Give the event a title.';
  end if;
  if p_entry_fee_kobo is null or p_entry_fee_kobo <= 0 then
    raise exception 'A guild-hosted event needs a positive entry fee.';
  end if;
  if p_cash_prize_kobo is not null then
    raise exception 'A guild-hosted event funds its own prize from entry fees — it has no separate cash prize.';
  end if;

  insert into guild_events (guild_id, host, title, entry_fee_kobo, created_by)
  values (p_guild_id, 'guild', trim(p_title), p_entry_fee_kobo, auth.uid())
  returning * into v_row;
  return v_row;
end;
$$;

create or replace function close_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_events;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can close entries for this event.';
  end if;
  update guild_events set status = 'closed'
  where id = p_event_id and guild_id = p_guild_id and status = 'open'
  returning * into v_row;
  if not found then
    raise exception 'Event not found, not yours, or not open.';
  end if;
  return v_row;
end;
$$;

revoke all on function create_guild_event(uuid, text, text, bigint, bigint) from public;
revoke all on function close_guild_event(uuid, uuid) from public;
grant execute on function create_guild_event(uuid, text, text, bigint, bigint) to authenticated;
grant execute on function close_guild_event(uuid, uuid) to authenticated;

-- ============================================================================================
-- 6. settle_guild_event — the one moment real money moves for either host. See the migration
-- header for the full authorization/dedup story.
-- ============================================================================================

create or replace function settle_guild_event(p_guild_id uuid, p_event_id uuid, p_shares jsonb)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_gross bigint;
  v_bad_contributor uuid;
begin
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;

  if v_event.host = 'guild' then
    if not is_guild_officer(p_guild_id) then
      raise exception 'Only the guild owner can settle this event.';
    end if;
  else -- 'inkroot'
    if auth.uid() is not null then
      raise exception 'Inkroot-hosted events are settled by Inkroot directly.';
    end if;
  end if;

  -- One settlement per event, ever — locked to the event itself so two concurrent settle
  -- attempts can't both pass the status check below.
  perform pg_advisory_xact_lock(hashtext('guild_event_settlement:' || p_event_id::text));
  select * into v_event from guild_events where id = p_event_id; -- re-read under the lock
  if v_event.status = 'settled' then
    raise exception 'This event has already been settled.';
  end if;

  -- Every declared winner must be an actual member of this guild — never trust a
  -- client-supplied id, same posture as every other write in this ledger.
  select (s->>'contributor_id')::uuid into v_bad_contributor
  from jsonb_array_elements(p_shares) s
  where not exists (
    select 1 from player_guild_members m
    where m.guild_id = p_guild_id and m.user_id = (s->>'contributor_id')::uuid
  )
  limit 1;
  if v_bad_contributor is not null then
    raise exception 'Every winner must be a member of this guild.';
  end if;

  if v_event.host = 'guild' then
    -- The verified pool: every successfully-paid entry's already-fee-applied net amount. Never
    -- amount_kobo (that's what the entrant paid, before Inkroot's cut).
    select coalesce(sum(net_kobo), 0) into v_gross
    from guild_event_entries where event_id = p_event_id and status = 'success';
  else
    v_gross := v_event.cash_prize_kobo; -- fixed, no fee — see migration header
  end if;

  perform distribute_guild_revenue(
    p_guild_id := p_guild_id,
    p_gross_amount_kobo := v_gross,
    p_shares := p_shares,
    p_kind := 'event_revenue',
    p_source := 'event_sale',
    p_source_purchase_id := null,
    p_anthology_id := null,
    p_project_event_id := p_event_id,
    p_title := 'Guild event \u2014 ' || v_event.title
  );

  update guild_events set status = 'settled', settled_at = now() where id = p_event_id;
  select * into v_event from guild_events where id = p_event_id;
  return v_event;
end;
$$;

revoke all on function settle_guild_event(uuid, uuid, jsonb) from public;
grant execute on function settle_guild_event(uuid, uuid, jsonb) to authenticated;

-- Safe to run anytime: every new table starts empty, the FK on project_event_id has nothing
-- existing to reject (see its own comment above), and distribute_guild_revenue's extended
-- dedup logic is exercised identically to before for every existing (purchase-sourced) caller.


-- ============================================================================================
-- Migration 43: Inkroot Admin — Guild Events. Adds the actual admin surface for the
-- host='inkroot' half of 42_migration_guild_events.sql, which until now had no client-callable
-- path at all (by design, at the time — see that migration's header): create_guild_event() and
-- settle_guild_event() both flatly refused to act on a host='inkroot' row for any signed-in
-- caller, leaving only a direct service-role/SQL action outside the app.
--
-- This migration gives Inkroot's own staff an in-app way to do that, gated by a new, narrowly-
-- scoped trust flag rather than reusing profiles.is_moderator. Deliberately a separate column:
-- is_moderator already means "can read reports and ban accounts" (see the Trust & Safety
-- migration's own comment on that column) — a content moderator authorizing a real cash payout
-- is a different trust domain, and conflating the two would silently hand payout authority to
-- every existing moderator the day this migration runs. is_platform_admin gets the exact same
-- lockdown profiles.is_moderator already has: settable only by service_role (see
-- protect_admin_profile_columns below, extended in place), never self-grantable, never grantable
-- by another admin through the app.
--
-- is_inkroot_admin() (the actual authorization check create_guild_event/settle_guild_event now
-- use for the host='inkroot' path) also still accepts a null auth.uid() — i.e. a genuine
-- service-role/direct-SQL call with no user session at all — so the original "Inkroot ops runs
-- this directly against the database" path from the Guild Events migration still works
-- unchanged; this migration only adds a second, in-app path alongside it, not a replacement.
-- ============================================================================================

alter table profiles add column if not exists is_platform_admin boolean not null default false;

-- Redefined in place (same function, extended) rather than a second trigger, so there is still
-- exactly one place that decides what a moderator-acting-on-someone-else's-row vs an
-- ordinary-user-acting-on-their-own-row is allowed to touch — see the Trust & Safety migration's
-- own comment on why this needs to be one trigger, not several independently-reasoned ones.
create or replace function protect_admin_profile_columns()
returns trigger as $$
declare
  acting_is_moderator boolean;
begin
  if coalesce(auth.role(), '') = 'service_role' then
    return new;
  end if;
  if coalesce(current_setting('inkroot.trusted_admin_rpc', true), '') = 'true' then
    return new;
  end if;
  if new.is_moderator is distinct from old.is_moderator then
    new.is_moderator := old.is_moderator;
  end if;
  -- Same treatment as is_moderator immediately above: locked to service_role in every path,
  -- full stop, including a platform admin acting on someone else's row — an admin can't mint
  -- another admin any more than a moderator can mint another moderator.
  if new.is_platform_admin is distinct from old.is_platform_admin then
    new.is_platform_admin := old.is_platform_admin;
  end if;
  if new.login_banned is distinct from old.login_banned then
    new.login_banned := old.login_banned;
  end if;
  if new.login_ban_reason is distinct from old.login_ban_reason then
    new.login_ban_reason := old.login_ban_reason;
  end if;
  select p.is_moderator into acting_is_moderator from profiles p where p.id = auth.uid();
  if coalesce(acting_is_moderator, false) and auth.uid() <> old.id then
    new.pen_name := old.pen_name;
    new.display_name := old.display_name;
    new.avatar_url := old.avatar_url;
  else
    new.banned := old.banned;
    new.ban_reason := old.ban_reason;
    new.verified := old.verified;
  end if;
  return new;
end;
$$ language plpgsql security definer;
-- No need to re-create the trigger itself — protect_admin_profile_columns_trigger already calls
-- this function by name, so the redefinition above takes effect immediately.

-- The one authorization check both create_guild_event() and settle_guild_event() use for their
-- host='inkroot' branch. True for a genuine platform admin, OR for a call with no user session
-- at all (auth.uid() is null) — a direct service-role/SQL action, e.g. Inkroot ops working
-- straight from the Supabase SQL editor rather than through the app.
create or replace function is_inkroot_admin()
returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is null or exists (
    select 1 from profiles where id = auth.uid() and is_platform_admin
  );
$$;

revoke all on function is_inkroot_admin() from public;
grant execute on function is_inkroot_admin() to authenticated;

-- ============================================================================================
-- admin_list_guilds — lets a platform admin find a guild to host a cash-prize event for.
-- player_guilds' own select policy is scoped to a guild's owner/members only (see its
-- migration's comment on why — protecting invite_code), so an admin who isn't a member of every
-- guild couldn't otherwise browse them to pick one. This is a narrow, read-only bypass of that
-- restriction, gated the same way every other admin action here is, and never returns
-- invite_code (same "never leak the invite code outside the owner/member policy" posture
-- join_player_guild_by_code() already takes).
-- ============================================================================================

create or replace function admin_list_guilds(p_search text default null)
returns table (id uuid, name text, owner_id uuid, member_count bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can browse every guild.';
  end if;
  return query
    select g.id, g.name, g.owner_id,
           -- A Founder Guild's real roster lives in founder_guild_members (keyed by
           -- founder_slug), not player_guild_members — see 69_migration_founder_guild_parity.sql.
           case when g.is_founder_guild
             then (select count(*) from founder_guild_members m where m.guild_id = g.founder_slug)
             else (select count(*) from player_guild_members m where m.guild_id = g.id)
           end as member_count
    from player_guilds g
    where p_search is null or p_search = '' or g.name ilike '%' || p_search || '%'
    order by g.name
    limit 50;
end;
$$;

revoke all on function admin_list_guilds(text) from public;
grant execute on function admin_list_guilds(text) to authenticated;

-- ============================================================================================
-- create_guild_event — rewritten to branch on host instead of flatly refusing 'inkroot'.
-- host='guild' keeps its exact original behavior (owner-only, positive entry fee, no cash
-- prize). host='inkroot' is new: gated by is_inkroot_admin() instead of guild ownership (an
-- Inkroot-funded prize isn't the guild owner's money to authorize), requires a positive cash
-- prize and no entry fee, and — unlike a guild-hosted event — can target any guild that exists,
-- not just one the caller owns.
-- ============================================================================================

create or replace function create_guild_event(
  p_guild_id uuid, p_title text, p_host text,
  p_entry_fee_kobo bigint default null, p_cash_prize_kobo bigint default null
)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_events;
begin
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'Give the event a title.';
  end if;

  if p_host = 'inkroot' then
    if not is_inkroot_admin() then
      raise exception 'Only an Inkroot admin can host a cash-prize event.';
    end if;
    if p_cash_prize_kobo is null or p_cash_prize_kobo <= 0 then
      raise exception 'An Inkroot-hosted event needs a positive cash prize.';
    end if;
    if p_entry_fee_kobo is not null then
      raise exception 'An Inkroot-hosted event has no entry fee \u2014 it''s funded directly.';
    end if;
    if not exists (select 1 from player_guilds g where g.id = p_guild_id) then
      raise exception 'Guild not found.';
    end if;
    insert into guild_events (guild_id, host, title, cash_prize_kobo, created_by)
    values (p_guild_id, 'inkroot', trim(p_title), p_cash_prize_kobo, auth.uid())
    returning * into v_row;
    return v_row;
  elsif p_host = 'guild' then
    if not is_guild_officer(p_guild_id) then
      raise exception 'Only the guild owner can host a guild event.';
    end if;
    if p_entry_fee_kobo is null or p_entry_fee_kobo <= 0 then
      raise exception 'A guild-hosted event needs a positive entry fee.';
    end if;
    if p_cash_prize_kobo is not null then
      raise exception 'A guild-hosted event funds its own prize from entry fees \u2014 it has no separate cash prize.';
    end if;
    insert into guild_events (guild_id, host, title, entry_fee_kobo, created_by)
    values (p_guild_id, 'guild', trim(p_title), p_entry_fee_kobo, auth.uid())
    returning * into v_row;
    return v_row;
  else
    raise exception 'Unknown event host.';
  end if;
end;
$$;

revoke all on function create_guild_event(uuid, text, text, bigint, bigint) from public;
grant execute on function create_guild_event(uuid, text, text, bigint, bigint) to authenticated;

-- ============================================================================================
-- settle_guild_event — only its host='inkroot' authorization branch changes: was "reject any
-- signed-in caller", now "accept a platform admin (or, unchanged, a call with no user session at
-- all)". The host='guild' branch, the advisory lock, the settled-status guard, the
-- every-winner-must-be-a-member check, and the distribute_guild_revenue() call are all identical
-- to the Guild Events migration's original version.
-- ============================================================================================

create or replace function settle_guild_event(p_guild_id uuid, p_event_id uuid, p_shares jsonb)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_gross bigint;
  v_bad_contributor uuid;
begin
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;

  if v_event.host = 'guild' then
    if not is_guild_officer(p_guild_id) then
      raise exception 'Only the guild owner can settle this event.';
    end if;
  else -- 'inkroot'
    if not is_inkroot_admin() then
      raise exception 'Only an Inkroot admin can settle a cash-prize event.';
    end if;
  end if;

  perform pg_advisory_xact_lock(hashtext('guild_event_settlement:' || p_event_id::text));
  select * into v_event from guild_events where id = p_event_id; -- re-read under the lock
  if v_event.status = 'settled' then
    raise exception 'This event has already been settled.';
  end if;

  select (s->>'contributor_id')::uuid into v_bad_contributor
  from jsonb_array_elements(p_shares) s
  where not exists (
    select 1 from player_guild_members m
    where m.guild_id = p_guild_id and m.user_id = (s->>'contributor_id')::uuid
  )
  limit 1;
  if v_bad_contributor is not null then
    raise exception 'Every winner must be a member of this guild.';
  end if;

  if v_event.host = 'guild' then
    select coalesce(sum(net_kobo), 0) into v_gross
    from guild_event_entries where event_id = p_event_id and status = 'success';
  else
    v_gross := v_event.cash_prize_kobo;
  end if;

  perform distribute_guild_revenue(
    p_guild_id := p_guild_id,
    p_gross_amount_kobo := v_gross,
    p_shares := p_shares,
    p_kind := 'event_revenue',
    p_source := 'event_sale',
    p_source_purchase_id := null,
    p_anthology_id := null,
    p_project_event_id := p_event_id,
    p_title := 'Guild event \u2014 ' || v_event.title
  );

  update guild_events set status = 'settled', settled_at = now() where id = p_event_id;
  select * into v_event from guild_events where id = p_event_id;
  return v_event;
end;
$$;

revoke all on function settle_guild_event(uuid, uuid, jsonb) from public;
grant execute on function settle_guild_event(uuid, uuid, jsonb) to authenticated;

-- Safe to run anytime: is_platform_admin defaults to false for every existing profile (nobody
-- gains admin access on deployment), create_guild_event/settle_guild_event's host='guild'
-- branches are byte-for-byte the same logic as before, and is_inkroot_admin() still accepts a
-- null auth.uid() exactly as the original inline checks did, so the pre-existing
-- direct-service-role path is unaffected. Flip is_platform_admin on for a real staff account
-- the same way is_moderator is flipped on today: manually, e.g. via the Supabase SQL editor,
-- logged in as the project owner.


-- ============================================================================================
-- Migration 44: Guild Treasury permissions — Guild Leader / Treasurer / Officers / Members.
--
-- Everything guild-treasury-related up to now (the Guild Treasury, Guild Treasury Ledger
-- Hardening, Guild Revenue Distribution, and Guild Member Earnings migrations above) only
-- ever recognized
-- one authority over a Player Guild's own funds: player_guilds.owner_id (see 33's header —
-- "GO_PERMISSIONS' richer Council/rung system has no server-side counterpart yet"). This
-- migration is that server-side counterpart, scoped to the treasury specifically:
--
--   - Guild Leader — the existing owner_id. Still the one authority that can grant/revoke the
--     roles below; not stored as a role value on player_guild_members, so there is never a
--     second row that could disagree with player_guilds.owner_id about who leads the guild.
--   - Treasurer / Officer — new, explicit roles on player_guild_members.role, assignable only by
--     the Guild Leader, authorized to manage guild-owned funds exactly like the Leader today.
--   - Member — the default for everyone else. Unchanged: a member's own held-in-trust earnings
--     (bucket = 'member' in guild_treasury_transactions) were already only ever visible to and
--     movable by that member themselves (see the Guild Treasury and Guild Member Earnings migrations' RLS policies and security-definer
--     RPCs, all keyed to auth.uid()) — nothing here touches that, and nothing here widens who
--     can see or move a 'member'-bucket row. A Leader/Treasurer/Officer's extra authority below
--     is strictly over the 'guild' bucket (money the guild collectively owns), never the
--     'member' bucket (money merely held in the guild's trust on a member's own behalf). That
--     separation is what makes "never allow one unauthorized user to transfer member-owned
--     earnings" true by construction, not just by convention: there is no function in this
--     migration, or any before it, that can move a 'member'-bucket row for anyone but that row's
--     own member_id.
--
-- Also added: multi-approval for large guild-owned-fund withdrawals. A single Leader/Treasurer/
-- Officer can still authorize a spend up to guild_treasury_multi_approval_threshold_kobo()
-- directly (spend_from_guild_treasury, unchanged in spirit from 33/34 — just re-scoped to any
-- authorized role instead of owner_id alone). At or above that threshold, spend_from_guild_
-- treasury refuses and the caller must go through propose_guild_treasury_spend() +
-- approve_guild_treasury_spend(), which requires a second, distinct authorized approver before
-- a kobo actually moves.
--
-- Safe to run anytime, including against a deployment with existing rows: the new role column
-- defaults every existing membership row to 'member' (nobody gains Treasurer/Officer authority
-- on deployment — the Leader has to grant it explicitly afterward), and every function below is
-- created with or-replace or if-not-exists.
-- ============================================================================================

-- ============================================================================================
-- player_guild_members.role — Treasurer/Officer/Member only. 'leader' is deliberately not a
-- valid value here: leadership is player_guilds.owner_id, exactly as it already was, so there's
-- never a second, independent place that could claim someone else is the guild's leader.
-- ============================================================================================

alter table player_guild_members add column if not exists role text not null default 'member';
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'player_guild_members_role_check') then
    alter table player_guild_members
      add constraint player_guild_members_role_check check (role in ('treasurer', 'officer', 'member'));
  end if;
end $$;

-- No update policy is added for player_guild_members here, on purpose — same "no client write
-- policy, only a security-definer RPC that re-derives authority server-side" stance as
-- guild_treasury_transactions itself. A client cannot promote themselves (or anyone else) to
-- Treasurer/Officer by writing to this table directly; see set_guild_treasury_role() below.

-- ============================================================================================
-- Authority checks — the one place "is this caller allowed to manage guild-owned funds" is
-- decided, so spend_from_guild_treasury/propose_guild_treasury_spend/approve_guild_treasury_
-- spend all agree with each other and with whatever the UI displays.
-- ============================================================================================

-- 'leader' | 'treasurer' | 'officer' | 'member' | null (not a member of this guild at all).
-- A Founder Guild has no owner_id (see is_founder_guild/founder_slug on player_guilds) — its
-- 'leader' authority is delegated to whichever profile(s) carry is_platform_admin, per Inkroot's
-- own decision that the platform admin (and anyone they appoint via that flag) acts as the
-- Founder Guild's officer. See is_guild_officer()/is_guild_member() below for the same rule
-- applied to plain "is this caller allowed at all" checks elsewhere.
create or replace function guild_treasury_role(p_guild_id uuid, p_user_id uuid default auth.uid())
returns text as $$
  select case
    when exists (
      select 1 from player_guilds g
      where g.id = p_guild_id
        and (
          (not g.is_founder_guild and g.owner_id = p_user_id)
          or (g.is_founder_guild and exists (
            select 1 from profiles p where p.id = p_user_id and p.is_platform_admin
          ))
        )
    ) then 'leader'
    else (select m.role from player_guild_members m where m.guild_id = p_guild_id and m.user_id = p_user_id)
  end;
$$ language sql stable security definer set search_path = public;

create or replace function is_guild_treasury_authorized(p_guild_id uuid, p_user_id uuid default auth.uid())
returns boolean as $$
  select guild_treasury_role(p_guild_id, p_user_id) in ('leader', 'treasurer', 'officer');
$$ language sql stable security definer set search_path = public;

revoke all on function guild_treasury_role(uuid, uuid) from public;
revoke all on function is_guild_treasury_authorized(uuid, uuid) from public;
grant execute on function guild_treasury_role(uuid, uuid) to authenticated;
grant execute on function is_guild_treasury_authorized(uuid, uuid) to authenticated;

-- Only the Guild Leader may grant/revoke Treasurer or Officer. Deliberately cannot target the
-- Leader's own membership row or set role = 'leader' — leadership only ever changes by
-- transferring player_guilds.owner_id itself (no feature does that today), never through this
-- function, so there's exactly one place ownership can ever be decided.
create or replace function set_guild_treasury_role(p_guild_id uuid, p_member_id uuid, p_role text)
returns player_guild_members
language plpgsql security definer set search_path = public as $$
declare
  v_guild player_guilds%rowtype;
  v_row player_guild_members;
begin
  if p_role not in ('treasurer', 'officer', 'member') then
    raise exception 'Role must be treasurer, officer, or member.';
  end if;

  select * into v_guild from player_guilds where id = p_guild_id;
  if not found then
    raise exception 'Guild not found.';
  end if;
  if v_guild.is_founder_guild then
    raise exception 'A Founder Guild has no single leader to delegate Treasurer/Officer roles — every Inkroot admin already carries full authority here.';
  end if;
  if auth.uid() <> v_guild.owner_id then
    raise exception 'Only the guild leader can assign treasury roles.';
  end if;
  if p_member_id = v_guild.owner_id then
    raise exception 'The guild leader''s own role cannot be changed here.';
  end if;

  update player_guild_members set role = p_role
  where guild_id = p_guild_id and user_id = p_member_id
  returning * into v_row;

  if not found then
    raise exception 'That writer is not a member of this guild.';
  end if;
  return v_row;
end;
$$;

revoke all on function set_guild_treasury_role(uuid, uuid, text) from public;
grant execute on function set_guild_treasury_role(uuid, uuid, text) to authenticated;

-- ============================================================================================
-- spend_from_guild_treasury — widened from "owner_id only" (33/34_migration_*.sql) to any
-- authorized role, and now refuses outright at or above the multi-approval threshold rather than
-- letting one person move a large sum alone. Same signature as 34_migration_guild_treasury_
-- Guild Treasury Ledger Hardening migration left it (create-or-replace is enough; nothing here
-- changes the argument list), so every existing caller (guild-treasury.js's
-- spendFromGuildTreasury) keeps working
-- unchanged for amounts under the threshold.
-- ============================================================================================

-- ₦100,000. A guild's own choice of "large" isn't configurable yet — same "reserved, not
-- invented" posture as everything else in this table that isn't live yet (see 33's header) —
-- but every caller of this threshold goes through this one function, so making it configurable
-- later (e.g. a per-guild setting) only ever needs one definition changed.
create or replace function guild_treasury_multi_approval_threshold_kobo()
returns bigint as $$
  select 10000000::bigint;
$$ language sql immutable;

revoke all on function guild_treasury_multi_approval_threshold_kobo() from public;
grant execute on function guild_treasury_multi_approval_threshold_kobo() to authenticated;

create or replace function spend_from_guild_treasury(
  p_guild_id uuid, p_amount_kobo bigint, p_title text,
  p_idempotency_key text default null, p_project_event_id uuid default null
)
returns guild_treasury_transactions
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_treasury_transactions;
begin
  if p_idempotency_key is not null then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
    if found then
      return v_row;
    end if;
  end if;

  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not is_guild_treasury_authorized(p_guild_id) then
    raise exception 'Only the guild leader, treasurer, or an officer can authorize a treasury spend.';
  end if;
  if p_amount_kobo >= guild_treasury_multi_approval_threshold_kobo() then
    raise exception 'Withdrawals of this size require multiple approvals — use propose_guild_treasury_spend instead.';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_guild_id::text));
  if guild_treasury_available_kobo(p_guild_id) < p_amount_kobo then
    raise exception 'That would exceed the guild''s available treasury balance.';
  end if;

  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     project_event_id, status, title, created_by, idempotency_key)
  values
    (p_guild_id, 'guild', null, 'debit', 'spend', p_amount_kobo, 'NGN', 'guild_treasury',
     'external', p_project_event_id, 'success', p_title, auth.uid(), p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_row;

  if not found then
    select * into v_row from guild_treasury_transactions where idempotency_key = p_idempotency_key;
  end if;
  return v_row;
end;
$$;

-- ============================================================================================
-- Multi-approval spend requests — the large-withdrawal path. A pending request reserves its
-- amount against the guild's available balance (see the "reserved" subquery in both RPCs below)
-- so two large proposals can't both be approved against the same money; it stops reserving the
-- instant it's executed or cancelled.
-- ============================================================================================

create table if not exists guild_treasury_spend_requests (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  amount_kobo bigint not null check (amount_kobo > 0),
  title text not null,
  requested_by uuid not null references auth.users(id) on delete cascade,
  required_approvals int not null default 2 check (required_approvals >= 2),
  status text not null default 'pending' check (status in ('pending', 'executed', 'cancelled')),
  idempotency_key text,
  transaction_id uuid references guild_treasury_transactions(id),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);

alter table guild_treasury_spend_requests enable row level security;

-- Same transparency stance as guild-owned guild_treasury_transactions rows: every guild member
-- can see a proposed spend, not just the authorized roles who can act on it — the actual
-- authority check happens inside the RPCs below, not in RLS.
create policy "guild members read guild treasury spend requests" on guild_treasury_spend_requests
  for select using (
    exists (
      select 1 from player_guild_members m
      where m.guild_id = guild_treasury_spend_requests.guild_id and m.user_id = auth.uid()
    )
  );

-- No insert/update/delete policy for any client role — every write goes through
-- propose_guild_treasury_spend()/approve_guild_treasury_spend()/cancel_guild_treasury_spend_
-- request() below, exactly the same "server re-checks everything" posture as
-- guild_treasury_transactions itself.

create index if not exists guild_treasury_spend_requests_guild_status_idx
  on guild_treasury_spend_requests (guild_id, status, created_at desc);
create unique index if not exists guild_treasury_spend_requests_idempotency_key_idx
  on guild_treasury_spend_requests (idempotency_key) where idempotency_key is not null;

create table if not exists guild_treasury_spend_approvals (
  request_id uuid not null references guild_treasury_spend_requests(id) on delete cascade,
  approver_id uuid not null references auth.users(id) on delete cascade,
  approved_at timestamptz not null default now(),
  primary key (request_id, approver_id)
);

alter table guild_treasury_spend_approvals enable row level security;

create policy "guild members read spend approvals" on guild_treasury_spend_approvals
  for select using (
    exists (
      select 1 from guild_treasury_spend_requests r
      join player_guild_members m on m.guild_id = r.guild_id and m.user_id = auth.uid()
      where r.id = guild_treasury_spend_approvals.request_id
    )
  );

-- No insert/update/delete policy here either — approve_guild_treasury_spend() below is the only
-- writer.

-- A pending request's own amount, not-yet-executed, reserved against the guild's available
-- balance so a second proposal can't be approved against money the first one is already
-- claiming. Excludes p_exclude_request_id so a request can check "everyone else's" reservation
-- without double-counting its own.
create or replace function guild_treasury_reserved_by_other_requests_kobo(p_guild_id uuid, p_exclude_request_id uuid default null)
returns bigint as $$
  select coalesce(sum(amount_kobo), 0) from guild_treasury_spend_requests
  where guild_id = p_guild_id and status = 'pending'
    and (p_exclude_request_id is null or id <> p_exclude_request_id);
$$ language sql stable security definer set search_path = public;

revoke all on function guild_treasury_reserved_by_other_requests_kobo(uuid, uuid) from public;
grant execute on function guild_treasury_reserved_by_other_requests_kobo(uuid, uuid) to authenticated;

-- Any authorized role (Leader/Treasurer/Officer) may propose a large spend. The proposer is
-- recorded as its first approval automatically (inserted right below, in the same transaction) —
-- a solo proposal can never execute itself, since required_approvals is at least 2 and the
-- primary key on guild_treasury_spend_approvals stops the same person voting twice.
create or replace function propose_guild_treasury_spend(
  p_guild_id uuid, p_amount_kobo bigint, p_title text, p_idempotency_key text default null
)
returns guild_treasury_spend_requests
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_treasury_spend_requests;
begin
  if p_idempotency_key is not null then
    select * into v_row from guild_treasury_spend_requests where idempotency_key = p_idempotency_key;
    if found then
      return v_row;
    end if;
  end if;

  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'A spend request needs a title.';
  end if;
  if not is_guild_treasury_authorized(p_guild_id) then
    raise exception 'Only the guild leader, treasurer, or an officer can propose a treasury spend.';
  end if;
  if p_amount_kobo < guild_treasury_multi_approval_threshold_kobo() then
    raise exception 'Amounts under the multi-approval threshold can be authorized directly with spend_from_guild_treasury.';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_guild_id::text));
  if guild_treasury_available_kobo(p_guild_id) - guild_treasury_reserved_by_other_requests_kobo(p_guild_id) < p_amount_kobo then
    raise exception 'That would exceed the guild''s available treasury balance once pending proposals are accounted for.';
  end if;

  insert into guild_treasury_spend_requests (guild_id, amount_kobo, title, requested_by, idempotency_key)
  values (p_guild_id, p_amount_kobo, trim(p_title), auth.uid(), p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_row;

  if not found then
    select * into v_row from guild_treasury_spend_requests where idempotency_key = p_idempotency_key;
    return v_row;
  end if;

  insert into guild_treasury_spend_approvals (request_id, approver_id) values (v_row.id, auth.uid());
  return v_row;
end;
$$;

-- A second (or later) authorized role approves. Once enough distinct approvals exist, this
-- executes the spend itself — inserting into guild_treasury_transactions exactly like
-- spend_from_guild_treasury does, tagged with an idempotency key derived from the request's own
-- id so the same request can never execute twice even if two approvals raced each other to be
-- "the one that tips it over".
create or replace function approve_guild_treasury_spend(p_request_id uuid)
returns guild_treasury_spend_requests
language plpgsql security definer set search_path = public as $$
declare
  v_req guild_treasury_spend_requests;
  v_txn guild_treasury_transactions;
  v_approval_count int;
begin
  select * into v_req from guild_treasury_spend_requests where id = p_request_id for update;
  if not found then
    raise exception 'Spend request not found.';
  end if;
  if v_req.status <> 'pending' then
    raise exception 'This spend request has already been decided.';
  end if;
  if not is_guild_treasury_authorized(v_req.guild_id) then
    raise exception 'Only the guild leader, treasurer, or an officer can approve a treasury spend.';
  end if;

  insert into guild_treasury_spend_approvals (request_id, approver_id)
  values (p_request_id, auth.uid())
  on conflict (request_id, approver_id) do nothing;

  select count(*) into v_approval_count from guild_treasury_spend_approvals where request_id = p_request_id;
  if v_approval_count < v_req.required_approvals then
    return v_req; -- still pending, one more approval recorded
  end if;

  perform pg_advisory_xact_lock(hashtext(v_req.guild_id::text));
  if guild_treasury_available_kobo(v_req.guild_id)
     - guild_treasury_reserved_by_other_requests_kobo(v_req.guild_id, p_request_id) < v_req.amount_kobo then
    raise exception 'That would exceed the guild''s available treasury balance — cancel or wait for funds before it can execute.';
  end if;

  insert into guild_treasury_transactions
    (guild_id, bucket, member_id, direction, kind, amount_kobo, currency, source, destination,
     status, title, created_by, idempotency_key)
  values
    (v_req.guild_id, 'guild', null, 'debit', 'spend', v_req.amount_kobo, 'NGN', 'guild_treasury',
     'external', 'success', v_req.title, v_req.requested_by, 'spend_request:' || p_request_id::text)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning * into v_txn;

  if not found then
    select * into v_txn from guild_treasury_transactions where idempotency_key = 'spend_request:' || p_request_id::text;
  end if;

  update guild_treasury_spend_requests
  set status = 'executed', transaction_id = v_txn.id, decided_at = now()
  where id = p_request_id
  returning * into v_req;

  return v_req;
end;
$$;

-- Lets the proposer or the guild leader stand a pending proposal down (e.g. it's no longer
-- needed, or funds are wanted elsewhere) so it stops reserving against the available balance.
-- Never allowed once executed or already cancelled — this only ever moves 'pending' -> 'cancelled'.
create or replace function cancel_guild_treasury_spend_request(p_request_id uuid)
returns guild_treasury_spend_requests
language plpgsql security definer set search_path = public as $$
declare
  v_req guild_treasury_spend_requests;
begin
  select * into v_req from guild_treasury_spend_requests where id = p_request_id for update;
  if not found then
    raise exception 'Spend request not found.';
  end if;
  if v_req.status <> 'pending' then
    raise exception 'This spend request has already been decided.';
  end if;
  if auth.uid() <> v_req.requested_by
     and not is_guild_officer(v_req.guild_id) then
    raise exception 'Only the person who proposed this spend, or the guild leader, can cancel it.';
  end if;

  update guild_treasury_spend_requests set status = 'cancelled', decided_at = now()
  where id = p_request_id
  returning * into v_req;
  return v_req;
end;
$$;

revoke all on function propose_guild_treasury_spend(uuid, bigint, text, text) from public;
revoke all on function approve_guild_treasury_spend(uuid) from public;
revoke all on function cancel_guild_treasury_spend_request(uuid) from public;
grant execute on function propose_guild_treasury_spend(uuid, bigint, text, text) to authenticated;
grant execute on function approve_guild_treasury_spend(uuid) to authenticated;
grant execute on function cancel_guild_treasury_spend_request(uuid) to authenticated;

-- Safe to run anytime — see this migration's header.
-- ============================================================================================
-- Migration 45: Guild Event creation — turns the one-field "title + entry fee" quick-create in
-- 42_migration_guild_events.sql into a full submission the guild owner fills in (title,
-- description, rules, event type, entry fee, participant limit, prize structure, guild share,
-- start/end date, organizer, cover image) and Inkroot reviews before it ever reaches readers.
--
-- Same table, richer row: every new column lives on guild_events itself rather than a second
-- table, so entries (guild_event_entries) and settlement (settle_guild_event) keep working
-- against the exact same row they always have — nothing about how money moves changes here.
--
-- Two lifecycles on one row, kept deliberately separate:
--   - approval_status: draft -> pending_approval -> approved -> published -> active -> completed,
--     or draft/pending_approval -> ... -> rejected. This is the NEW one this migration adds —
--     entirely about whether/when a submission is fit to show readers at all.
--   - status (open/closed/settled, from migration 42): unchanged, still entirely about whether
--     entries are currently being accepted and whether the pool has been paid out. What's new is
--     only how it gets flipped: activate_guild_event() below is now the thing that moves it to
--     'open' (readers can enter) instead of that happening the instant the event exists.
-- A guild-hosted event therefore can't take a single Naira until its owner has filled in the
-- whole form, Inkroot has approved it, the owner has published it, AND the owner has activated
-- it — four separate, server-checked steps, not one.
--
-- Rejected events stay unpublished by construction, not by convention: create_guild_event_draft
-- inserts every new event with status = 'closed' (not the table's own 'open' default), and
-- nothing on the reject path ever touches status — activate_guild_event is the only function
-- that ever sets status = 'open', and it refuses anything whose approval_status isn't
-- 'published'. A rejected event can only reach 'published' again by being edited back to
-- 'draft' (update_guild_event_draft) and resubmitted, so there is no path from 'rejected' to
-- open entries that skips re-review.
--
-- create_guild_event() — the original quick-create RPC — is left fully callable, for both hosts,
-- exactly as it always worked (instantly live, no review step). It's how host='inkroot' events
-- are still created (Inkroot funding its own prize is already the trusted party in that flow —
-- see migration 42/43's own header on why there's no review step to route it through), and
-- keeping it callable for host='guild' too means nothing that already depends on this exact RPC
-- signature breaks. The new, richer path below is additive.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. New columns on guild_events.
-- ----------------------------------------------------------------------------------------------

alter table guild_events
  add column if not exists description text check (char_length(description) <= 4000),
  add column if not exists rules text check (char_length(rules) <= 4000),
  add column if not exists event_type text not null default 'other'
    check (event_type in ('tournament', 'writing_contest', 'reading_challenge', 'giveaway', 'workshop', 'other')),
  add column if not exists participant_limit integer check (participant_limit > 0),
  -- Informational only — a guide for the organizer at settle_guild_event() time, e.g.
  -- [{"place": 1, "share_pct": 50}, {"place": 2, "share_pct": 30}, {"place": 3, "share_pct": 20}].
  -- Never trusted or enforced server-side: the actual payout is still whatever p_shares
  -- settle_guild_event() is called with, checked the same way it always has been.
  add column if not exists prize_structure jsonb not null default '[]'::jsonb,
  -- Also informational/planning-only, same reasoning as prize_structure — the guild's actual
  -- take at settlement is still just "gross minus whatever winner shares were declared" (see
  -- distribute_guild_revenue's v_guild_share), computed the same way regardless of this value.
  add column if not exists guild_share_bps integer not null default 0
    check (guild_share_bps >= 0 and guild_share_bps <= 10000),
  add column if not exists start_date timestamptz,
  add column if not exists end_date timestamptz,
  add column if not exists organizer_id uuid references auth.users(id) on delete set null,
  add column if not exists cover_image_url text,
  add column if not exists approval_status text not null default 'draft'
    check (approval_status in ('draft', 'pending_approval', 'approved', 'published', 'active', 'completed', 'rejected')),
  add column if not exists rejection_reason text,
  add column if not exists submitted_at timestamptz,
  add column if not exists reviewed_by uuid references auth.users(id) on delete set null,
  add column if not exists reviewed_at timestamptz,
  add column if not exists published_at timestamptz,
  add column if not exists activated_at timestamptz,
  add column if not exists completed_at timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'guild_events_date_range_chk') then
    alter table guild_events
      add constraint guild_events_date_range_chk
      check (start_date is null or end_date is null or end_date > start_date);
  end if;
end $$;

create index if not exists guild_events_pending_approval_idx
  on guild_events (approval_status) where approval_status = 'pending_approval';

-- 'guild-event-covers' joins the same public, per-uploader-folder posture avatars/guild-crests/
-- book-covers already have (see schema_phase9.sql) — a cover image is meant to be publicly
-- visible the moment it's uploaded, same as any of those. One function change is enough: every
-- read/insert/update/delete policy on storage.objects already delegates the allowed-folder list
-- to is_public_media_folder() for exactly this reason (see its own comment on why that's one
-- function, not four repeated literals).
create or replace function is_public_media_folder(folder text)
returns boolean
language sql
immutable
as $$
  select folder in ('avatars', 'guild-crests', 'book-covers', 'guild-event-covers');
$$;

-- ----------------------------------------------------------------------------------------------
-- 2. create_guild_event — redefined only to keep its old "instantly live" behavior working
-- unchanged now that approval_status/status default differently for a NEW row. Every check and
-- authorization branch below is identical to migration 43's version; the only addition is the
-- explicit approval_status/status/published_at/activated_at values on each insert.
-- ----------------------------------------------------------------------------------------------

create or replace function create_guild_event(
  p_guild_id uuid, p_title text, p_host text,
  p_entry_fee_kobo bigint default null, p_cash_prize_kobo bigint default null
)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_events;
begin
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'Give the event a title.';
  end if;

  if p_host = 'inkroot' then
    if not is_inkroot_admin() then
      raise exception 'Only an Inkroot admin can host a cash-prize event.';
    end if;
    if p_cash_prize_kobo is null or p_cash_prize_kobo <= 0 then
      raise exception 'An Inkroot-hosted event needs a positive cash prize.';
    end if;
    if p_entry_fee_kobo is not null then
      raise exception 'An Inkroot-hosted event has no entry fee \u2014 it''s funded directly.';
    end if;
    if not exists (select 1 from player_guilds g where g.id = p_guild_id) then
      raise exception 'Guild not found.';
    end if;
    insert into guild_events (guild_id, host, title, cash_prize_kobo, created_by, approval_status, status, published_at, activated_at)
    values (p_guild_id, 'inkroot', trim(p_title), p_cash_prize_kobo, auth.uid(), 'active', 'open', now(), now())
    returning * into v_row;
    return v_row;
  elsif p_host = 'guild' then
    if not is_guild_officer(p_guild_id) then
      raise exception 'Only the guild owner can host a guild event.';
    end if;
    if p_entry_fee_kobo is null or p_entry_fee_kobo <= 0 then
      raise exception 'A guild-hosted event needs a positive entry fee.';
    end if;
    if p_cash_prize_kobo is not null then
      raise exception 'A guild-hosted event funds its own prize from entry fees \u2014 it has no separate cash prize.';
    end if;
    insert into guild_events (guild_id, host, title, entry_fee_kobo, created_by, approval_status, status, published_at, activated_at)
    values (p_guild_id, 'guild', trim(p_title), p_entry_fee_kobo, auth.uid(), 'active', 'open', now(), now())
    returning * into v_row;
    return v_row;
  else
    raise exception 'Unknown event host.';
  end if;
end;
$$;

revoke all on function create_guild_event(uuid, text, text, bigint, bigint) from public;
grant execute on function create_guild_event(uuid, text, text, bigint, bigint) to authenticated;

-- ----------------------------------------------------------------------------------------------
-- 3. create_guild_event_draft / update_guild_event_draft — the actual Guild Event creation form.
-- Guild-owner-only, host='guild' only (see the migration header on why host='inkroot' has no
-- review step to route through). A new row always starts approval_status='draft',
-- status='closed' — never enterable, never visible as anything but a draft, until it's been all
-- the way through submit -> approve -> publish -> activate below.
-- ----------------------------------------------------------------------------------------------

create or replace function create_guild_event_draft(
  p_guild_id uuid,
  p_title text,
  p_description text default null,
  p_rules text default null,
  p_event_type text default 'other',
  p_entry_fee_kobo bigint default null,
  p_participant_limit integer default null,
  p_prize_structure jsonb default '[]'::jsonb,
  p_guild_share_bps integer default 0,
  p_start_date timestamptz default null,
  p_end_date timestamptz default null,
  p_organizer_id uuid default null,
  p_cover_image_url text default null
)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_events;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can host a guild event.';
  end if;
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'Give the event a title.';
  end if;
  if p_entry_fee_kobo is null or p_entry_fee_kobo <= 0 then
    raise exception 'A guild-hosted event needs a positive entry fee.';
  end if;
  if p_organizer_id is not null and not exists (
    select 1 from player_guild_members m where m.guild_id = p_guild_id and m.user_id = p_organizer_id
  ) then
    raise exception 'The organizer must be a member of this guild.';
  end if;
  if p_start_date is not null and p_end_date is not null and p_end_date <= p_start_date then
    raise exception 'End date must be after the start date.';
  end if;

  insert into guild_events (
    guild_id, host, title, description, rules, event_type, entry_fee_kobo, participant_limit,
    prize_structure, guild_share_bps, start_date, end_date, organizer_id, cover_image_url,
    created_by, approval_status, status
  ) values (
    p_guild_id, 'guild', trim(p_title), nullif(trim(coalesce(p_description, '')), ''),
    nullif(trim(coalesce(p_rules, '')), ''), coalesce(p_event_type, 'other'),
    p_entry_fee_kobo, p_participant_limit, coalesce(p_prize_structure, '[]'::jsonb),
    coalesce(p_guild_share_bps, 0), p_start_date, p_end_date, p_organizer_id, p_cover_image_url,
    auth.uid(), 'draft', 'closed'
  ) returning * into v_row;
  return v_row;
end;
$$;

-- Only ever touches a row still in 'draft' or 'rejected' — once it's pending_approval or beyond,
-- editing would mean changing what Inkroot already reviewed (or is reviewing) out from under
-- them, so it's refused. Editing a rejected event always resets it back to 'draft' and clears
-- the review trail (rejection_reason/reviewed_by/reviewed_at/submitted_at) — it has to be
-- resubmitted deliberately (submit_guild_event_for_approval), never silently re-enters the
-- queue just because it was touched.
create or replace function update_guild_event_draft(
  p_guild_id uuid,
  p_event_id uuid,
  p_title text,
  p_description text default null,
  p_rules text default null,
  p_event_type text default 'other',
  p_entry_fee_kobo bigint default null,
  p_participant_limit integer default null,
  p_prize_structure jsonb default '[]'::jsonb,
  p_guild_share_bps integer default 0,
  p_start_date timestamptz default null,
  p_end_date timestamptz default null,
  p_organizer_id uuid default null,
  p_cover_image_url text default null
)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can edit this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status not in ('draft', 'rejected') then
    raise exception 'Only a draft or rejected event can be edited.';
  end if;
  if p_title is null or length(trim(p_title)) = 0 then
    raise exception 'Give the event a title.';
  end if;
  if p_entry_fee_kobo is null or p_entry_fee_kobo <= 0 then
    raise exception 'A guild-hosted event needs a positive entry fee.';
  end if;
  if p_organizer_id is not null and not exists (
    select 1 from player_guild_members m where m.guild_id = p_guild_id and m.user_id = p_organizer_id
  ) then
    raise exception 'The organizer must be a member of this guild.';
  end if;
  if p_start_date is not null and p_end_date is not null and p_end_date <= p_start_date then
    raise exception 'End date must be after the start date.';
  end if;

  update guild_events set
    title = trim(p_title),
    description = nullif(trim(coalesce(p_description, '')), ''),
    rules = nullif(trim(coalesce(p_rules, '')), ''),
    event_type = coalesce(p_event_type, 'other'),
    entry_fee_kobo = p_entry_fee_kobo,
    participant_limit = p_participant_limit,
    prize_structure = coalesce(p_prize_structure, '[]'::jsonb),
    guild_share_bps = coalesce(p_guild_share_bps, 0),
    start_date = p_start_date,
    end_date = p_end_date,
    organizer_id = p_organizer_id,
    cover_image_url = p_cover_image_url,
    approval_status = 'draft',
    rejection_reason = null,
    reviewed_by = null,
    reviewed_at = null,
    submitted_at = null
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 4. submit_guild_event_for_approval / approve_guild_event / reject_guild_event — the review
-- step. Submit is owner-only (their own event); approve/reject are is_inkroot_admin()-only, same
-- trust domain as everything else Inkroot-admin-gated (see migration 43's own header on why this
-- is a separate flag from is_moderator).
-- ----------------------------------------------------------------------------------------------

create or replace function submit_guild_event_for_approval(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can submit this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status not in ('draft', 'rejected') then
    raise exception 'This event has already been submitted.';
  end if;
  if v_event.title is null or length(trim(v_event.title)) = 0
     or v_event.entry_fee_kobo is null or v_event.start_date is null or v_event.end_date is null then
    raise exception 'Fill in the title, entry fee, and start/end dates before submitting.';
  end if;

  update guild_events set approval_status = 'pending_approval', submitted_at = now(), rejection_reason = null
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

create or replace function approve_guild_event(p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can approve a guild event.';
  end if;
  select * into v_event from guild_events where id = p_event_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'pending_approval' then
    raise exception 'This event is not awaiting approval.';
  end if;

  update guild_events set approval_status = 'approved', reviewed_by = auth.uid(), reviewed_at = now(), rejection_reason = null
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

create or replace function reject_guild_event(p_event_id uuid, p_reason text)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can reject a guild event.';
  end if;
  if p_reason is null or length(trim(p_reason)) = 0 then
    raise exception 'Give a reason so the organizer knows what to fix.';
  end if;
  select * into v_event from guild_events where id = p_event_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'pending_approval' then
    raise exception 'This event is not awaiting approval.';
  end if;

  -- status is left exactly as create_guild_event_draft set it ('closed') — see the migration
  -- header on why that alone is enough to keep a rejected event unpublished.
  update guild_events set approval_status = 'rejected', reviewed_by = auth.uid(), reviewed_at = now(),
    rejection_reason = trim(p_reason)
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 5. publish_guild_event / activate_guild_event / complete_guild_event — the owner-driven tail
-- of the pipeline, each one a strict single step forward (approved -> published -> active ->
-- completed), same "re-check the exact state you're leaving" posture as close_guild_event
-- already has in migration 42.
-- ----------------------------------------------------------------------------------------------

create or replace function publish_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can publish this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'approved' then
    raise exception 'This event needs Inkroot approval before it can be published.';
  end if;

  update guild_events set approval_status = 'published', published_at = now()
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- The moment a guild-hosted event actually starts accepting entries — see the migration header
-- on why status='open' waits for this instead of being set at creation.
create or replace function activate_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can activate this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'published' then
    raise exception 'Publish this event before opening it for entries.';
  end if;

  update guild_events set approval_status = 'active', activated_at = now(), status = 'open'
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- Stops new entries (status -> 'closed', same effect close_guild_event already has) and marks
-- the run itself finished. Settling the pool and paying winners is still the separate, existing
-- settle_guild_event() call — completing an event says nothing about whether that's happened yet.
create or replace function complete_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can complete this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'active' then
    raise exception 'Only an active event can be marked completed.';
  end if;

  update guild_events set approval_status = 'completed', completed_at = now(), status = 'closed'
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 6. admin_list_pending_guild_events — the Inkroot review queue. player_guilds' own select
-- policy is member/owner-scoped (see admin_list_guilds' own comment), so this resolves guild
-- names the same security-definer-bypass way admin_list_guilds does rather than leaving the
-- admin screen to guess.
-- ----------------------------------------------------------------------------------------------

create or replace function admin_list_pending_guild_events()
returns table (
  id uuid, guild_id uuid, guild_name text, title text, description text, rules text,
  event_type text, entry_fee_kobo bigint, participant_limit integer, prize_structure jsonb,
  guild_share_bps integer, start_date timestamptz, end_date timestamptz,
  organizer_id uuid, cover_image_url text, submitted_at timestamptz, created_by uuid
)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can review guild event submissions.';
  end if;
  return query
    select e.id, e.guild_id, g.name, e.title, e.description, e.rules,
           e.event_type, e.entry_fee_kobo, e.participant_limit, e.prize_structure,
           e.guild_share_bps, e.start_date, e.end_date,
           e.organizer_id, e.cover_image_url, e.submitted_at, e.created_by
    from guild_events e join player_guilds g on g.id = e.guild_id
    where e.approval_status = 'pending_approval'
    order by e.submitted_at asc nulls last;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 7. Grants.
-- ----------------------------------------------------------------------------------------------

revoke all on function create_guild_event_draft(uuid, text, text, text, text, bigint, integer, jsonb, integer, timestamptz, timestamptz, uuid, text) from public;
revoke all on function update_guild_event_draft(uuid, uuid, text, text, text, text, bigint, integer, jsonb, integer, timestamptz, timestamptz, uuid, text) from public;
revoke all on function submit_guild_event_for_approval(uuid, uuid) from public;
revoke all on function approve_guild_event(uuid) from public;
revoke all on function reject_guild_event(uuid, text) from public;
revoke all on function publish_guild_event(uuid, uuid) from public;
revoke all on function activate_guild_event(uuid, uuid) from public;
revoke all on function complete_guild_event(uuid, uuid) from public;
revoke all on function admin_list_pending_guild_events() from public;

grant execute on function create_guild_event_draft(uuid, text, text, text, text, bigint, integer, jsonb, integer, timestamptz, timestamptz, uuid, text) to authenticated;
grant execute on function update_guild_event_draft(uuid, uuid, text, text, text, text, bigint, integer, jsonb, integer, timestamptz, timestamptz, uuid, text) to authenticated;
grant execute on function submit_guild_event_for_approval(uuid, uuid) to authenticated;
grant execute on function approve_guild_event(uuid) to authenticated;
grant execute on function reject_guild_event(uuid, text) to authenticated;
grant execute on function publish_guild_event(uuid, uuid) to authenticated;
grant execute on function activate_guild_event(uuid, uuid) to authenticated;
grant execute on function complete_guild_event(uuid, uuid) to authenticated;
grant execute on function admin_list_pending_guild_events() to authenticated;

-- Safe to run anytime: every new column is nullable or has a default that reproduces the exact
-- prior behavior for any existing row (approval_status/status default to 'draft'/'closed' only
-- for brand-new inserts through the new functions — create_guild_event's own redefinition above
-- sets both explicitly for every row it inserts, so nothing that already went through it changes
-- behavior), and every new function is additive.
-- ============================================================================================
-- Migration 46: guild_event_entry_count() — lets anyone see how many of a guild-hosted event's
-- participant_limit slots are already taken, without exposing who took them.
--
-- guild_event_entries itself is deliberately NOT publicly readable (see its own RLS in
-- 42_migration_guild_events.sql — an entrant's own rows, or the guild owner's, only). That's the
-- right call for the entries themselves (nobody else needs to know who paid to enter), but it
-- means a reader deciding whether to enter a near-full event currently has no way to find out
-- it's near full at all. This is a narrow, count-only bypass of that same shape as
-- admin_list_guilds()/admin_list_pending_guild_events() — a security-definer function that
-- returns strictly less than the table it reads, here a bare integer rather than any row.
-- ============================================================================================

create or replace function guild_event_entry_count(p_event_id uuid)
returns integer
language sql stable security definer set search_path = public as $$
  select count(*)::integer from guild_event_entries
  where event_id = p_event_id and status in ('pending', 'success');
$$;

revoke all on function guild_event_entry_count(uuid) from public;
grant execute on function guild_event_entry_count(uuid) to authenticated;

-- Safe to run anytime: purely additive, reads nothing this function's own definition doesn't
-- already scope down to a single integer.
-- ============================================================================================
-- Migration 47: Guild Event hosting fee — a guild must pay Inkroot's hosting fee for an event
-- before publish_guild_event() will move it approved -> published (see
-- 45_migration_guild_event_creation_workflow.sql for the rest of that pipeline). This is a
-- second, separate charge from the per-entry platform fee (PLATFORM_FEE_BPS, deducted from each
-- reader's entry fee as it's paid — see 42_migration_guild_events.sql) — this one is what the
-- guild itself pays Inkroot, once, for the right to run the event at all.
--
-- Configurable pricing, not a constant: guild_event_hosting_fee_rates is an append-only table of
-- (fee_kobo, effective_from) rows, same "change it in one place, past rows keep whatever was
-- true when they happened" posture PLATFORM_FEE_BPS's own comment already documents for that
-- constant — except this one lives in the database (via set_guild_event_hosting_fee(), Inkroot-
-- admin-only) rather than a source constant, specifically so Inkroot can change it without a
-- deploy. current_guild_event_hosting_fee_kobo() always resolves "whatever the most recent row
-- with effective_from <= now() says", and every payment snapshots the rate_id/fee_kobo it was
-- actually charged at, so a rate change later never reclassifies a fee a guild already paid —
-- same reasoning guild_event_entries.net_kobo already relies on for the per-entry fee.
--
-- guild_event_hosting_fee_payments is one row per event (a hosting fee is paid once, not per
-- entrant) with the exact same pending -> success/failed, service-role-only-write,
-- paystack_reference-keyed lifecycle `purchases`/`guild_event_entries` already have — see their
-- own comments for why. A configured fee of exactly 0 kobo is the one case nothing is ever
-- charged for: the paystack-init-hosting-fee edge function records a 'success' row with no
-- Paystack reference at all rather than routing a zero-kobo charge through Paystack.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. Configurable pricing.
-- ----------------------------------------------------------------------------------------------

create table if not exists guild_event_hosting_fee_rates (
  id uuid primary key default gen_random_uuid(),
  fee_kobo bigint not null check (fee_kobo >= 0),
  note text check (char_length(note) <= 500),
  effective_from timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

alter table guild_event_hosting_fee_rates enable row level security;

-- Readable by anyone signed in — a guild owner needs to see the current fee (and, ideally, that
-- it's a real configured number rather than something the client made up) before they ever get
-- to the approved stage of an event. Never client-writable: only set_guild_event_hosting_fee()
-- below, which is is_inkroot_admin()-gated, ever inserts a row, and there is deliberately no
-- update/delete policy at all (or RPC) — a rate change is always a new row, never an edit to an
-- old one, so anything already charged against an old rate stays truthfully attributable to it.
create policy "anyone signed in can read hosting fee rates" on guild_event_hosting_fee_rates
  for select using (auth.uid() is not null);

create index if not exists guild_event_hosting_fee_rates_effective_idx
  on guild_event_hosting_fee_rates (effective_from desc);

create or replace function current_guild_event_hosting_fee_kobo()
returns bigint
language sql stable as $$
  select fee_kobo from guild_event_hosting_fee_rates
  where effective_from <= now()
  order by effective_from desc
  limit 1;
$$;

-- The rate a caller can act on right now, id and amount together — small enough not to warrant
-- a second RPC of its own, but returning both in one call means initiating a payment and
-- displaying "what am I about to pay" can never read two different rates a race let slip between.
create or replace function current_guild_event_hosting_fee()
returns table (rate_id uuid, fee_kobo bigint)
language sql stable as $$
  select id, fee_kobo from guild_event_hosting_fee_rates
  where effective_from <= now()
  order by effective_from desc
  limit 1;
$$;

create or replace function set_guild_event_hosting_fee(p_fee_kobo bigint, p_note text default null)
returns guild_event_hosting_fee_rates
language plpgsql security definer set search_path = public as $$
declare
  v_row guild_event_hosting_fee_rates;
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can set the guild event hosting fee.';
  end if;
  if p_fee_kobo is null or p_fee_kobo < 0 then
    raise exception 'The hosting fee cannot be negative.';
  end if;

  insert into guild_event_hosting_fee_rates (fee_kobo, note, created_by)
  values (p_fee_kobo, nullif(trim(coalesce(p_note, '')), ''), auth.uid())
  returning * into v_row;
  return v_row;
end;
$$;

-- Every rate ever set, newest first — the admin screen's own history/audit view. Same
-- is_inkroot_admin() gate as everything else admin-only, even though the table's own select
-- policy already lets any signed-in user read it one row at a time via
-- current_guild_event_hosting_fee(); this is the only way to see the *history*.
create or replace function admin_list_guild_event_hosting_fee_rates()
returns setof guild_event_hosting_fee_rates
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can view the hosting fee rate history.';
  end if;
  return query select * from guild_event_hosting_fee_rates order by effective_from desc;
end;
$$;

-- An initial rate so current_guild_event_hosting_fee_kobo() is never null for an event created
-- the moment this migration runs. ₦5,000 is only a starting point — change it any time via
-- set_guild_event_hosting_fee(), from the admin screen.
insert into guild_event_hosting_fee_rates (fee_kobo, note)
select 500000, 'Initial hosting fee'
where not exists (select 1 from guild_event_hosting_fee_rates);

-- ----------------------------------------------------------------------------------------------
-- 2. guild_event_hosting_fee_payments — one row per event, same lifecycle/RLS shape as
-- guild_event_entries (see its own comment in 42_migration_guild_events.sql for why: created
-- pending by the paystack-init-hosting-fee edge function, only ever flipped to success/failed by
-- paystack-webhook once Paystack confirms the charge — except a 0-kobo fee, recorded 'success'
-- immediately with no reference, since there is nothing for Paystack to confirm).
-- ----------------------------------------------------------------------------------------------

create table if not exists guild_event_hosting_fee_payments (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references guild_events(id) on delete cascade,
  guild_id uuid not null references player_guilds(id) on delete cascade,
  rate_id uuid references guild_event_hosting_fee_rates(id) on delete set null,
  fee_kobo bigint not null check (fee_kobo >= 0),
  status text not null default 'pending' check (status in ('pending', 'success', 'failed')),
  paystack_reference text unique,
  paid_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  unique (event_id)
);

alter table guild_event_hosting_fee_payments enable row level security;

create policy "guild owner reads their own event hosting fee payments" on guild_event_hosting_fee_payments
  for select using (
    is_guild_officer(guild_event_hosting_fee_payments.guild_id)
  );
create policy "inkroot admin reads all hosting fee payments" on guild_event_hosting_fee_payments
  for select using (is_inkroot_admin());
-- No client insert/update policy, same reasoning as guild_event_entries: only
-- paystack-init-hosting-fee (pending, or 'success' outright for a 0-kobo fee) and
-- paystack-webhook (success/failed), both service_role, ever write this table.

create index if not exists guild_event_hosting_fee_payments_event_idx
  on guild_event_hosting_fee_payments (event_id);

-- ----------------------------------------------------------------------------------------------
-- 3. publish_guild_event — redefined only to add the hosting-fee gate. Every existing check
-- (owner-only, must be 'approved') is unchanged from 45_migration_guild_event_creation_workflow.sql.
-- ----------------------------------------------------------------------------------------------

create or replace function publish_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can publish this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'approved' then
    raise exception 'This event needs Inkroot approval before it can be published.';
  end if;
  -- "an approved paid event" — every host='guild' event has a positive entry_fee_kobo by
  -- construction (create_guild_event_draft/update_guild_event_draft both require it), so this
  -- is effectively every guild event; written as an entry_fee_kobo check rather than
  -- unconditionally so a future free-to-enter event type wouldn't need this gate touched.
  if v_event.entry_fee_kobo is not null and not exists (
    select 1 from guild_event_hosting_fee_payments p
    where p.event_id = v_event.id and p.status = 'success'
  ) then
    raise exception 'Pay Inkroot''s hosting fee for this event before publishing it.';
  end if;

  update guild_events set approval_status = 'published', published_at = now()
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 4. Grants.
-- ----------------------------------------------------------------------------------------------

revoke all on function set_guild_event_hosting_fee(bigint, text) from public;
revoke all on function admin_list_guild_event_hosting_fee_rates() from public;

grant execute on function current_guild_event_hosting_fee_kobo() to authenticated;
grant execute on function current_guild_event_hosting_fee() to authenticated;
grant execute on function set_guild_event_hosting_fee(bigint, text) to authenticated;
grant execute on function admin_list_guild_event_hosting_fee_rates() to authenticated;

-- Safe to run anytime: every new table/column is additive, publish_guild_event's redefinition
-- only tightens an already-owner-and-approval-status-gated function, and the seed rate only
-- inserts when the rates table is empty.

-- ============================================================================================
-- Migration 48: Guild Event financial agreement — turns "prize_structure" and "guild_share_bps"
-- on guild_events (45_migration_guild_event_creation_workflow.sql) from planning-only numbers
-- nobody enforces into a real, locked commitment that:
--   1. Any signed-in person can read before they ever pay to enter (guild_event_financial_
--      agreements has the same broad "anyone signed in" read policy guild_events itself does —
--      see that migration's own comment on why a guild-hosted event is open to any reader, not
--      just guild members).
--   2. The guild owner can only set or change while the event is still 'draft'/'rejected' — the
--      exact same editable window update_guild_event_draft already enforces on the event's other
--      fields, so the two can never drift out of sync (an owner who wants to change the money
--      split after submitting has to edit the whole event back to draft, which already resets
--      the review trail — see that migration's header).
--   3. Gets permanently locked (locked = true) the moment activate_guild_event() actually opens
--      the event for entries — the first moment any money can move, same "lock at the moment
--      revenue can begin" reasoning publish_guild_anthology already uses for
--      guild_anthology_revenue_agreements (36_migration_guild_anthology_revenue_agreements.sql).
--   4. Is what settle_guild_event() itself now checks, not just what the create form once
--      showed: declared winner shares must add up to EXACTLY the locked prize_pool_bps, no more
--      and no less. Since distribute_guild_revenue already hands the guild everything the
--      winners weren't credited (v_gross - v_member_credited — see 42_migration_guild_events.sql),
--      pinning the winners' total to an exact, pre-committed number is what pins the guild's own
--      take to an exact, pre-committed number too — an organizer can no longer quietly shrink
--      what winners get and keep the difference, because "quietly" is no longer possible: the
--      number participants were shown before paying is the only number the database will settle
--      against.
--
-- What this migration deliberately does NOT change: entry_fee_kobo is still what an entrant
-- actually pays, and Inkroot's own per-entry cut (PLATFORM_FEE_BPS, applied the instant an entry
-- is charged — see paystack-init-event-entry) is still computed exactly as it always was and
-- still lands in guild_event_entries.net_kobo before this agreement ever sees a kobo. This
-- agreement only governs how that already-net pool is split between "goes to declared winners"
-- (prize_pool_bps) and "goes straight to the guild's own treasury" (guild_share_bps + every named
-- other_allocations line, e.g. a judges' honorarium or a charity cut the guild committed to
-- carving out of its own share — those still land in the guild's treasury balance as one
-- credit, same as guild_share_bps always has; a guild owner who actually wants to pay a named
-- allocation out to someone outside the app still does that via the guild's own existing
-- spend_from_guild_treasury/propose_guild_treasury_spend flow — this migration's guarantee
-- is that the *percentage* promised for that purpose is locked and visible, not that this
-- migration invents a new payment rail). platform_fee_bps on the agreement itself is a display
-- snapshot only — it records what the client (via the existing platform-fee-info function)
-- reported as Inkroot's live per-entry cut at the moment the agreement was proposed, purely so
-- the breakdown shown to a participant stays internally consistent even if Inkroot's own
-- PLATFORM_FEE_BPS constant changes later. It is never itself used to compute a charge; nothing
-- about how paystack-init-event-entry actually charges an entrant changes here.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. guild_event_financial_agreements — one per event. share_bps values are basis points
-- (10000 = 100%), same convention every other split in this schema already uses.
-- ----------------------------------------------------------------------------------------------

create or replace function guild_event_other_allocations_bps(p jsonb)
returns integer
language sql
immutable
as $$
  select coalesce(sum(coalesce((elem->>'bps')::integer, 0)), 0)::integer
  from jsonb_array_elements(coalesce(p, '[]'::jsonb)) elem;
$$;

create table if not exists guild_event_financial_agreements (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null unique references guild_events(id) on delete cascade,
  guild_id uuid not null references player_guilds(id) on delete cascade,
  -- Display snapshot only — see migration header. Never used to compute an actual charge.
  platform_fee_bps integer not null check (platform_fee_bps >= 0 and platform_fee_bps <= 10000),
  -- Share of the NET pool (post-platform-fee, i.e. the same figure guild_event_entries.net_kobo
  -- already sums at settlement) that must go to declared winners — enforced exactly, see
  -- settle_guild_event below.
  prize_pool_bps integer not null check (prize_pool_bps > 0 and prize_pool_bps <= 10000),
  -- Share of the net pool that goes straight to the guild's own treasury balance, with no named
  -- purpose attached — the organizer's own discretionary cut.
  guild_share_bps integer not null check (guild_share_bps >= 0 and guild_share_bps <= 10000),
  -- Named carve-outs of the guild's own take, e.g. [{"label": "Judges' honorarium", "bps": 500}].
  -- These still land in the guild treasury as part of the same single credit guild_share_bps
  -- always produced (see migration header) — what's locked here is the promise of how much
  -- of that credit was earmarked for what, so participants (and the guild's own members
  -- reviewing the treasury ledger) can hold the organizer to it.
  other_allocations jsonb not null default '[]'::jsonb,
  check (prize_pool_bps + guild_share_bps + guild_event_other_allocations_bps(other_allocations) = 10000),
  revision integer not null default 1,
  locked boolean not null default false,
  locked_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table guild_event_financial_agreements enable row level security;

-- Same broad "anyone signed in" read as guild_events itself — the whole point is that a
-- prospective entrant can see exactly where their money would go before they ever pay (see
-- fetchGuildEventFinancialAgreement / the EventCard breakdown in guild-events-panel.jsx).
create policy "anyone signed in can read event financial agreements" on guild_event_financial_agreements
  for select using (auth.uid() is not null);

-- Deliberately no insert/update/delete policy — only propose_guild_event_financial_
-- agreement() (owner-only, draft/rejected-only) and activate_guild_event() (lock only) below,
-- both security definer, ever write this table. Same posture as every other locked-agreement
-- table in this schema (guild_anthology_revenue_agreements, guild_event_hosting_fee_payments).

create index if not exists guild_event_financial_agreements_guild_idx
  on guild_event_financial_agreements (guild_id);

-- ----------------------------------------------------------------------------------------------
-- 2. propose_guild_event_financial_agreement — the only way to set or change this
-- agreement. Owner-only, host='guild' only, and only while the event itself is still editable
-- (draft/rejected) — the identical window update_guild_event_draft already enforces, so
-- "can I still change the money split" is never a different question from "can I still change
-- the rest of the form."
-- ----------------------------------------------------------------------------------------------

create or replace function propose_guild_event_financial_agreement(
  p_guild_id uuid,
  p_event_id uuid,
  p_prize_pool_bps integer,
  p_guild_share_bps integer,
  p_other_allocations jsonb default '[]'::jsonb,
  p_platform_fee_bps integer default null
)
returns guild_event_financial_agreements
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_existing guild_event_financial_agreements%rowtype;
  v_found boolean;
  v_other_sum integer;
  v_row guild_event_financial_agreements;
  v_elem jsonb;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can set this event''s financial structure.';
  end if;

  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id for update;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.host <> 'guild' then
    raise exception 'An Inkroot-hosted prize has no entry fees to divide up — there''s nothing to set here.';
  end if;
  if v_event.approval_status not in ('draft', 'rejected') then
    raise exception 'This event''s financial structure can no longer be changed here — edit the event (which resets it to draft for re-review) to change it.';
  end if;

  if p_platform_fee_bps is null or p_platform_fee_bps < 0 or p_platform_fee_bps > 10000 then
    raise exception 'A valid current platform fee is required to record this agreement.';
  end if;
  if p_prize_pool_bps is null or p_prize_pool_bps <= 0 or p_prize_pool_bps > 10000 then
    raise exception 'The prize pool must be a positive share of the pool — participants are paying to compete for something.';
  end if;
  if p_guild_share_bps is null or p_guild_share_bps < 0 or p_guild_share_bps > 10000 then
    raise exception 'The guild share must be between 0%% and 100%%.';
  end if;

  for v_elem in select * from jsonb_array_elements(coalesce(p_other_allocations, '[]'::jsonb)) loop
    if coalesce(trim(v_elem->>'label'), '') = '' then
      raise exception 'Every other allocation needs a label — who or what it''s for.';
    end if;
    if char_length(v_elem->>'label') > 200 then
      raise exception 'An allocation label is too long.';
    end if;
    if (v_elem->>'bps') is null or (v_elem->>'bps')::integer < 0 or (v_elem->>'bps')::integer > 10000 then
      raise exception 'Every other allocation needs a share between 0%% and 100%%.';
    end if;
  end loop;

  v_other_sum := guild_event_other_allocations_bps(p_other_allocations);
  if p_prize_pool_bps + p_guild_share_bps + v_other_sum <> 10000 then
    raise exception 'The prize pool, guild share, and every other allocation must add up to exactly 100%% of the pool — they currently add up to % basis points.', (p_prize_pool_bps + p_guild_share_bps + v_other_sum);
  end if;

  select * into v_existing from guild_event_financial_agreements where event_id = p_event_id for update;
  v_found := found;
  if v_found and v_existing.locked then
    raise exception 'This event''s financial agreement is locked and can no longer be changed.';
  end if;

  if v_found then
    update guild_event_financial_agreements set
      platform_fee_bps = p_platform_fee_bps,
      prize_pool_bps = p_prize_pool_bps,
      guild_share_bps = p_guild_share_bps,
      other_allocations = coalesce(p_other_allocations, '[]'::jsonb),
      revision = v_existing.revision + 1,
      updated_at = now()
    where id = v_existing.id
    returning * into v_row;
  else
    insert into guild_event_financial_agreements
      (event_id, guild_id, platform_fee_bps, prize_pool_bps, guild_share_bps, other_allocations, created_by)
    values
      (p_event_id, p_guild_id, p_platform_fee_bps, p_prize_pool_bps, p_guild_share_bps,
       coalesce(p_other_allocations, '[]'::jsonb), auth.uid())
    returning * into v_row;
  end if;

  return v_row;
end;
$$;

revoke all on function propose_guild_event_financial_agreement(uuid, uuid, integer, integer, jsonb, integer) from public;
grant execute on function propose_guild_event_financial_agreement(uuid, uuid, integer, integer, jsonb, integer) to authenticated;

-- ----------------------------------------------------------------------------------------------
-- 3. submit_guild_event_for_approval — redefined only to also require a financial agreement
-- on file before a host='guild' event can even reach Inkroot's review queue, so the numbers
-- Inkroot approves are always the real, complete numbers — not a submission that still has
-- no committed money split.
-- ----------------------------------------------------------------------------------------------

create or replace function submit_guild_event_for_approval(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can submit this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status not in ('draft', 'rejected') then
    raise exception 'This event has already been submitted.';
  end if;
  if v_event.title is null or length(trim(v_event.title)) = 0
     or v_event.entry_fee_kobo is null or v_event.start_date is null or v_event.end_date is null then
    raise exception 'Fill in the title, entry fee, and start/end dates before submitting.';
  end if;
  if v_event.host = 'guild' and not exists (
    select 1 from guild_event_financial_agreements a where a.event_id = p_event_id
  ) then
    raise exception 'Set how entry fees will be divided — prize pool, guild share, and any other allocations — before submitting.';
  end if;

  update guild_events set approval_status = 'pending_approval', submitted_at = now(), rejection_reason = null
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 4. activate_guild_event — redefined only to lock the financial agreement in the same
-- breath it opens the event for entries. See migration header for why this is the right moment:
-- it's the first moment any money can actually move.
-- ----------------------------------------------------------------------------------------------

create or replace function activate_guild_event(p_guild_id uuid, p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_agreement guild_event_financial_agreements%rowtype;
begin
  if not is_guild_officer(p_guild_id) then
    raise exception 'Only the guild owner can activate this event.';
  end if;
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.approval_status <> 'published' then
    raise exception 'Publish this event before opening it for entries.';
  end if;

  if v_event.host = 'guild' then
    select * into v_agreement from guild_event_financial_agreements where event_id = p_event_id for update;
    if not found then
      raise exception 'This event has no financial agreement on file — it cannot open for entries.';
    end if;
    if not v_agreement.locked then
      update guild_event_financial_agreements set locked = true, locked_at = now() where id = v_agreement.id;
    end if;
  end if;

  update guild_events set approval_status = 'active', activated_at = now(), status = 'open'
  where id = p_event_id
  returning * into v_event;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 5. settle_guild_event — redefined only to enforce the locked agreement for host='guild'
-- events. host='inkroot' settlement (no entry fees, no agreement, Inkroot-only caller) is
-- completely unchanged — see migration 42's own header on why that path has always been
-- fully Inkroot-controlled already.
-- ----------------------------------------------------------------------------------------------

create or replace function settle_guild_event(p_guild_id uuid, p_event_id uuid, p_shares jsonb)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_gross bigint;
  v_bad_contributor uuid;
  v_agreement guild_event_financial_agreements%rowtype;
  v_shares_sum integer;
begin
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;

  if v_event.host = 'guild' then
    if not is_guild_officer(p_guild_id) then
      raise exception 'Only the guild owner can settle this event.';
    end if;
  else -- 'inkroot'
    if auth.uid() is not null then
      raise exception 'Inkroot-hosted events are settled by Inkroot directly.';
    end if;
  end if;

  perform pg_advisory_xact_lock(hashtext('guild_event_settlement:' || p_event_id::text));
  select * into v_event from guild_events where id = p_event_id; -- re-read under the lock
  if v_event.status = 'settled' then
    raise exception 'This event has already been settled.';
  end if;

  select (s->>'contributor_id')::uuid into v_bad_contributor
  from jsonb_array_elements(p_shares) s
  where not exists (
    select 1 from player_guild_members m
    where m.guild_id = p_guild_id and m.user_id = (s->>'contributor_id')::uuid
  )
  limit 1;
  if v_bad_contributor is not null then
    raise exception 'Every winner must be a member of this guild.';
  end if;

  if v_event.host = 'guild' then
    -- The locked agreement is what participants were shown before they ever paid to enter (see
    -- migration header) — winner shares must add up to EXACTLY that prize pool percentage,
    -- not merely "no more than," so the guild's own take (whatever distribute_guild_revenue
    -- doesn't credit to a winner) is always exactly the locked remainder. This is the actual
    -- enforcement: an organizer cannot under-declare winners' shares to quietly keep more for
    -- the guild than what participants agreed to before paying.
    select * into v_agreement from guild_event_financial_agreements where event_id = p_event_id;
    if not found or not v_agreement.locked then
      raise exception 'This event has no locked financial agreement — it cannot be settled.';
    end if;

    select coalesce(sum((s->>'share_bps')::integer), 0) into v_shares_sum
    from jsonb_array_elements(p_shares) s;
    if v_shares_sum <> v_agreement.prize_pool_bps then
      raise exception 'Winner shares must add up to exactly the locked prize pool share — % basis points of the pool, no more and no less.', v_agreement.prize_pool_bps;
    end if;

    -- The verified pool: every successfully-paid entry's already-fee-applied net amount. Never
    -- amount_kobo (that's what the entrant paid, before Inkroot's cut).
    select coalesce(sum(net_kobo), 0) into v_gross
    from guild_event_entries where event_id = p_event_id and status = 'success';
  else
    v_gross := v_event.cash_prize_kobo; -- fixed, no fee — see migration 42's own header
  end if;

  perform distribute_guild_revenue(
    p_guild_id := p_guild_id,
    p_gross_amount_kobo := v_gross,
    p_shares := p_shares,
    p_kind := 'event_revenue',
    p_source := 'event_sale',
    p_source_purchase_id := null,
    p_anthology_id := null,
    p_project_event_id := p_event_id,
    p_title := 'Guild event — ' || v_event.title
  );

  update guild_events set status = 'settled', settled_at = now() where id = p_event_id;
  select * into v_event from guild_events where id = p_event_id;
  return v_event;
end;
$$;

revoke all on function settle_guild_event(uuid, uuid, jsonb) from public;
grant execute on function settle_guild_event(uuid, uuid, jsonb) to authenticated;

-- ----------------------------------------------------------------------------------------------
-- 6. admin_list_pending_guild_events — return type extended (drop + recreate, since
-- CREATE OR REPLACE can't change a set-returning function's output columns) so Inkroot's review
-- queue shows the real, committed financial agreement alongside everything else it already
-- reviewed — not just the old planning-only prize_structure/guild_share_bps fields.
-- ----------------------------------------------------------------------------------------------

drop function if exists admin_list_pending_guild_events();

create function admin_list_pending_guild_events()
returns table (
  id uuid, guild_id uuid, guild_name text, title text, description text, rules text,
  event_type text, entry_fee_kobo bigint, participant_limit integer, prize_structure jsonb,
  guild_share_bps integer, start_date timestamptz, end_date timestamptz,
  organizer_id uuid, cover_image_url text, submitted_at timestamptz, created_by uuid,
  financial_platform_fee_bps integer, financial_prize_pool_bps integer,
  financial_guild_share_bps integer, financial_other_allocations jsonb
)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can review guild event submissions.';
  end if;
  return query
    select e.id, e.guild_id, g.name, e.title, e.description, e.rules,
           e.event_type, e.entry_fee_kobo, e.participant_limit, e.prize_structure,
           e.guild_share_bps, e.start_date, e.end_date,
           e.organizer_id, e.cover_image_url, e.submitted_at, e.created_by,
           a.platform_fee_bps, a.prize_pool_bps, a.guild_share_bps, a.other_allocations
    from guild_events e
    join player_guilds g on g.id = e.guild_id
    left join guild_event_financial_agreements a on a.event_id = e.id
    where e.approval_status = 'pending_approval'
    order by e.submitted_at asc nulls last;
end;
$$;

revoke all on function admin_list_pending_guild_events() from public;
grant execute on function admin_list_pending_guild_events() to authenticated;

-- Safe to run anytime: the new table starts empty and only ever written by the two functions
-- above; every redefined function (submit_guild_event_for_approval, activate_guild_event,
-- settle_guild_event) keeps its exact prior signature and grants, and only tightens behavior for
-- host='guild' events that now must go through this migration's new agreement — any event
-- already sitting in 'active' or beyond from before this migration ran has no agreement row and
-- will correctly be refused at settlement until its owner is treated as needing one (in practice,
-- run this before any such event reaches settlement, or backfill an agreement for it directly).

-- ============================================================================================
-- Migration 49: Guild Event results — organizer submission + required approval, on top of the
-- settlement engine 42_migration_guild_events.sql already built (settle_guild_event() /
-- distribute_guild_revenue() already create payout records, credit winners, credit the guild's
-- own share, and record everything in guild_treasury_transactions — nothing about how money
-- actually moves changes here).
--
-- Before this migration, only the guild owner could settle an event, and only by declaring
-- winners and paying them out in the same action (guild-events-panel.jsx's "Declare winners"
-- form calling settle_guild_event() directly). That's left fully working — a guild owner who
-- wants to settle an event themselves still can. This migration adds a second, delegated path:
--
--   1. submit_guild_event_results() — the event's own organizer (guild_events.organizer_id,
--      from 45_migration_guild_event_creation_workflow.sql) proposes winner placements once the
--      event is marked 'completed'. Nothing is paid out yet — this only records a proposal
--      (guild_event_results, status='pending_approval').
--   2. approve_guild_event_results() — a guild authority (Leader/Treasurer/Officer — same
--      is_guild_treasury_authorized() role check 44_migration_guild_treasury_roles_and_approvals
--      .sql already uses for guild-owned-fund spends) reviews the proposal and, if it approves,
--      this is the one call that actually settles the event: it hands the organizer's declared
--      placements to the existing settle_guild_event() unchanged, which creates the payout
--      records, credits winners, credits the guild's own remainder, and writes the ledger rows —
--      exactly as it always has for a direct owner settle.
--   3. reject_guild_event_results() — sends a proposal back with a reason; the organizer can
--      revise and resubmit (submit_guild_event_results upserts the same row rather than piling
--      up duplicates).
--
-- Four-eyes, not rubber-stamped: the same person who submitted a proposal can never also approve
-- or reject it (checked explicitly in both functions below), so results can't become final on
-- one person's say-so alone.
--
-- Duplicate-payout protection is layered exactly the way 42's own header describes, plus one
-- more layer specific to this workflow:
--   a. guild_event_results.status only ever moves pending_approval -> approved (terminal) or
--      pending_approval -> rejected (resubmittable back to pending_approval) — approve_guild_
--      event_results() re-checks status = 'pending_approval' under a row lock before doing
--      anything, so two concurrent approvals of the same proposal can't both go through.
--   b. The actual settlement still goes through settle_guild_event(), whose own advisory lock
--      and guild_events.status = 'settled' check (unchanged) is what makes it impossible to pay
--      the same event out twice regardless of which path (direct owner settle, or this
--      submit-then-approve path) got there first.
--   c. distribute_guild_revenue()'s own project_event_id dedup (unchanged) is the final,
--      independent backstop even if (a) and (b) were ever bypassed.
--   d. unique(event_id) on guild_event_results means there is only ever one results row per
--      event — a resubmission after rejection overwrites it in place rather than creating a
--      second competing proposal.
--
-- settle_guild_event() itself is widened here from "guild owner only" to any authorized guild
-- role (Leader/Treasurer/Officer) — the same broadening 44_migration_guild_treasury_roles_and_
-- approvals.sql already did for spend_from_guild_treasury, so a Treasurer or Officer approving
-- results can actually settle the event and not just record an approval that then fails. The
-- guild owner (always 'leader') still qualifies, so a solo-owner guild loses nothing — but see
-- the four-eyes rule above: the owner still can't approve their own submission if they're also
-- the event's organizer.
--
-- Safe to run anytime: guild_event_results is a brand-new table (starts empty), and settle_
-- guild_event() keeps its exact prior signature and every prior check (locked financial
-- agreement, exact prize-pool-bps match, member-only winners) — only its authorization check
-- widens, which can never turn a previously-allowed caller into a refused one.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. guild_event_results — one row per event's (current) results proposal.
-- ----------------------------------------------------------------------------------------------

create table if not exists guild_event_results (
  id uuid primary key default gen_random_uuid(),
  guild_id uuid not null references player_guilds(id) on delete cascade,
  event_id uuid not null references guild_events(id) on delete cascade,
  -- [{"contributor_id": "...", "place": 1, "share_bps": 5000}, ...] — the organizer's proposed
  -- payout. Mirrors settle_guild_event()'s own p_shares shape (contributor_id/share_bps) plus
  -- `place`, which is informational (mirrors prize_structure's own "informational, never
  -- enforced" posture from 45_migration_guild_event_creation_workflow.sql) — approval hands
  -- contributor_id/share_bps straight to settle_guild_event(), which re-validates all of it
  -- server-side exactly as it always has.
  placements jsonb not null,
  status text not null default 'pending_approval' check (status in ('pending_approval', 'approved', 'rejected')),
  submitted_by uuid references auth.users(id) on delete set null,
  submitted_at timestamptz not null default now(),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  rejection_reason text check (char_length(rejection_reason) <= 2000),
  settled_at timestamptz,
  unique (event_id)
);

alter table guild_event_results enable row level security;

-- The organizer who submitted a proposal can always read it back (to see rejection reasons,
-- track its status, etc).
create policy "organizer reads their own submitted results" on guild_event_results
  for select using (auth.uid() = submitted_by);
-- Same authority that can approve/reject can also just browse the queue.
create policy "guild treasury authority reads event results" on guild_event_results
  for select using (is_guild_treasury_authorized(guild_id));
-- No client insert/update policy — every write goes through the three functions below, which
-- re-check organizer/authority server-side exactly like every other write in this ledger.

create index if not exists guild_event_results_pending_idx
  on guild_event_results (guild_id) where status = 'pending_approval';

-- ----------------------------------------------------------------------------------------------
-- 2. submit_guild_event_results — organizer-only, and only once the event is 'completed'.
-- Upserts the single row for this event: a first submission inserts, a resubmission after
-- rejection overwrites it in place and resets it to 'pending_approval'. Refuses outright once a
-- prior submission has already been approved (and therefore already paid out).
-- ----------------------------------------------------------------------------------------------

create or replace function submit_guild_event_results(p_guild_id uuid, p_event_id uuid, p_placements jsonb)
returns guild_event_results
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_agreement guild_event_financial_agreements%rowtype;
  v_row guild_event_results%rowtype;
  v_bad_contributor uuid;
  v_shares_sum integer;
  v_dup_place boolean;
begin
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;
  if v_event.host <> 'guild' then
    raise exception 'Inkroot-hosted events are settled by Inkroot directly.';
  end if;
  if v_event.organizer_id is null or auth.uid() <> v_event.organizer_id then
    raise exception 'Only this event''s organizer can submit its results.';
  end if;
  if v_event.approval_status <> 'completed' then
    raise exception 'Mark the event completed before submitting results.';
  end if;
  if v_event.status = 'settled' then
    raise exception 'This event has already been settled.';
  end if;

  if p_placements is null or jsonb_array_length(p_placements) = 0 then
    raise exception 'Add at least one winner.';
  end if;

  select (p->>'contributor_id')::uuid into v_bad_contributor
  from jsonb_array_elements(p_placements) p
  where not exists (
    select 1 from player_guild_members m
    where m.guild_id = p_guild_id and m.user_id = (p->>'contributor_id')::uuid
  )
  limit 1;
  if v_bad_contributor is not null then
    raise exception 'Every winner must be a member of this guild.';
  end if;

  select exists (
    select 1 from jsonb_array_elements(p_placements) p
    group by (p->>'place')
    having count(*) > 1
  ) into v_dup_place;
  if v_dup_place then
    raise exception 'Each place (1st, 2nd, ...) can only be used once.';
  end if;

  -- Fail fast with the same check settle_guild_event() enforces at approval time (exact match
  -- to the locked prize pool share), rather than letting an organizer submit something an
  -- approver can never actually approve.
  select * into v_agreement from guild_event_financial_agreements where event_id = p_event_id;
  if not found or not v_agreement.locked then
    raise exception 'This event has no locked financial agreement — it cannot be settled.';
  end if;
  select coalesce(sum((p->>'share_bps')::integer), 0) into v_shares_sum
  from jsonb_array_elements(p_placements) p;
  if v_shares_sum <> v_agreement.prize_pool_bps then
    raise exception 'Winner shares must add up to exactly the locked prize pool share — % basis points of the pool, no more and no less.', v_agreement.prize_pool_bps;
  end if;

  select * into v_row from guild_event_results where event_id = p_event_id for update;
  if found and v_row.status = 'approved' then
    raise exception 'Results for this event have already been approved and paid out.';
  end if;

  insert into guild_event_results (guild_id, event_id, placements, status, submitted_by, submitted_at)
  values (p_guild_id, p_event_id, p_placements, 'pending_approval', auth.uid(), now())
  on conflict (event_id) do update set
    placements = excluded.placements,
    status = 'pending_approval',
    submitted_by = excluded.submitted_by,
    submitted_at = excluded.submitted_at,
    reviewed_by = null,
    reviewed_at = null,
    rejection_reason = null,
    settled_at = null
  returning * into v_row;
  return v_row;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 3. approve_guild_event_results — the moment a proposal becomes final. Requires an authorized
-- guild role, distinct from whoever submitted it, and a still-pending proposal. Delegates the
-- actual money movement entirely to the existing settle_guild_event() — see this migration's
-- header for why nothing about payout creation/crediting/ledgering is duplicated here.
-- ----------------------------------------------------------------------------------------------

create or replace function approve_guild_event_results(p_event_id uuid)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_results guild_event_results%rowtype;
  v_event guild_events%rowtype;
  v_shares jsonb;
begin
  select * into v_results from guild_event_results where event_id = p_event_id for update;
  if not found then
    raise exception 'No results have been submitted for this event yet.';
  end if;
  if v_results.status = 'approved' then
    raise exception 'These results have already been approved.';
  end if;
  if v_results.status <> 'pending_approval' then
    raise exception 'These results were rejected — the organizer must resubmit before they can be approved.';
  end if;

  if not is_guild_treasury_authorized(v_results.guild_id) then
    raise exception 'Only the guild leader, a treasurer, or an officer can approve event results.';
  end if;
  if auth.uid() = v_results.submitted_by then
    raise exception 'The organizer who submitted these results cannot also approve them.';
  end if;

  select jsonb_agg(jsonb_build_object('contributor_id', p->>'contributor_id', 'share_bps', (p->>'share_bps')::integer))
  into v_shares
  from jsonb_array_elements(v_results.placements) p;

  -- The one call that actually moves money — every check settle_guild_event() has always made
  -- (locked-agreement exact match, member-only winners, dedup lock, one-settlement-ever) still
  -- applies in full; this function adds the submit/approve workflow around it, not a second way
  -- to move money.
  v_event := settle_guild_event(v_results.guild_id, p_event_id, v_shares);

  update guild_event_results
  set status = 'approved', reviewed_by = auth.uid(), reviewed_at = now(), settled_at = now()
  where event_id = p_event_id;

  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 4. reject_guild_event_results — sends a pending proposal back with a reason. The organizer can
-- then call submit_guild_event_results() again, which overwrites this same row.
-- ----------------------------------------------------------------------------------------------

create or replace function reject_guild_event_results(p_event_id uuid, p_reason text)
returns guild_event_results
language plpgsql security definer set search_path = public as $$
declare
  v_results guild_event_results%rowtype;
begin
  select * into v_results from guild_event_results where event_id = p_event_id for update;
  if not found then
    raise exception 'No results have been submitted for this event yet.';
  end if;
  if v_results.status <> 'pending_approval' then
    raise exception 'These results have already been decided.';
  end if;
  if not is_guild_treasury_authorized(v_results.guild_id) then
    raise exception 'Only the guild leader, a treasurer, or an officer can reject event results.';
  end if;
  if auth.uid() = v_results.submitted_by then
    raise exception 'The organizer who submitted these results cannot also reject them.';
  end if;

  update guild_event_results
  set status = 'rejected', reviewed_by = auth.uid(), reviewed_at = now(), rejection_reason = p_reason
  where event_id = p_event_id
  returning * into v_results;
  return v_results;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 5. settle_guild_event — redefined only to widen its host='guild' authorization check from
-- "guild owner only" to any authorized guild role (Leader/Treasurer/Officer), matching 44_
-- migration_guild_treasury_roles_and_approvals.sql's own broadening of guild-owned-fund
-- authority. Every other check (locked agreement, exact prize-pool-bps match, member-only
-- winners, advisory lock, one-settlement-ever) is byte-for-byte identical to the version in
-- 48_migration_guild_event_financial_agreement.sql. host='inkroot' settlement is untouched.
-- ----------------------------------------------------------------------------------------------

create or replace function settle_guild_event(p_guild_id uuid, p_event_id uuid, p_shares jsonb)
returns guild_events
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_gross bigint;
  v_bad_contributor uuid;
  v_agreement guild_event_financial_agreements%rowtype;
  v_shares_sum integer;
begin
  select * into v_event from guild_events where id = p_event_id and guild_id = p_guild_id;
  if not found then
    raise exception 'Guild event not found.';
  end if;

  if v_event.host = 'guild' then
    if not is_guild_treasury_authorized(p_guild_id) then
      raise exception 'Only the guild leader, a treasurer, or an officer can settle this event.';
    end if;
  else -- 'inkroot'
    if auth.uid() is not null then
      raise exception 'Inkroot-hosted events are settled by Inkroot directly.';
    end if;
  end if;

  perform pg_advisory_xact_lock(hashtext('guild_event_settlement:' || p_event_id::text));
  select * into v_event from guild_events where id = p_event_id; -- re-read under the lock
  if v_event.status = 'settled' then
    raise exception 'This event has already been settled.';
  end if;

  select (s->>'contributor_id')::uuid into v_bad_contributor
  from jsonb_array_elements(p_shares) s
  where not exists (
    select 1 from player_guild_members m
    where m.guild_id = p_guild_id and m.user_id = (s->>'contributor_id')::uuid
  )
  limit 1;
  if v_bad_contributor is not null then
    raise exception 'Every winner must be a member of this guild.';
  end if;

  if v_event.host = 'guild' then
    select * into v_agreement from guild_event_financial_agreements where event_id = p_event_id;
    if not found or not v_agreement.locked then
      raise exception 'This event has no locked financial agreement — it cannot be settled.';
    end if;

    select coalesce(sum((s->>'share_bps')::integer), 0) into v_shares_sum
    from jsonb_array_elements(p_shares) s;
    if v_shares_sum <> v_agreement.prize_pool_bps then
      raise exception 'Winner shares must add up to exactly the locked prize pool share — % basis points of the pool, no more and no less.', v_agreement.prize_pool_bps;
    end if;

    select coalesce(sum(net_kobo), 0) into v_gross
    from guild_event_entries where event_id = p_event_id and status = 'success';
  else
    v_gross := v_event.cash_prize_kobo;
  end if;

  perform distribute_guild_revenue(
    p_guild_id := p_guild_id,
    p_gross_amount_kobo := v_gross,
    p_shares := p_shares,
    p_kind := 'event_revenue',
    p_source := 'event_sale',
    p_source_purchase_id := null,
    p_anthology_id := null,
    p_project_event_id := p_event_id,
    p_title := 'Guild event — ' || v_event.title
  );

  update guild_events set status = 'settled', settled_at = now() where id = p_event_id;
  select * into v_event from guild_events where id = p_event_id;
  return v_event;
end;
$$;

-- ----------------------------------------------------------------------------------------------
-- 6. Grants.
-- ----------------------------------------------------------------------------------------------

revoke all on function submit_guild_event_results(uuid, uuid, jsonb) from public;
revoke all on function approve_guild_event_results(uuid) from public;
revoke all on function reject_guild_event_results(uuid, text) from public;
revoke all on function settle_guild_event(uuid, uuid, jsonb) from public;

grant execute on function submit_guild_event_results(uuid, uuid, jsonb) to authenticated;
grant execute on function approve_guild_event_results(uuid) to authenticated;
grant execute on function reject_guild_event_results(uuid, text) to authenticated;
grant execute on function settle_guild_event(uuid, uuid, jsonb) to authenticated;

-- Safe to run anytime — see this migration's header.

-- ============================================================================================
-- Migration 50: Guild Economy / Living Universe security audit — fixes for the vulnerabilities
-- actually found, not a rewrite of what already held up. Most of the checklist this audit was
-- run against was already correctly closed by earlier migrations (see the per-item notes below,
-- kept here as the audit record); this migration only changes the handful of real gaps.
--
-- FOUND AND FIXED HERE:
--
--   1. Duplicate/over withdrawals (real bank payouts) — paystack-withdraw previously read
--      author_balance_kobo() and inserted the `withdrawals` row as two separate round trips from
--      the Edge Function, with no lock between them. Two concurrent withdrawal requests could
--      both read the same starting balance and both pass the check, paying out more than the
--      author actually earned. Every OTHER balance-checked write in this schema (contribute_to_
--      guild_treasury, spend_from_guild_treasury, withdraw_guild_member_earnings,
--      propose_guild_treasury_spend/approve_guild_treasury_spend) already serializes its
--      check-then-write under pg_advisory_xact_lock — this was the one path that didn't.
--      create_withdrawal_locked() below closes it the same way, using the SAME lock key
--      (hashtext(user_id)) contribute_to_guild_treasury/withdraw_guild_member_earnings already
--      use — a withdrawal now also correctly serializes against a concurrent guild contribution
--      or earnings release for the same writer, not just against another concurrent withdrawal.
--
--   2. Refund/chargeback abuse — there was no path for a Paystack refund or card-dispute event to
--      ever reach purchases/guild_event_entries/guild_event_hosting_fee_payments. A buyer who
--      disputed a charge with their bank (or requested a Paystack refund) after the sale had
--      already credited an author or a guild would keep whatever they bought, and the row would
--      stay 'success' forever with no way to exclude it from a balance or a not-yet-settled event
--      pool. 'refunded' is added as a real terminal status, and the webhook below flips a
--      matching 'success' row to it on refund.processed / charge.dispute.create — author_
--      balance_kobo() and settle_guild_event()'s pool sum already only count status = 'success',
--      so a refunded row is automatically excluded from both once its status changes; no other
--      function needed to change. (A refund that arrives AFTER an event has already settled or a
--      purchase has already been withdrawn can't claw back money that's already left the ledger —
--      no different from how a real payment processor's own settlement finality works; that's a
--      business decision for an operator to handle manually, not something this migration can
--      undo automatically.)
--
--   3. A reversed transfer being silently ignored — paystack-webhook's transfer.failed/
--      transfer.reversed handler only ever matched a withdrawal row still 'status = pending'. A
--      transfer that succeeds and is LATER reversed by the receiving bank (transfer.reversed
--      fires after transfer.success already flipped the row to 'success') never matched that
--      filter, so the row stayed 'success' forever — meaning the author's real balance stayed
--      permanently reduced by money that was actually returned to the platform, with no way for
--      them to withdraw it again. The handler now also matches a currently-'success' row, so a
--      reversal correctly flips it to 'failed' and the writer's available balance (which excludes
--      non-'success' withdrawals) is restored.
--
--   4. Guild Event entry race (participant_limit oversell, and duplicate-entry check) — paystack-
--      init-event-entry checked "already entered" and "under the participant limit" as two plain
--      SELECTs before inserting, all from the Edge Function, with nothing serializing concurrent
--      requests for the same event. create_guild_event_entry_locked() below moves that whole
--      check-then-insert into one security-definer function under an advisory lock keyed to the
--      event (same lock key settle_guild_event() already uses for this event, so an entry can't
--      race a settlement either), so a participant-limited event can never oversell and the
--      duplicate-entry check can never be beaten by two simultaneous requests.
--
-- AUDITED AND ALREADY CORRECT — no change needed, kept here as the record of what was checked:
--
--   - Duplicate payments: purchases/guild_event_entries/guild_event_hosting_fee_payments all
--     have unique paystack_reference and no client insert/update policy; paystack-webhook only
--     ever flips a still-'pending' row, so a retried webhook delivery can't double-credit.
--   - Fake event entries / fake sales: both tables are only ever written by their own Edge
--     Function (server-derived amount, real event/book lookup) — RLS grants no client insert.
--   - Revenue split manipulation: distribute_guild_revenue()'s dedup (by source_purchase_id or
--     project_event_id) makes every distribution one-shot; settle_guild_event() requires winner
--     shares to match the LOCKED financial agreement exactly; anthology revenue agreements
--     require every contributor's own approval and reset all approvals on any re-propose.
--   - Leaving/rejoining guilds: guild_join_events is an insert-only, unique(guild_id, user_id)
--     ledger — "new member" credit (Guilds on the Rise scoring) can only ever be earned once per
--     person per guild, no matter how many times they leave and rejoin.
--   - Client-side balance manipulation: every balance (author_balance_kobo, guild_treasury_*,
--     guild_member_earnings) is a server-side function over an append-only ledger the client
--     cannot write to directly — there is no stored balance column a client write could corrupt.
--   - Ranking manipulation / fake reading activity: book_read_events caps one counted read per
--     (book, reader) per UTC day and refuses a book's own author a read on their own work;
--     Rising Star / Guilds on the Rise scoring is windowed, diminishing-returns curved, and
--     floored against low-distinct-participant collusion — see migrations 38/40's own headers.
--   - Unauthorized treasury access: guild_treasury_transactions has no client insert/update
--     policy at all; every write goes through a security-definer RPC that re-derives the caller's
--     role (Leader/Treasurer/Officer) from player_guilds.owner_id/player_guild_members.role
--     itself, never from a client-supplied flag.
--   - Race conditions: audited exhaustively above — items 1 and 4 were the two real gaps found;
--     every other balance-checked write already held an appropriate advisory lock.
--
-- Safe to run anytime: the widened status checks accept every value they already did plus
-- 'refunded', the two new functions are additive, and the reversed-transfer fix only changes
-- behavior for a webhook event this deployment couldn't previously handle correctly at all.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. 'refunded' as a real terminal status alongside 'success'/'failed'/'pending'.
-- ----------------------------------------------------------------------------------------------

alter table purchases drop constraint if exists purchases_status_check;
alter table purchases add constraint purchases_status_check
  check (status in ('pending', 'success', 'failed', 'refunded'));

alter table guild_event_entries drop constraint if exists guild_event_entries_status_check;
alter table guild_event_entries add constraint guild_event_entries_status_check
  check (status in ('pending', 'success', 'failed', 'refunded'));

alter table guild_event_hosting_fee_payments drop constraint if exists guild_event_hosting_fee_payments_status_check;
alter table guild_event_hosting_fee_payments add constraint guild_event_hosting_fee_payments_status_check
  check (status in ('pending', 'success', 'failed', 'refunded'));

-- ----------------------------------------------------------------------------------------------
-- 2. create_withdrawal_locked — the one place a withdrawals row is ever created. Takes an
-- explicit p_user_id (like author_balance_kobo's own check_user_id) rather than auth.uid(),
-- because it's called by paystack-withdraw using the service-role client — the Edge Function has
-- already authenticated the caller via their own JWT (requireUser) before ever reaching this;
-- this function is the atomic "check the real balance and create the row" step, not the identity
-- check. service-role-only by both the runtime check below AND by never being granted to
-- authenticated — a signed-in client cannot call this directly and pass someone else's user id.
-- ----------------------------------------------------------------------------------------------

create or replace function create_withdrawal_locked(
  p_user_id uuid, p_bank_account_id uuid, p_amount_kobo bigint
)
returns withdrawals
language plpgsql security definer set search_path = public as $$
declare
  v_row withdrawals;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized.';
  end if;
  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not exists (select 1 from bank_accounts where id = p_bank_account_id and user_id = p_user_id) then
    raise exception 'Saved bank account not found.';
  end if;

  -- Same lock key contribute_to_guild_treasury()/withdraw_guild_member_earnings() already lock
  -- on for this exact writer — a withdrawal now serializes against those too, not just against
  -- another concurrent withdrawal attempt.
  perform pg_advisory_xact_lock(hashtext(p_user_id::text));
  if author_balance_kobo(p_user_id) < p_amount_kobo then
    raise exception 'Amount is more than your available balance.';
  end if;

  insert into withdrawals (user_id, bank_account_id, amount_kobo, status)
  values (p_user_id, p_bank_account_id, p_amount_kobo, 'pending')
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function create_withdrawal_locked(uuid, uuid, bigint) from public;

-- ------------------------------------------------------------------------------------------------
-- create_manual_withdrawal_locked — the manual-path sibling of create_withdrawal_locked
-- immediately above. Identical shape and identical posture (see 62_migration_manual_withdrawals.sql
-- for why a second withdrawal method exists at all): explicit p_user_id because it's called by
-- manual-withdraw using the service-role client, service-role-only by both the runtime check and
-- by never being granted to authenticated, same advisory-lock key so it serializes against every
-- other thing that touches this writer's balance.
-- ------------------------------------------------------------------------------------------------

create or replace function create_manual_withdrawal_locked(
  p_user_id uuid, p_bank_account_id uuid, p_amount_kobo bigint
)
returns withdrawals
language plpgsql security definer set search_path = public as $$
declare
  v_row withdrawals;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized.';
  end if;
  if p_amount_kobo is null or p_amount_kobo <= 0 then
    raise exception 'Amount must be positive.';
  end if;
  if not exists (select 1 from bank_accounts where id = p_bank_account_id and user_id = p_user_id) then
    raise exception 'Saved bank account not found.';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_user_id::text));
  if author_balance_kobo(p_user_id) < p_amount_kobo then
    raise exception 'Amount is more than your available balance.';
  end if;

  insert into withdrawals (user_id, bank_account_id, amount_kobo, status, method)
  values (p_user_id, p_bank_account_id, p_amount_kobo, 'pending', 'manual')
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function create_manual_withdrawal_locked(uuid, uuid, bigint) from public;

-- ------------------------------------------------------------------------------------------------
-- admin_list_pending_manual_withdrawals / admin_settle_manual_withdrawal — the manual withdrawal
-- review queue, gated by is_inkroot_admin() same as every other Inkroot admin action. Unlike
-- create_manual_withdrawal_locked above, these two ARE meant to be called directly by a signed-in
-- admin's own client — settling a request is pure bookkeeping (the actual bank transfer happens
-- outside the app, by hand), not a call to any external API needing a service-role secret.
-- ------------------------------------------------------------------------------------------------

create or replace function admin_list_pending_manual_withdrawals()
returns table (
  id uuid, user_id uuid, writer_name text, amount_kobo bigint,
  bank_name text, account_number text, account_name text, created_at timestamptz
)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only a platform admin can view manual withdrawal requests.';
  end if;
  return query
    select w.id, w.user_id, coalesce(p.pen_name, p.display_name, 'Unnamed writer'), w.amount_kobo,
           b.bank_name, b.account_number, b.account_name, w.created_at
    from withdrawals w
    join bank_accounts b on b.id = w.bank_account_id
    left join profiles p on p.id = w.user_id
    where w.method = 'manual' and w.status = 'pending'
    order by w.created_at asc;
end;
$$;

revoke all on function admin_list_pending_manual_withdrawals() from public;
grant execute on function admin_list_pending_manual_withdrawals() to authenticated;

create or replace function admin_settle_manual_withdrawal(
  p_withdrawal_id uuid, p_new_status text, p_note text default null
)
returns withdrawals
language plpgsql security definer set search_path = public as $$
declare
  v_row withdrawals;
begin
  if not is_inkroot_admin() then
    raise exception 'Only a platform admin can settle a manual withdrawal.';
  end if;
  if p_new_status not in ('success', 'failed') then
    raise exception 'Status must be success or failed.';
  end if;

  select * into v_row from withdrawals where id = p_withdrawal_id for update;
  if not found then
    raise exception 'Withdrawal not found.';
  end if;
  if v_row.method <> 'manual' then
    raise exception 'This withdrawal is not a manual request.';
  end if;
  if v_row.status <> 'pending' then
    raise exception 'This withdrawal has already been settled.';
  end if;

  update withdrawals
    set status = p_new_status,
        completed_at = now(),
        admin_note = p_note,
        failure_reason = case when p_new_status = 'failed' then p_note else null end
    where id = p_withdrawal_id
    returning * into v_row;
  return v_row;
end;
$$;

revoke all on function admin_settle_manual_withdrawal(uuid, text, text) from public;
grant execute on function admin_settle_manual_withdrawal(uuid, text, text) to authenticated;

-- ----------------------------------------------------------------------------------------------
-- 3. create_guild_event_entry_locked — the one place a guild_event_entries row is ever created.
-- Same service-role-only posture and same explicit-user-id shape as create_withdrawal_locked
-- above, for the same reason (paystack-init-event-entry has already authenticated the caller).
-- ----------------------------------------------------------------------------------------------

create or replace function create_guild_event_entry_locked(
  p_user_id uuid, p_event_id uuid, p_paystack_reference text, p_amount_kobo bigint, p_net_kobo bigint
)
returns guild_event_entries
language plpgsql security definer set search_path = public as $$
declare
  v_event guild_events%rowtype;
  v_row guild_event_entries;
  v_count integer;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized.';
  end if;

  -- Same lock key settle_guild_event() uses for this event — an entry can't be created mid-
  -- settlement, and two simultaneous entry attempts for the same event now fully serialize.
  perform pg_advisory_xact_lock(hashtext('guild_event_entry:' || p_event_id::text));

  select * into v_event from guild_events where id = p_event_id;
  if not found then
    raise exception 'Event not found.';
  end if;
  if v_event.host <> 'guild' then
    raise exception 'This event has no entry fee to pay.';
  end if;
  if v_event.status <> 'open' or v_event.approval_status <> 'active' then
    raise exception 'This event is no longer taking entries.';
  end if;

  if exists (
    select 1 from guild_event_entries
    where event_id = p_event_id and entrant_id = p_user_id and status <> 'failed'
  ) then
    raise exception 'You''ve already entered this event.';
  end if;

  if v_event.participant_limit is not null then
    select count(*) into v_count from guild_event_entries
    where event_id = p_event_id and status in ('pending', 'success');
    if v_count >= v_event.participant_limit then
      raise exception 'This event is full.';
    end if;
  end if;

  insert into guild_event_entries (event_id, entrant_id, paystack_reference, amount_kobo, net_kobo, status)
  values (p_event_id, p_user_id, p_paystack_reference, p_amount_kobo, p_net_kobo, 'pending')
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function create_guild_event_entry_locked(uuid, uuid, text, bigint, bigint) from public;

-- Safe to run anytime — see this migration's header.

-- ============================================================================================
-- Migration 51 (see supabase/history/51_migration_public_guild_events_directory.sql)
-- ============================================================================================

-- ============================================================================================
-- Migration 51: list_public_guild_events() / get_public_guild_profile() — the read path Living
-- Universe's Guild Events, Guilds on the Rise, and Best/Most-Read cards all need to link a reader
-- straight to the guild that hosted them, without exposing anything player_guilds' own
-- owner/member-scoped RLS keeps private (invite_code above all).
--
-- guild_events itself already has an "anyone can read" policy (see 42_migration_guild_events.sql)
-- — the actual gap is that a non-member has no RLS-safe way to resolve guild_events.guild_id into
-- a guild_name/crest_url to show, and no way to know how full an event's entrant list is (same
-- gap guild_event_entry_count() closed for a single event — see
-- 46_migration_guild_event_entry_count.sql). Both functions below are the same narrow,
-- security-definer bypass shape as admin_list_guilds()/admin_list_pending_guild_events(): each
-- returns strictly less than the table(s) it reads, and neither ever returns invite_code.
--
-- "Approved and published" is deliberately not just approval_status = 'published' — an event
-- that has since gone 'active' (open for entry) or 'completed' (wrapped up) was published at some
-- point along the way and never un-published, so a reader browsing Living Universe should still
-- see it. This mirrors fetchGuildEvents()'s own default filter in lib/guild-events.js exactly:
-- ('published', 'active', 'completed'). A 'draft', 'pending_approval', 'rejected', or merely
-- 'approved'-but-not-yet-published row never reaches this function, same as it never reaches a
-- guild's own public event list.
-- ============================================================================================

-- ----------------------------------------------------------------------------------------------
-- 1. list_public_guild_events — every approved-and-published (or later) Guild Event across every
-- guild, newest-starting-first, for a platform-wide discovery feed like Living Universe. Not
-- guild-scoped (fetchGuildEvents(guildId) already covers that case) and not admin-scoped
-- (admin_list_pending_guild_events already covers that one).
--
-- participant_count/collected_net_kobo are computed from guild_event_entries the same
-- "count/sum only, never a row" way guild_event_entry_count() does — entries themselves stay
-- non-public. collected_net_kobo sums net_kobo (post-platform-fee) from successful entries only,
-- so a host='guild' event's displayed pool is exactly the verified amount actually available to
-- pay out, never a projection from entry_fee_kobo × some assumed turnout.
-- ----------------------------------------------------------------------------------------------

create or replace function list_public_guild_events(p_result_limit integer default null)
returns table (
  id uuid, guild_id uuid, guild_name text, guild_crest_url text,
  host text, title text, description text, event_type text, cover_image_url text,
  entry_fee_kobo bigint, cash_prize_kobo bigint, participant_limit integer,
  start_date timestamptz, end_date timestamptz, approval_status text, status text,
  participant_count integer, collected_net_kobo bigint
)
language plpgsql stable security definer set search_path = public as $$
begin
  return query
    select
      e.id, e.guild_id, g.name, g.crest_url,
      e.host, e.title, e.description, e.event_type, e.cover_image_url,
      e.entry_fee_kobo, e.cash_prize_kobo, e.participant_limit,
      e.start_date, e.end_date, e.approval_status, e.status,
      coalesce(c.participant_count, 0)::integer,
      coalesce(c.collected_net_kobo, 0)::bigint
    from guild_events e
    join player_guilds g on g.id = e.guild_id
    left join lateral (
      select
        count(*) filter (where x.status = 'success')::integer as participant_count,
        sum(x.net_kobo) filter (where x.status = 'success')::bigint as collected_net_kobo
      from guild_event_entries x
      where x.event_id = e.id
    ) c on true
    where e.approval_status in ('published', 'active', 'completed')
    order by
      case e.approval_status when 'active' then 0 when 'published' then 1 else 2 end,
      coalesce(e.start_date, e.created_at) desc
    limit coalesce(p_result_limit, 30);
end;
$$;

revoke all on function list_public_guild_events(integer) from public;
grant execute on function list_public_guild_events(integer) to authenticated;

-- ----------------------------------------------------------------------------------------------
-- 2. get_public_guild_profile — the minimal, safe-to-show-anyone read of a single Player Guild by
-- id, for a card or link (Living Universe's Guilds on the Rise, Guild Events, Best/Most-Read) to
-- land on a real guild page without needing that reader to already be a member. Same fields
-- admin_list_guilds() already treats as safe to expose broadly, plus a live member_count —
-- nothing else player_guilds holds (owner_id aside, which is not sensitive but also not needed
-- here) ever leaves this function.
-- ----------------------------------------------------------------------------------------------

create or replace function get_public_guild_profile(p_guild_id uuid)
returns table (
  id uuid, name text, motto text, crest_url text, member_count integer, created_at timestamptz
)
language plpgsql stable security definer set search_path = public as $$
begin
  return query
    select g.id, g.name, g.motto, g.crest_url,
      (select count(*)::integer from player_guild_members m where m.guild_id = g.id) as member_count,
      g.created_at
    from player_guilds g
    where g.id = p_guild_id;
end;
$$;

revoke all on function get_public_guild_profile(uuid) from public;
grant execute on function get_public_guild_profile(uuid) to authenticated;

-- Safe to run anytime: both functions are purely additive reads, neither writes anything, and
-- neither returns a column (invite_code) that any existing broad-read function doesn't already
-- treat as sensitive.

-- ============================================================================================
-- Migration 52 (see supabase/history/52_migration_naira_achievement_grants.sql)
-- ============================================================================================

-- Migration 52: Naira Achievement Grants — the server-side implementation of Tier 1 of
-- NAIRA_ACHIEVEMENTS (see the comment on NAIRA_ACHIEVEMENTS in src/writing/health-checks.jsx).
-- Scope note, and what's deliberately NOT in this migration:
--
--   nairaFirstPurchase / nairaBookCollector / nairaGrandCollector (buyer purchase counts),
--   nairaRookieMerchant / nairaHustler / nairaSeniorMan (author sale counts), and
--   nairaFirstPublication (a real published_books or guild_published_books row >= 30,000 words)
--   are implemented below — real signals that already exist server-side today.
--
--   nairaWelcome ("complete your profile") is NOT implemented here and stays exactly as it was
--   (locked, "Requires backend verification — not yet available") even though some of its
--   pieces ARE real server signals (profiles.pen_name, a player_guild_members/
--   founder_guild_members row, 3+ distinct rows in `follows`, a status='success' row in
--   guild_event_entries). One piece of the agreed definition — a profile's motto — is not:
--   `motto` only ever lives in this device's local profile object and syncProfile() (see
--   src/lib/profile.js) never sends it to the `profiles` table at all, so there is nothing on
--   this server to check it against yet. Rather than silently drop motto from the definition or
--   guess a different one, this stays flagged for a real decision (add + sync a motto column, a
--   genuine schema/client change, vs. redefining "complete your profile" without it) the same way
--   nairaDedicatedWriter/nairaMasterWriter/nairaFirstBook/nairaReader/nairaLoyal already are.
--
--   nairaDedicatedWriter, nairaMasterWriter, nairaFirstBook (word-count-based), nairaReader,
--   nairaLoyal (reading-hours/streak-based) are untouched — no server-verifiable signal for any
--   of them exists yet (manuscript text is an unvalidated local blob; there's no reading-time or
--   streak tracking anywhere). Still locked, still honest.
--
-- word_count on published_books: the original ask assumed this column might not exist yet.
-- Checked against the actual schema first (per the ground rules) — it was already added by
-- 26_migration_published_books_richer_metadata.sql and is already populated on every publish by
-- publishBookRemote (src/lib/library.js). No new column, no backfill needed.
--
-- Payout pipeline: an achievement grant is a NEW CREDIT SOURCE that author_balance_kobo() sums
-- in — not a second wallet or a second withdraw flow. "Once released, a Naira is a Naira" (see
-- 41_migration_guild_member_earnings_withdrawal.sql's own header); the existing withdrawals /
-- paystack-withdraw pipeline is the only way any of this actually reaches a bank account, exactly
-- as it already is for a book sale or a released guild earning.
--
-- RLS posture: same as purchases/withdrawals — a user can select their own grant rows, but there
-- is no client insert/update policy at all. Every row is created only by
-- grant_naira_achievement(), a security definer function that re-derives everything from
-- auth.uid() and re-checks the real signal itself — never from anything the client reports.
--
-- One-time-claim enforcement: unique (user_id, achievement_id) on achievement_grants, plus
-- grant_naira_achievement() locking on pg_advisory_xact_lock(hashtext('naira_achievement:' ||
-- user_id || ':' || achievement_id)) before checking "already granted", the same
-- lock-then-recheck shape settle_guild_event()/create_withdrawal_locked() already use.
--
-- No separate "claim" step in the frontend (see AchievementCard in src/writing/achievements.jsx
-- — unlocked just renders "Unlocked ✓", there was never a claim button to begin with, and this
-- migration doesn't add one). So the read path itself is what grants: naira_achievement_progress()
-- below attempts grant_naira_achievement() for each Tier 1 id on every call (swallowing "not
-- eligible yet" / "already granted" as expected, non-error outcomes) and then reports the
-- resulting state. The very same locking + uniqueness constraint that makes
-- grant_naira_achievement() safe to call directly also makes calling it from inside a read
-- perfectly safe — it's the same one-time-claim guarantee either way, just triggered by viewing
-- the Hall of Legends instead of a separate button click.
--
-- Safe to run anytime: both new tables/functions are additive, and author_balance_kobo()'s new
-- term is 0 for every writer until their first real grant exists.

-- ============================================================================================
-- achievement_grants — one row per (user, Naira achievement) ever paid out. Permanent once
-- written — never updated or deleted by anything in this schema.
-- ============================================================================================

create table if not exists achievement_grants (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  achievement_id text not null,
  naira_reward_kobo bigint not null check (naira_reward_kobo > 0),
  created_at timestamptz not null default now(),
  unique (user_id, achievement_id)
);

alter table achievement_grants enable row level security;

create policy "a user reads their own achievement grants" on achievement_grants
  for select using (auth.uid() = user_id);
-- No client insert/update/delete policy — every row is created only by
-- grant_naira_achievement() below, running as the authenticated user via auth.uid().

create index if not exists achievement_grants_user_id_idx on achievement_grants (user_id);

-- ============================================================================================
-- naira_achievement_current — the real, live signal for one Tier 1 achievement, for the calling
-- user only (auth.uid(), never a client-supplied id). Shared by grant_naira_achievement() and
-- naira_achievement_progress() so there is exactly one definition of each signal, not two copies
-- that could drift. Returns null for any id outside Tier 1 (nairaWelcome and every Tier 2 id) —
-- callers treat that as "leave this one exactly as it already was" (see the header above).
-- ============================================================================================

create or replace function naira_achievement_current(p_achievement_id text)
returns bigint as $$
  select case p_achievement_id
    when 'nairaFirstPurchase' then
      (select count(*) from purchases where buyer_id = auth.uid() and status = 'success')
    when 'nairaBookCollector' then
      (select count(*) from purchases where buyer_id = auth.uid() and status = 'success')
    when 'nairaGrandCollector' then
      (select count(*) from purchases where buyer_id = auth.uid() and status = 'success')
    when 'nairaRookieMerchant' then
      (select count(*) from purchases where author_id = auth.uid() and status = 'success')
    when 'nairaHustler' then
      (select count(*) from purchases where author_id = auth.uid() and status = 'success')
    when 'nairaSeniorMan' then
      (select count(*) from purchases where author_id = auth.uid() and status = 'success')
    when 'nairaFirstPublication' then
      (select case when exists (
        select 1 from published_books where author_id = auth.uid() and word_count >= 30000
        union all
        select 1 from guild_published_books where author_id = auth.uid() and word_count >= 30000
      ) then 1 else 0 end)
    else null
  end;
$$ language sql stable security definer set search_path = public;

revoke all on function naira_achievement_current(text) from public;
grant execute on function naira_achievement_current(text) to authenticated;

-- ============================================================================================
-- grant_naira_achievement — the one place an achievement_grants row is ever created. Re-derives
-- the real signal itself (via naira_achievement_current above) rather than trusting anything the
-- caller reports, locks per (user, achievement) before checking "already granted" so two
-- concurrent calls can never both pass, and is a no-op (returns the existing row) on a retry
-- against an already-granted achievement rather than raising — naira_achievement_progress()
-- below depends on that idempotency to call this safely on every read.
-- ============================================================================================

create or replace function grant_naira_achievement(p_achievement_id text)
returns achievement_grants
language plpgsql security definer set search_path = public as $$
declare
  v_row achievement_grants;
  v_target bigint;
  v_reward_kobo bigint;
  v_current bigint;
begin
  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row; -- already granted — idempotent, not an error
  end if;

  -- target/reward mirror NAIRA_ACHIEVEMENTS in src/writing/health-checks.jsx exactly (nairaReward
  -- there is Naira, not kobo — x100 here). Any id outside this list (nairaWelcome, every Tier 2
  -- id) falls through to the else and is refused — there is deliberately no signal to check yet.
  case p_achievement_id
    when 'nairaFirstPurchase'    then v_target := 1;   v_reward_kobo := 10000;
    when 'nairaBookCollector'    then v_target := 50;  v_reward_kobo := 500000;
    when 'nairaGrandCollector'   then v_target := 100; v_reward_kobo := 1000000;
    when 'nairaRookieMerchant'   then v_target := 10;  v_reward_kobo := 100000;
    when 'nairaHustler'          then v_target := 50;  v_reward_kobo := 500000;
    when 'nairaSeniorMan'        then v_target := 100; v_reward_kobo := 1500000;
    when 'nairaFirstPublication' then v_target := 1;   v_reward_kobo := 100000;
    else
      raise exception 'This achievement has no server-verifiable signal yet.';
  end case;

  -- Locked per (user, achievement) — same lock-then-recheck shape settle_guild_event()/
  -- create_withdrawal_locked() already use, scoped narrower than a whole-user lock since two
  -- different achievements for the same writer have nothing to serialize against each other.
  perform pg_advisory_xact_lock(hashtext('naira_achievement:' || auth.uid()::text || ':' || p_achievement_id));

  -- Re-read under the lock in case a concurrent call just granted it.
  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row;
  end if;

  v_current := naira_achievement_current(p_achievement_id);
  if v_current is null or v_current < v_target then
    raise exception 'Achievement not yet earned.';
  end if;

  insert into achievement_grants (user_id, achievement_id, naira_reward_kobo)
  values (auth.uid(), p_achievement_id, v_reward_kobo)
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function grant_naira_achievement(text) from public;
grant execute on function grant_naira_achievement(text) to authenticated;

-- ============================================================================================
-- naira_achievement_progress — one round trip for the Hall of Legends' Naira Rewards grid.
-- Attempts grant_naira_achievement() for every Tier 1 id (each call is independently locked and
-- idempotent — see above), swallowing the expected "not eligible yet" outcome, then reports
-- current/unlocked per id from the now-current achievement_grants state. This is what actually
-- pays an achievement out the moment it's first met — there's no separate claim step (see the
-- migration header). current is capped at target for display, same convention
-- computeLifetimeAchievements() already uses client-side.
-- ============================================================================================

create or replace function naira_achievement_progress()
returns table (achievement_id text, current_count bigint, unlocked boolean)
language plpgsql security definer set search_path = public as $$
declare
  v_id text;
  v_target bigint;
  v_ids text[] := array['nairaFirstPurchase', 'nairaBookCollector', 'nairaGrandCollector',
                         'nairaRookieMerchant', 'nairaHustler', 'nairaSeniorMan', 'nairaFirstPublication'];
  v_targets bigint[] := array[1, 50, 100, 10, 50, 100, 1];
begin
  for i in 1 .. array_length(v_ids, 1) loop
    v_id := v_ids[i];
    v_target := v_targets[i];
    begin
      perform grant_naira_achievement(v_id);
    exception when others then
      null; -- not eligible yet — expected, not an error worth surfacing here
    end;

    achievement_id := v_id;
    unlocked := exists (select 1 from achievement_grants g where g.user_id = auth.uid() and g.achievement_id = v_id);
    if unlocked then
      current_count := v_target;
    else
      current_count := least(coalesce(naira_achievement_current(v_id), 0), v_target);
    end if;
    return next;
  end loop;
end;
$$;

revoke all on function naira_achievement_progress() from public;
grant execute on function naira_achievement_progress() to authenticated;

-- ============================================================================================
-- author_balance_kobo — extended once more (same function, same signature, still the one place
-- a writer's withdrawable balance is computed) to add successful achievement grants as a credit.
-- Based on the LATEST logical definition (41_migration_guild_member_earnings_withdrawal.sql's
-- version, which excludes anthology-sourced purchases and adds released guild earnings back in)
-- — not the older copy still sitting in supabase/schema.sql, which predates migration 41 and
-- hasn't been kept in sync with it. That drift is pre-existing and out of scope here (only
-- NAIRA_ACHIEVEMENTS is in scope for this migration); flagging it since a fresh install running
-- schema.sql alone would need 41 and this migration layered on top to reach this correct state.
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(p.author_amount_kobo) from purchases p
              where p.author_id = check_user_id and p.status = 'success'
                and not exists (
                  select 1 from guild_anthologies a where a.published_book_id = p.book_id
                )), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0)
    +
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where member_id = check_user_id and kind = 'release_to_member' and status = 'success'), 0)
    +
    coalesce((select sum(naira_reward_kobo) from achievement_grants
              where user_id = check_user_id), 0);
$$ language sql stable security definer set search_path = public;

revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- Safe to run anytime: achievement_grants starts empty on every deployment, so this added term is
-- 0 for every existing writer until their first real Tier 1 grant — no existing balance changes
-- on deployment.

-- ============================================================================================
-- Migration 53 (see supabase/history/53_migration_naira_writing_and_reading_signals.sql)
-- ============================================================================================

-- Migration 53: real, cheat-resistant signals for the Tier 2 NAIRA_ACHIEVEMENTS that were
-- deliberately left unbuilt in 52_migration_naira_achievement_grants.sql:
--
--   nairaFirstBook, nairaDedicatedWriter, nairaMasterWriter (word-count-based), and
--   nairaReader, nairaLoyal (reading-hours / streak-based).
--
-- Chosen direction (explicitly: cheat-resistance over shipping speed):
--   - Word count: real manuscript content sync + a day-capped credit ledger, NOT a bare
--     client-reported number. See the "why not just trust a number" reasoning below.
--   - Reading: a real server-throttled heartbeat while a book is visibly open, NOT a reuse of
--     the existing "opened today" signal (which can't distinguish 3 hours of reading from 3
--     seconds).
--   - The streak (nairaLoyal) is the union of both: a day counts if either signal fired.
--
-- nairaWelcome is still not in this migration — unchanged from 52's reasoning (motto isn't
-- synced to profiles at all yet).
--
-- ============================================================================================
-- PART 1 — word count, real content in, day-capped credit out
-- ============================================================================================
--
-- The problem restated precisely: a project's chapters live only inside one opaque JSONB blob
-- per project in kv_store (see syncEngine.js/storage.js) — there is no structured, validated
-- manuscript table anywhere. Two sub-problems, two separate fixes:
--
--   1. "Is the reported word count even real?" — fixed by NOT trusting a reported number at
--      all. The trigger below parses kv_store's actual synced value and derives a real word
--      count itself, the same tokenization src/shared-utils/strip-html.jsx's wordCount()/
--      stripHtml() already use (strip tags, collapse whitespace, count tokens) — block-vs-inline
--      tag handling doesn't change a token count, so a single regex pass is equivalent here.
--
--   2. "Can real content still be gamed?" — yes: pasting a finished 50,000-word novel into one
--      chapter and syncing it would derive a perfectly real, perfectly honest word count
--      instantly. Fixed by writing_credit_ledger below: only min(today's real increase, 10,000)
--      ever counts toward the lifetime total, so reaching 50,000 takes at least 5 distinct real
--      calendar days no matter how the underlying total jumped. This is the same "capped,
--      not fully verifiable, but honestly bounded" tradeoff already accepted elsewhere in this
--      schema (Rising Star's diminishing-returns weighting, Guilds on the Rise's floors — see
--      38_migration_rising_star_scoring.sql, 40_migration_guilds_on_rise_scoring.sql) rather
--      than a new kind of compromise invented just for this.
--
-- IMPORTANT — a real quirk of how this app syncs, confirmed against storage.js/syncEngine.js
-- before writing this: storage.set(projectKey(id), JSON.stringify(project)) means the value
-- pushed to kv_store is a JSON-encoded STRING containing the project, not the project object
-- itself — so kv_store.value (jsonb) holds a JSON *string scalar*, double-encoded. The trigger
-- below unwraps that with `value #>> '{}'` (get the string content) before parsing it a second
-- time as jsonb. Skipping this step would make every project row fail to parse silently.
--
-- Also confirmed against project-schema-and-backups.jsx/ink-root.jsx: a project's own JSON blob
-- has NO `id` field of its own — the id lives only in the kv_store KEY (`inkroot:project:<id>`)
-- and the separate local project index. The trigger below derives project_id from NEW.key
-- (stripping the 16-character 'inkroot:project:' prefix), not from inside the payload.

create table if not exists project_word_high_water (
  user_id uuid not null references auth.users(id) on delete cascade,
  project_id text not null,
  word_count bigint not null default 0,
  updated_at timestamptz not null default now(),
  primary key (user_id, project_id)
);

alter table project_word_high_water enable row level security;

create policy "a user reads their own project word counts" on project_word_high_water
  for select using (auth.uid() = user_id);
-- No client insert/update/delete policy — every row is written only by the trigger below, which
-- runs as a security definer function and so isn't subject to this table's RLS at all.

-- Monotonic (greatest-of), deliberately never decreases even if a writer later trims or deletes
-- content — this measures words actually written, ever, not a live document length. Cutting a
-- bad paragraph after writing it shouldn't erase credit for having written it.
create or replace function sync_project_word_high_water()
returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_project_id text;
  v_data jsonb;
  v_chapters jsonb;
  v_chapter jsonb;
  v_text text;
  v_total bigint := 0;
begin
  if NEW.key !~ '^inkroot:project:' or NEW.deleted or NEW.value is null then
    return NEW;
  end if;
  v_project_id := substring(NEW.key from 17); -- length('inkroot:project:') = 16

  begin
    -- Unwrap the double-encoding described above, then parse the manuscript it actually holds.
    v_data := (NEW.value #>> '{}')::jsonb;
  exception when others then
    return NEW; -- not valid/double-encoded JSON — skip rather than ever fail this writer's sync
  end;

  v_chapters := v_data -> 'chapters';
  if v_chapters is null or jsonb_typeof(v_chapters) <> 'array' then
    return NEW;
  end if;

  for v_chapter in select * from jsonb_array_elements(v_chapters) loop
    v_text := coalesce(v_chapter ->> 'text', '');
    v_text := regexp_replace(v_text, '<[^>]+>', ' ', 'g');
    v_text := regexp_replace(v_text, '&nbsp;', ' ', 'g');
    v_text := trim(regexp_replace(v_text, '\s+', ' ', 'g'));
    if v_text <> '' then
      v_total := v_total + array_length(regexp_split_to_array(v_text, '\s+'), 1);
    end if;
  end loop;

  insert into project_word_high_water (user_id, project_id, word_count, updated_at)
  values (NEW.user_id, v_project_id, v_total, now())
  on conflict (user_id, project_id) do update
    set word_count = greatest(project_word_high_water.word_count, excluded.word_count),
        updated_at = now();

  return NEW;
end;
$$;

drop trigger if exists trg_sync_project_word_high_water on kv_store;
create trigger trg_sync_project_word_high_water
  after insert or update on kv_store
  for each row execute function sync_project_word_high_water();

-- Day-capped lifetime credit. One row per (user, calendar day, UTC) — day N's credited_words is
-- recomputed (not incremented) every time this runs, from the gap between the live total and
-- everything credited on strictly earlier days, so calling it any number of times in one day is
-- idempotent and safe.
create table if not exists writing_credit_ledger (
  user_id uuid not null references auth.users(id) on delete cascade,
  day date not null,
  credited_words bigint not null default 0,
  primary key (user_id, day)
);

alter table writing_credit_ledger enable row level security;

create policy "a user reads their own writing credit ledger" on writing_credit_ledger
  for select using (auth.uid() = user_id);
-- No client insert/update/delete policy — only sync_writing_credit_ledger() below writes here.

create or replace function sync_writing_credit_ledger()
returns bigint -- lifetime credited total after syncing today's row
language plpgsql security definer set search_path = public as $$
declare
  v_today date := (now() at time zone 'utc')::date;
  v_current_total bigint;
  v_prior_total bigint;
  v_today_capped bigint;
begin
  select coalesce(sum(word_count), 0) into v_current_total
  from project_word_high_water where user_id = auth.uid();

  select coalesce(sum(credited_words), 0) into v_prior_total
  from writing_credit_ledger where user_id = auth.uid() and day < v_today;

  v_today_capped := least(greatest(v_current_total - v_prior_total, 0), 10000); -- 10,000 words/day cap

  insert into writing_credit_ledger (user_id, day, credited_words)
  values (auth.uid(), v_today, v_today_capped)
  on conflict (user_id, day) do update set credited_words = excluded.credited_words;

  return v_prior_total + v_today_capped;
end;
$$;

revoke all on function sync_writing_credit_ledger() from public;
grant execute on function sync_writing_credit_ledger() to authenticated;

-- ============================================================================================
-- PART 2 — reading, real heartbeats, server-throttled
-- ============================================================================================
--
-- book_read_events (38_migration_rising_star_scoring.sql) only ever recorded "opened this book
-- today," which can't distinguish a real read from a three-second bounce. This adds actual
-- verified minutes, scoped to published_books only (same scope book_read_events already has —
-- guild_published_books was never part of this signal either, so this isn't a new gap).
--
-- Anti-gaming: record_reading_heartbeat() throttles against ITS OWN clock (a per-user
-- last-heartbeat-at row, checked server-side), never against anything the client claims about
-- elapsed time — so a client calling this faster than once every ~45 seconds simply gets
-- ignored, regardless of what interval it thinks it's using. A daily cap (180 minutes) on top of
-- that bounds worst-case exposure even if every throttled call is scripted rather than a real
-- read — same honest caveat as any heartbeat system in a web client: this bounds the damage, it
-- doesn't make faking a heartbeat impossible for a determined, modified client.

create table if not exists reading_heartbeats_daily (
  user_id uuid not null references auth.users(id) on delete cascade,
  day date not null,
  minutes integer not null default 0,
  primary key (user_id, day)
);

alter table reading_heartbeats_daily enable row level security;

create policy "a user reads their own reading heartbeat history" on reading_heartbeats_daily
  for select using (auth.uid() = user_id);
-- No client insert/update/delete policy — only record_reading_heartbeat() below writes here.

create table if not exists reading_heartbeat_cursor (
  user_id uuid primary key references auth.users(id) on delete cascade,
  last_heartbeat_at timestamptz not null
);

alter table reading_heartbeat_cursor enable row level security;

create policy "a user reads their own heartbeat cursor" on reading_heartbeat_cursor
  for select using (auth.uid() = user_id);
-- No client insert/update/delete policy — only record_reading_heartbeat() below writes here.

create or replace function record_reading_heartbeat(p_book_id text)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_last timestamptz;
  v_today date := (now() at time zone 'utc')::date;
begin
  if is_banned(auth.uid()) then
    return;
  end if;
  -- Same self-read exclusion book_read_events' own insert policy already enforces — an author
  -- can't farm their own book's reading time.
  if exists (select 1 from published_books b where b.id = p_book_id and b.author_id = auth.uid()) then
    return;
  end if;
  if not exists (select 1 from published_books where id = p_book_id) then
    return; -- not a real published book — e.g. a local-only project id, nothing to credit
  end if;

  select last_heartbeat_at into v_last from reading_heartbeat_cursor where user_id = auth.uid();
  if v_last is not null and now() - v_last < interval '45 seconds' then
    return; -- throttled — the server's own clock decides this, not the client's claimed interval
  end if;

  insert into reading_heartbeat_cursor (user_id, last_heartbeat_at)
  values (auth.uid(), now())
  on conflict (user_id) do update set last_heartbeat_at = excluded.last_heartbeat_at;

  insert into reading_heartbeats_daily (user_id, day, minutes)
  values (auth.uid(), v_today, 1)
  on conflict (user_id, day) do update
    set minutes = least(reading_heartbeats_daily.minutes + 1, 180); -- 180 minutes/day cap
end;
$$;

revoke all on function record_reading_heartbeat(text) from public;
grant execute on function record_reading_heartbeat(text) to authenticated;

-- ============================================================================================
-- PART 3 — the streak: a day counts if EITHER real signal fired that day
-- ============================================================================================
--
-- This computes the LONGEST streak ever reached in the caller's full history, not just an
-- in-progress one ending today — a one-time grant (see grant_naira_achievement in migration 52)
-- has to work this way, or a writer who hit 7 days, didn't happen to open the Hall of Legends
-- that exact day, and broke the streak the next day would unfairly lose an achievement they
-- genuinely already earned. Standard "gaps and islands" technique: subtracting each date's row
-- number (ordered) from itself collapses any run of consecutive dates onto the same group key.

create or replace function naira_longest_activity_streak()
returns integer
language sql stable security definer set search_path = public as $$
  with active_days as (
    select day from writing_credit_ledger where user_id = auth.uid() and credited_words > 0
    union
    select day from reading_heartbeats_daily where user_id = auth.uid() and minutes >= 5
  ),
  islands as (
    select day, day - (row_number() over (order by day))::integer as grp
    from active_days
  )
  select coalesce(max(cnt), 0)::integer from (
    select count(*) as cnt from islands group by grp
  ) s;
$$;

revoke all on function naira_longest_activity_streak() from public;
grant execute on function naira_longest_activity_streak() to authenticated;

-- ============================================================================================
-- PART 4 — wire the five signals into the existing Tier 1 machinery from migration 52
-- ============================================================================================
--
-- naira_achievement_current is upgraded from `language sql stable` to `language plpgsql`
-- (dropping the `stable` label) because it now calls sync_writing_credit_ledger(), which writes.
-- The Tier 1 branches are carried over unchanged.
--
-- Product decision made here (flagging it plainly, same as nairaWelcome in migration 52):
-- nairaFirstBook's original desc, "Complete your first manuscript," had no server-checkable
-- signal — the only local candidate is project.completed, a plain boolean the writer can flip
-- for a brand-new, empty project in one tap, which fails the same "trust a client number"
-- problem this whole migration exists to close. Redefined instead as reaching a 30,000-word
-- lifetime credited total (the SAME day-capped, real-content signal nairaDedicatedWriter/
-- nairaMasterWriter use, just a lower threshold, and the same 30,000-word bar
-- nairaFirstPublication already uses to mean "book-length") — current/unlocked still display
-- against its original target of 1 (a single completion, not a running word count) since that's
-- the shape its card in achievements.jsx already renders.

create or replace function naira_achievement_current(p_achievement_id text)
returns bigint
language plpgsql security definer set search_path = public as $$
declare
  v_result bigint;
begin
  case p_achievement_id
    when 'nairaFirstPurchase' then
      select count(*) into v_result from purchases where buyer_id = auth.uid() and status = 'success';
    when 'nairaBookCollector' then
      select count(*) into v_result from purchases where buyer_id = auth.uid() and status = 'success';
    when 'nairaGrandCollector' then
      select count(*) into v_result from purchases where buyer_id = auth.uid() and status = 'success';
    when 'nairaRookieMerchant' then
      select count(*) into v_result from purchases where author_id = auth.uid() and status = 'success';
    when 'nairaHustler' then
      select count(*) into v_result from purchases where author_id = auth.uid() and status = 'success';
    when 'nairaSeniorMan' then
      select count(*) into v_result from purchases where author_id = auth.uid() and status = 'success';
    when 'nairaFirstPublication' then
      select (case when exists (
        select 1 from published_books where author_id = auth.uid() and word_count >= 30000
        union all
        select 1 from guild_published_books where author_id = auth.uid() and word_count >= 30000
      ) then 1 else 0 end) into v_result;
    when 'nairaFirstBook' then
      select (case when sync_writing_credit_ledger() >= 30000 then 1 else 0 end) into v_result;
    when 'nairaDedicatedWriter' then
      select sync_writing_credit_ledger() into v_result;
    when 'nairaMasterWriter' then
      select sync_writing_credit_ledger() into v_result;
    when 'nairaReader' then
      select coalesce(sum(minutes), 0) / 60 into v_result
      from reading_heartbeats_daily where user_id = auth.uid();
    when 'nairaLoyal' then
      select naira_longest_activity_streak() into v_result;
    else
      v_result := null;
  end case;
  return v_result;
end;
$$;

revoke all on function naira_achievement_current(text) from public;
grant execute on function naira_achievement_current(text) to authenticated;

-- grant_naira_achievement (migration 52) — add the five new target/reward pairs. Reward amounts
-- convert NAIRA_ACHIEVEMENTS' nairaReward (Naira) to kobo (x100), same as every Tier 1 entry:
-- nairaFirstBook 500 -> 50000, nairaDedicatedWriter 500 -> 50000, nairaMasterWriter 1000 -> 100000,
-- nairaReader 500 -> 50000, nairaLoyal 1000 -> 100000.
create or replace function grant_naira_achievement(p_achievement_id text)
returns achievement_grants
language plpgsql security definer set search_path = public as $$
declare
  v_row achievement_grants;
  v_target bigint;
  v_reward_kobo bigint;
  v_current bigint;
begin
  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row; -- already granted — idempotent, not an error
  end if;

  case p_achievement_id
    when 'nairaFirstPurchase'    then v_target := 1;      v_reward_kobo := 10000;
    when 'nairaBookCollector'    then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaGrandCollector'   then v_target := 100;     v_reward_kobo := 1000000;
    when 'nairaRookieMerchant'   then v_target := 10;      v_reward_kobo := 100000;
    when 'nairaHustler'          then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaSeniorMan'        then v_target := 100;     v_reward_kobo := 1500000;
    when 'nairaFirstPublication' then v_target := 1;       v_reward_kobo := 100000;
    when 'nairaFirstBook'        then v_target := 1;       v_reward_kobo := 50000;
    when 'nairaDedicatedWriter'  then v_target := 50000;   v_reward_kobo := 50000;
    when 'nairaMasterWriter'     then v_target := 100000;  v_reward_kobo := 100000;
    when 'nairaReader'           then v_target := 5;       v_reward_kobo := 50000;
    when 'nairaLoyal'            then v_target := 7;       v_reward_kobo := 100000;
    else
      raise exception 'This achievement has no server-verifiable signal yet.';
  end case;

  perform pg_advisory_xact_lock(hashtext('naira_achievement:' || auth.uid()::text || ':' || p_achievement_id));

  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row;
  end if;

  v_current := naira_achievement_current(p_achievement_id);
  if v_current is null or v_current < v_target then
    raise exception 'Achievement not yet earned.';
  end if;

  insert into achievement_grants (user_id, achievement_id, naira_reward_kobo)
  values (auth.uid(), p_achievement_id, v_reward_kobo)
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function grant_naira_achievement(text) from public;
grant execute on function grant_naira_achievement(text) to authenticated;

-- naira_achievement_progress (migration 52) — extend the id/target arrays with the five new
-- ones. current_count reporting (least(current, target) when locked, target when unlocked) is
-- already generic and needed no changes — every id here reports current in the same units its
-- target is expressed in (see naira_achievement_current above), same as every Tier 1 id already did.
create or replace function naira_achievement_progress()
returns table (achievement_id text, current_count bigint, unlocked boolean)
language plpgsql security definer set search_path = public as $$
declare
  v_id text;
  v_target bigint;
  v_ids text[] := array['nairaFirstPurchase', 'nairaBookCollector', 'nairaGrandCollector',
                         'nairaRookieMerchant', 'nairaHustler', 'nairaSeniorMan', 'nairaFirstPublication',
                         'nairaFirstBook', 'nairaDedicatedWriter', 'nairaMasterWriter', 'nairaReader', 'nairaLoyal'];
  v_targets bigint[] := array[1, 50, 100, 10, 50, 100, 1,
                               1, 50000, 100000, 5, 7];
begin
  for i in 1 .. array_length(v_ids, 1) loop
    v_id := v_ids[i];
    v_target := v_targets[i];
    begin
      perform grant_naira_achievement(v_id);
    exception when others then
      null; -- not eligible yet — expected, not an error worth surfacing here
    end;

    achievement_id := v_id;
    unlocked := exists (select 1 from achievement_grants g where g.user_id = auth.uid() and g.achievement_id = v_id);
    if unlocked then
      current_count := v_target;
    else
      current_count := least(coalesce(naira_achievement_current(v_id), 0), v_target);
    end if;
    return next;
  end loop;
end;
$$;

revoke all on function naira_achievement_progress() from public;
grant execute on function naira_achievement_progress() to authenticated;

-- Safe to run anytime: every new table starts empty, project_word_high_water/writing_credit_ledger
-- only ever populate from here forward (there's no historical manuscript content to backfill —
-- this migration doesn't attempt to derive word counts retroactively from before it existed), and
-- author_balance_kobo() (migration 52) already sums achievement_grants generically — no change
-- needed there for these five to pay out through the exact same withdrawable-balance pipeline.

-- ============================================================================================
-- Migration 54 (see supabase/history/54_migration_naira_welcome_and_profile_motto.sql)
-- ============================================================================================

-- Migration 54: nairaWelcome ("complete your profile") — real signals for 5 of its 6 confirmed
-- criteria (a set pen name, a set avatar, a set motto, guild membership, following 3+ other
-- creators, and a successful guild-event entry), staged and ready. Deliberately NOT wired into
-- the payout path yet — see the decision at the end of this file. nairaWelcome stays exactly as
-- unbuilt/locked as it's always been until the 6th criterion (following Inkroot's official
-- Instagram account) has a real verification path; there is currently no way to check that
-- server-side (see the note below), and shipping the other 5 as sufficient on their own would
-- silently drop a requirement rather than build or flag it.
--
-- ============================================================================================
-- PART 1 — motto actually gets synced, for the first time
-- ============================================================================================
--
-- Confirmed against author-identity.jsx/ink-root.jsx before writing this: profile.motto has
-- always been edited locally (WriterIdentityCard's motto field, via onSaveProfile) but
-- saveProfile's call to syncProfile() only ever forwarded name/penName/avatar — motto never
-- reached the profiles table at all. This is the schema half of closing that gap; profile.js's
-- syncProfile() is updated in the same change to actually send it. This part ships regardless of
-- how the Instagram question above resolves — it's real, useful on its own, and every other
-- Naira achievement wiring in this migration depends on it existing.
--
-- Length cap (140) is a plain honesty-of-data-shape choice, same reasoning as pen_name/
-- display_name's 80-char cap earlier in the original table — nothing about this migration
-- depends on the exact number.

alter table profiles add column if not exists motto text check (motto is null or char_length(motto) <= 140);

-- ============================================================================================
-- PART 2 — the 5 confirmed real signals, staged as their own function, NOT yet wired to payout
-- ============================================================================================
--
-- naira_welcome_profile_signals_met() checks all 5 already-agreed, already-real criteria for the
-- calling user (auth.uid()) in one place, so wiring nairaWelcome into naira_achievement_current/
-- grant_naira_achievement/naira_achievement_progress once Instagram is resolved is a small,
-- mechanical change (call this function, AND it with the new Instagram check) rather than
-- rebuilding this logic from scratch. It is intentionally not called from anywhere in the
-- existing Tier 1/2 machinery yet — nairaWelcome is not in naira_achievement_progress's id list,
-- so it continues to report current: 0, unlocked: false exactly as it always has (see
-- computeNairaAchievements() in health-checks.jsx, which already treats "not in the progress
-- map" as "leave it locked").

create or replace function naira_welcome_profile_signals_met()
returns boolean
language sql stable security definer set search_path = public as $$
  select
    coalesce(nullif(trim(p.pen_name), ''), null) is not null
    and coalesce(nullif(trim(p.avatar_url), ''), null) is not null
    and coalesce(nullif(trim(p.motto), ''), null) is not null
    and exists (
      select 1 from player_guild_members m where m.user_id = auth.uid()
      union all
      select 1 from founder_guild_members m where m.user_id = auth.uid()
    )
    and (select count(distinct followee_id) from follows where follower_id = auth.uid()) >= 3
    and exists (
      select 1 from guild_event_entries e where e.entrant_id = auth.uid() and e.status = 'success'
    )
  from profiles p where p.id = auth.uid();
$$;

revoke all on function naira_welcome_profile_signals_met() from public;
grant execute on function naira_welcome_profile_signals_met() to authenticated;

-- ============================================================================================
-- NOT IN THIS MIGRATION — "follow the official Inkroot Instagram account", and therefore
-- nairaWelcome's actual payout wiring
-- ============================================================================================
-- Explicitly decided: ship the 5 verified criteria above now (they're real and useful — the
-- motto sync in particular closes a gap that existed independent of this achievement), but hold
-- nairaWelcome itself locked/ungrantable until Instagram has a real verification path. Adding it
-- to naira_achievement_current/grant_naira_achievement/naira_achievement_progress happens in a
-- follow-up migration once that's resolved — it isn't done here specifically so this achievement
-- can never be granted on 5 of its 6 agreed criteria while silently skipping the 6th.
--
-- There is no existing Instagram integration anywhere in this codebase to build on (checked —
-- zero references to Instagram/social links of any kind before this migration). More
-- importantly, this isn't just "expensive," the way the writing/reading signals in migration 53
-- were — it may not be checkable at all through Instagram's standard public API surface.
-- Instagram's Graph API lets a Business/Creator account see and manage things about ITSELF
-- (its own posts, its own followers list) once its owner completes Meta's app-review process;
-- it does not expose a general "does arbitrary user X follow account Y" lookup to third-party
-- apps. The only route that's actually real:
--   1. Inkroot's own Instagram account would need to be a Business/Creator account connected to
--      a Meta App that's passed Meta's review for the relevant permission.
--   2. Each writer would need to complete an Instagram Login OAuth consent flow in this app,
--      linking their own IG account.
--   3. The backend would then check whether that writer's IG user id appears in Inkroot's own
--      followers list via the Graph API.
-- That is a real, meaningfully-sized integration (a Meta app review, an OAuth flow, a new
-- linked-account concept in this schema), not a one-migration addition.

-- ============================================================================================
-- Migration 55 (see supabase/history/55_migration_referral_tracking.sql)
-- ============================================================================================

-- Migration 55: Referral Tracking — every user gets a shareable referral code, and a permanent,
-- append-only record is created the first time a NEW account redeems someone else's code.
--
-- Scope note, and what's deliberately NOT in this migration: this migration only tracks WHO
-- referred WHOM and WHEN. It does not pay anyone anything. `referrals.status` starts (and, as of
-- this migration, only ever sits at) 'pending' — there is no code path anywhere below that moves
-- it to 'rewarded' or that touches author_balance_kobo()/achievement_grants/any ledger. A signup
-- alone must not generate a cash reward; wiring an actual Naira payout on top of a referral is a
-- separate decision for a later migration, at which point it should reuse the exact
-- lock-then-recheck-then-idempotent-insert shape grant_naira_achievement() already uses in
-- 52_migration_naira_achievement_grants.sql — a new `referral_grants` table (mirroring
-- `achievement_grants`) feeding one more `coalesce(sum(...), 0)` term into author_balance_kobo(),
-- not a new wallet and not a second payout pipeline. Not built here because it isn't asked for
-- here, and because "what actually qualifies a referral for a reward" (referee's first purchase?
-- first publish? just staying signed up N days?) is a product decision this migration shouldn't
-- guess at.
--
-- Referral codes live on `profiles`, not a separate table or a secret like player_guilds'
-- invite_code (see 03_migration_restrict_player_guild_invite_code.sql, which deliberately closed
-- public read on THAT code). The two are opposite by design: a guild invite code gates who can
-- join a private guild, so it has to stay hidden from non-members. A referral code's entire
-- purpose is to be handed out publicly — putting it on `profiles`, which already has an
-- unconditional "anyone can read profiles" select policy, is exactly right, not an oversight.
--
-- Self-referral and repeat-referral, both closed structurally rather than just by convention:
--   - Self-referral: `check (referrer_id <> referee_id)` on the table itself, PLUS an explicit
--     check inside redeem_referral_code() so a self-referral attempt gets a clear error message
--     instead of an opaque constraint-violation.
--   - Repeatedly referring the same account: `referee_id` is UNIQUE. An account can appear as a
--     referee at most once, ever, full stop — not just "once per referrer". Whoever's code an
--     account redeems first is that account's referrer permanently; the row is never updated or
--     deleted by anything in this schema.
--
-- Safe to run anytime: both the new column and the new table are additive, and the backfill for
-- existing profiles below only fills a null, never overwrites an existing value.

-- ============================================================================================
-- profiles.referral_code — one short, permanent, publicly-readable code per account. Same
-- generation shape as player_guilds.invite_code (schema.sql) — lowercase hex, 8 chars, taken from
-- a fresh gen_random_uuid() — reused here rather than inventing a different scheme, chosen
-- deliberately for exactly this migration ("keep the existing structure").
-- ============================================================================================

alter table profiles add column if not exists referral_code text;

-- Backfill for every account that existed before this migration ran. New rows get this same
-- value from the column default added right after, so this UPDATE never needs to run again.
update profiles set referral_code = substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)
where referral_code is null;

alter table profiles alter column referral_code set default substr(replace(gen_random_uuid()::text, '-', ''), 1, 8);
alter table profiles alter column referral_code set not null;

do $$ begin
  alter table profiles add constraint profiles_referral_code_unique unique (referral_code);
exception when duplicate_object then null; -- already added by a previous run of this migration
end $$;

-- No RLS change needed: profiles' existing "anyone can read profiles" / "a user updates their
-- own profile" policies already cover this column exactly the way they cover pen_name or
-- avatar_url. protect_admin_profile_columns() (schema.sql) is untouched — referral_code isn't
-- one of the admin-only columns it guards, and doesn't need to be; a user changing their own
-- referral_code is no more sensitive than changing their own display name would be. (Nothing
-- in this migration exposes an update path for it beyond that ordinary self-service one, and
-- nothing here needs to — a user is welcome to know their own code, which they'd need to be able
-- to read anyway to share it.)

-- ============================================================================================
-- referrals — one permanent row per successfully-redeemed referral. Append-only: nothing in this
-- schema ever updates or deletes a row here.
-- ============================================================================================

create table if not exists referrals (
  id uuid primary key default gen_random_uuid(),
  referrer_id uuid not null references auth.users(id) on delete cascade,
  referee_id uuid not null references auth.users(id) on delete cascade,
  -- Tracking only, as of this migration — see the header above. 'rewarded' is reserved for a
  -- future migration to actually use; nothing here ever writes it.
  status text not null default 'pending' check (status in ('pending', 'rewarded')),
  created_at timestamptz not null default now(),
  -- An account can be someone's referee at most once, ever — the structural half of "prevent
  -- repeatedly referring the same account" (the other half is the idempotent redeem function
  -- below, which turns a second attempt into a no-op read instead of a constraint-violation
  -- error).
  unique (referee_id),
  -- The structural half of "prevent users from referring themselves".
  check (referrer_id <> referee_id)
);

alter table referrals enable row level security;

-- Both sides of a referral can see it: a referrer building a "your referrals" list, and a referee
-- who wants to see who referred them. Neither can see anyone else's row.
create policy "a user reads referrals where they are the referrer" on referrals
  for select using (auth.uid() = referrer_id);
create policy "a user reads referrals where they are the referee" on referrals
  for select using (auth.uid() = referee_id);
-- No client insert/update/delete policy at all — same stance as achievement_grants and
-- purchases: every row is created only by redeem_referral_code() below, a security definer
-- function that re-derives the referrer from the code server-side and always inserts the
-- referee as auth.uid(), never a client-supplied id. There is deliberately no update policy
-- either, since even the future reward migration should flip `status` via its own
-- security-definer function (mirroring grant_naira_achievement()), not via a client-writable
-- column.

create index if not exists referrals_referrer_id_idx on referrals (referrer_id, created_at desc);

-- ============================================================================================
-- redeem_referral_code — the one place a `referrals` row is ever created. Looks the code up
-- server-side (so this works regardless of profiles' select policy shape) and always inserts the
-- CALLING user as referee_id — never a client-supplied id, the same "never trust what the client
-- reports" stance as join_player_guild_by_code() and grant_naira_achievement().
--
-- Idempotent by design, matching grant_naira_achievement()'s own idempotency: if this account is
-- already someone's referee (from an earlier successful call), this returns that existing row
-- rather than raising. That matters here specifically because the realistic caller (see the
-- client-side note in src/lib/referrals.js) is "attempt this once after every fresh sign-in,
-- guarded by a locally-cached code" — a network hiccup or a duplicate call must not be able to
-- produce a second row for the same account, and doesn't need to surface as an error either.
-- ============================================================================================

create or replace function redeem_referral_code(p_code text)
returns referrals
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referrer_id uuid;
  v_row referrals;
begin
  select * into v_row from referrals where referee_id = auth.uid();
  if found then
    return v_row; -- already referred — idempotent, not an error (see header above)
  end if;

  select id into v_referrer_id from profiles where referral_code = lower(trim(p_code));
  if v_referrer_id is null then
    raise exception 'No account found with that referral code.';
  end if;

  if v_referrer_id = auth.uid() then
    raise exception 'You cannot refer yourself.';
  end if;

  -- on conflict (referee_id): guards the race between this function's own two reads above and a
  -- concurrent call for the same referee (e.g. two tabs both finishing sign-in at once) — the
  -- same kind of race grant_naira_achievement() closes with an explicit advisory lock, handled
  -- here with a plain insert-conflict instead since there is nothing to compute under the lock
  -- beyond the insert itself.
  insert into referrals (referrer_id, referee_id)
  values (v_referrer_id, auth.uid())
  on conflict (referee_id) do nothing
  returning * into v_row;

  if v_row.id is null then
    -- Lost that race — read back whichever row actually landed for this referee.
    select * into v_row from referrals where referee_id = auth.uid();
  end if;

  return v_row;
end;
$$;

revoke all on function redeem_referral_code(text) from public;
grant execute on function redeem_referral_code(text) to authenticated;

-- ============================================================================================
-- Migration 56 (see supabase/history/56_migration_referral_rewards.sql)
-- ============================================================================================

-- Migration 56: Referral Rewards — pays a referrer real Naira, but ONLY once the referred
-- account produces genuine economic activity of one of three kinds. A signup alone (covered by
-- 55_migration_referral_tracking.sql) never pays anything, and never has — this migration adds
-- the reward layer that migration 55's header explicitly deferred, using the exact shape it
-- named there: a new grants table feeding one more credit term into author_balance_kobo(),
-- reusing grant_naira_achievement()'s lock-then-recheck-then-idempotent-insert shape. No new
-- wallet, no new payout pipeline — a referral reward reaches a bank account through the exact
-- same withdrawals / paystack-withdraw flow every other credit source already uses.
--
-- The three reward kinds and what "genuine" means for each, all deliberately requiring a REAL
-- signal already recorded elsewhere by a trusted, server-only writer (Paystack's webhook, or
-- distribute_guild_revenue()) — never something the client reports about itself or about the
-- person it referred:
--
--   reader_purchase — the referred user, as a BUYER, has at least one `purchases` row with
--     status = 'success' (Paystack has actually confirmed the money moved) for at least
--     READER_REFERRAL_MIN_PURCHASE_KOBO. The floor exists specifically so "meaningless activity"
--     — a one-Naira tip solely to trigger a payout — doesn't qualify; ₦500 is a real purchase,
--     not a rounding error.
--
--   writer_earnings — the referred user, as an AUTHOR, satisfies BOTH halves of "successfully
--     publishes AND generates qualifying earnings", not just one:
--       (a) a real publication — reusing the exact signal
--           naira_achievement_current('nairaFirstPublication') already established in
--           52_migration_naira_achievement_grants.sql: a published_books or
--           guild_published_books row with word_count >= 30000. Not redefined here — a second,
--           slightly-different definition of "really published" would only invite drift.
--       (b) real earnings — sum(purchases.author_amount_kobo) across that author's successful
--           sales reaches WRITER_REFERRAL_MIN_EARNINGS_KOBO. A single ₦50 sale of a 30k-word book
--           satisfies (a) but not (b) on its own — both are required, matching "publishes AND
--           generates qualifying earnings" in the request rather than either alone.
--
--   guild_activity — the referred user OWNS a player_guild (player_guilds.owner_id) whose
--     treasury has actually received real, externally-verified sale revenue — a
--     guild_treasury_transactions row with kind in ('anthology_share', 'event_revenue') (see
--     that table's own header: these two kinds are the ones distribute_guild_revenue() writes
--     from a real Anthology or Guild Event sale, not a member's own pocket via `contribution`)
--     — summing to at least GUILD_REFERRAL_MIN_REVENUE_KOBO. Deliberately NOT triggered by
--     member count, `contribution` rows (a member moving their own money into their own guild's
--     purse proves nothing), or simply creating a guild — none of those are "genuinely active" in
--     the economic sense this migration is scoped to.
--
-- The three kobo floors above (and the three payout amounts below) are a business threshold, not
-- a technical constant — tune them in a follow-up migration if the amounts prove wrong; nothing
-- about the mechanism changes if they do.
--
-- One referral, up to three rewards: a referral is NOT typed at redemption time (there is one
-- referral_code per user, per 55_migration_referral_tracking.sql, not a separate "writer" vs
-- "reader" link) — whether it ever pays out, and as which kind(s), depends entirely on what the
-- referred account actually goes on to do. The same referee triggering both a qualifying
-- purchase and, later, qualifying writer earnings pays the referrer twice — once per kind, each
-- exactly once ever (`unique (referral_id, kind)` below).
--
-- referrals.status: moves from 'pending' to 'rewarded' the first time ANY reward kind is granted
-- for that referral, and never moves back — a coarse "has this referral ever produced real
-- value" flag. The row-level detail (which kind, how much, when) lives in referral_grants below;
-- status is not overloaded to track per-kind state.
--
-- Safe to run anytime: referral_grants is new and additive, and author_balance_kobo()'s new term
-- is 0 for every account until its first real referral reward exists.

-- ============================================================================================
-- referral_grants — one row per (referral, reward kind) ever paid out. Permanent once written —
-- never updated or deleted by anything in this schema. Mirrors achievement_grants' shape exactly.
-- ============================================================================================

create table if not exists referral_grants (
  id uuid primary key default gen_random_uuid(),
  referral_id uuid not null references referrals(id) on delete cascade,
  kind text not null check (kind in ('reader_purchase', 'writer_earnings', 'guild_activity')),
  naira_reward_kobo bigint not null check (naira_reward_kobo > 0),
  created_at timestamptz not null default now(),
  unique (referral_id, kind)
);

alter table referral_grants enable row level security;

-- Readable by the referrer (whose balance it feeds) via a join back to referrals — there is no
-- referrer_id column directly on this table, so the policy has to look it up the same way a
-- caller would.
create policy "a referrer reads their own referral grants" on referral_grants
  for select using (
    exists (select 1 from referrals r where r.id = referral_grants.referral_id and r.referrer_id = auth.uid())
  );
-- No client insert/update/delete policy at all — every row is created only by
-- grant_referral_reward() below, a security definer function that re-derives eligibility itself
-- from purchases / published_books / guild_treasury_transactions — never from anything the
-- client reports.

create index if not exists referral_grants_referral_id_idx on referral_grants (referral_id);

-- ============================================================================================
-- referral_reader_signal / referral_writer_signal / referral_guild_signal — the real,
-- server-verified eligibility check for one referee, for one reward kind. Each is `security
-- definer` specifically so it CAN read the referee's own purchases/published_books/guild rows
-- (which the referrer's own RLS would otherwise correctly hide) while returning only a boolean —
-- never a raw row — back out. That's the same shape admin_set_login_ban() uses to touch data an
-- ordinary RLS-scoped call couldn't: elevated privilege internally, a narrow, non-leaking result
-- externally.
-- ============================================================================================

create or replace function referral_reader_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from purchases
    where buyer_id = p_referee_id and status = 'success' and amount_kobo >= 50000 -- ₦500 floor
  );
$$;

revoke all on function referral_reader_signal(uuid) from public;
grant execute on function referral_reader_signal(uuid) to authenticated;

create or replace function referral_writer_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select
    exists (
      select 1 from published_books where author_id = p_referee_id and word_count >= 30000
      union all
      select 1 from guild_published_books where author_id = p_referee_id and word_count >= 30000
    )
    and
    coalesce((select sum(author_amount_kobo) from purchases
              where author_id = p_referee_id and status = 'success'), 0) >= 500000; -- ₦5,000 floor
$$;

revoke all on function referral_writer_signal(uuid) from public;
grant execute on function referral_writer_signal(uuid) to authenticated;

create or replace function referral_guild_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(sum(t.amount_kobo), 0) >= 500000 -- ₦5,000 floor, real sale revenue only
  from guild_treasury_transactions t
  join player_guilds g on g.id = t.guild_id
  where g.owner_id = p_referee_id
    and t.kind in ('anthology_share', 'event_revenue')
    and t.status = 'success';
$$;

revoke all on function referral_guild_signal(uuid) from public;
grant execute on function referral_guild_signal(uuid) to authenticated;

-- ============================================================================================
-- grant_referral_reward — the one place a referral_grants row is ever created. Re-derives
-- eligibility itself (via the three signal functions above) rather than trusting anything the
-- caller reports, locks per (referral, kind) before checking "already granted" so two concurrent
-- calls can never both pass, and is a no-op (returns the existing row) on a retry against an
-- already-granted (referral, kind) pair rather than raising — same idempotency contract
-- grant_naira_achievement() and redeem_referral_code() already use, for the same reason:
-- referral_reward_progress() below depends on it to call this safely on every read.
-- ============================================================================================

create or replace function grant_referral_reward(p_referral_id uuid, p_kind text)
returns referral_grants
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referral referrals%rowtype;
  v_row referral_grants;
  v_reward_kobo bigint;
  v_eligible boolean;
begin
  select * into v_referral from referrals where id = p_referral_id;
  if not found then
    raise exception 'No such referral.';
  end if;

  -- Only the referrer who stands to be paid can trigger an attempt for their own referral — the
  -- caller-scoping half of "never trust a client-supplied target"; the eligibility check itself
  -- (the other half) is re-derived from the referee's real data below, never from the caller.
  if v_referral.referrer_id <> auth.uid() then
    raise exception 'Not your referral.';
  end if;

  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row; -- already granted — idempotent, not an error
  end if;

  -- Reward amounts mirror NAIRA_ACHIEVEMENTS' own convention (kobo = Naira x100). See this
  -- migration's header for why each is sized the way it is.
  case p_kind
    when 'reader_purchase' then v_reward_kobo := 20000;   -- ₦200
    when 'writer_earnings' then v_reward_kobo := 200000;  -- ₦2,000
    when 'guild_activity'  then v_reward_kobo := 300000;  -- ₦3,000
    else
      raise exception 'Unknown referral reward kind.';
  end case;

  -- Locked per (referral, kind) — same lock-then-recheck shape grant_naira_achievement() and
  -- settle_guild_event() already use, scoped narrowly since two different reward kinds for the
  -- same referral have nothing to serialize against each other.
  perform pg_advisory_xact_lock(hashtext('referral_reward:' || p_referral_id::text || ':' || p_kind));

  -- Re-read under the lock in case a concurrent call just granted it.
  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row;
  end if;

  case p_kind
    when 'reader_purchase' then v_eligible := referral_reader_signal(v_referral.referee_id);
    when 'writer_earnings' then v_eligible := referral_writer_signal(v_referral.referee_id);
    when 'guild_activity'  then v_eligible := referral_guild_signal(v_referral.referee_id);
  end case;

  if not coalesce(v_eligible, false) then
    raise exception 'This referral has not produced qualifying activity yet.';
  end if;

  insert into referral_grants (referral_id, kind, naira_reward_kobo)
  values (p_referral_id, p_kind, v_reward_kobo)
  returning * into v_row;

  -- One-directional: a referral that has already reached 'rewarded' (from an earlier reward of
  -- a different kind) stays there — this never resets or overwrites it.
  update referrals set status = 'rewarded' where id = p_referral_id and status = 'pending';

  return v_row;
end;
$$;

revoke all on function grant_referral_reward(uuid, text) from public;
grant execute on function grant_referral_reward(uuid, text) to authenticated;

-- ============================================================================================
-- referral_reward_progress — one round trip for a "your referrals" screen. For every referral
-- the CALLING user (auth.uid()) is the referrer of, attempts all three reward kinds (each call
-- independently locked and idempotent — see above), swallowing the expected "not eligible yet"
-- outcome, then reports current unlocked/amount state per (referral, kind). Same
-- read-doubles-as-grant shape as naira_achievement_progress() — there is no separate claim step
-- here either.
-- ============================================================================================

create or replace function referral_reward_progress()
returns table (referral_id uuid, referee_id uuid, kind text, unlocked boolean, naira_reward_kobo bigint)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referral referrals%rowtype;
  v_kind text;
  v_kinds text[] := array['reader_purchase', 'writer_earnings', 'guild_activity'];
begin
  for v_referral in select * from referrals where referrer_id = auth.uid() loop
    foreach v_kind in array v_kinds loop
      begin
        perform grant_referral_reward(v_referral.id, v_kind);
      exception when others then
        null; -- not eligible yet — expected, not an error worth surfacing here
      end;

      referral_id := v_referral.id;
      referee_id := v_referral.referee_id;
      kind := v_kind;
      select g.naira_reward_kobo into naira_reward_kobo
        from referral_grants g where g.referral_id = v_referral.id and g.kind = v_kind;
      unlocked := naira_reward_kobo is not null;
      return next;
    end loop;
  end loop;
end;
$$;

revoke all on function referral_reward_progress() from public;
grant execute on function referral_reward_progress() to authenticated;

-- ============================================================================================
-- author_balance_kobo — extended once more (same function, same signature, still the one place
-- a writer's withdrawable balance is computed) to add successful referral grants as a credit.
-- Based on the copy in 52_migration_naira_achievement_grants.sql (the latest one actually
-- redefined since 41_migration_guild_member_earnings_withdrawal.sql) — not the older copy still
-- sitting in supabase/schema.sql, which has been drifting since migration 41 and is flagged
-- there already; this migration doesn't fix that pre-existing drift, only adds to it in the same
-- already-documented way.
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(p.author_amount_kobo) from purchases p
              where p.author_id = check_user_id and p.status = 'success'
                and not exists (
                  select 1 from guild_anthologies a where a.published_book_id = p.book_id
                )), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0)
    +
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where member_id = check_user_id and kind = 'release_to_member' and status = 'success'), 0)
    +
    coalesce((select sum(naira_reward_kobo) from achievement_grants
              where user_id = check_user_id), 0)
    +
    coalesce((select sum(rg.naira_reward_kobo) from referral_grants rg
              join referrals r on r.id = rg.referral_id
              where r.referrer_id = check_user_id), 0);
$$ language sql stable security definer set search_path = public;

revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- ============================================================================================
-- Migration 57 (see supabase/history/57_migration_referral_reward_platform_fee_funding.sql)
-- ============================================================================================

-- Migration 57: Referral Rewards funded by Inkroot's own platform fee — not a flat, unlimited
-- amount picked upfront.
--
-- 56_migration_referral_rewards.sql paid a fixed ₦200 / ₦2,000 / ₦3,000 per reward kind,
-- unconnected to how much money the qualifying activity actually generated for Inkroot. That's
-- exactly the "unlimited separate cash pool" this migration replaces: from here on, a referral
-- reward is always a small, fixed SHARE of the real platform fee Inkroot itself already
-- collected from the qualifying transaction(s) — never a number invented independently of it,
-- and never anything drawn from an author's or guild member's own agreed earnings.
--
-- The mechanism this leans on already exists and is untouched by this migration:
-- `_shared/payments.ts`'s authorAmountKobo(amountKobo) (PLATFORM_FEE_BPS = 1000, i.e. 10%) is
-- applied at the moment ANY real Naira payment is initiated — a book/tip purchase
-- (purchases.author_amount_kobo) or a Guild Event entry (guild_event_entries.net_kobo) — so
-- `gross - net` is always sitting right there on the row, is exactly what Paystack actually
-- confirmed, and reflects whatever PLATFORM_FEE_BPS was in effect at the time (past rows keep
-- whatever split they were written with — same posture that constant's own comment already
-- documents). This migration never recomputes a fee from scratch; it only ever reads
-- `gross - net` off rows that already exist.
--
-- Worked example, matching the request exactly: a ₦5,000 (500,000 kobo) book purchase.
-- author_amount_kobo = 450,000 (author's normal 90% — completely untouched by any of this).
-- Inkroot's platform fee = 500,000 - 450,000 = 50,000 kobo (₦500). referral_fee_share_bps() below
-- (2000 = 20%) means the referral reward funded by this specific purchase is
-- 50,000 * 20% = 10,000 kobo (₦100) — a small portion of Inkroot's own fee, nothing more.
--
-- referral_fee_share_bps() — one function, not a literal repeated three times — is the ONE place
-- this percentage lives; change it there and every reward kind's payout changes with it, the
-- same "change it in one place" posture PLATFORM_FEE_BPS itself uses.
--
-- What funds each kind, concretely (eligibility gates — referral_reader_signal/
-- referral_writer_signal/referral_guild_signal, i.e. the ₦500 / ₦5,000 / ₦5,000 floors that make
-- an activity "genuine" — are UNCHANGED from migration 56; only the payout AMOUNT changes here):
--
--   reader_purchase — the platform fee (amount_kobo - author_amount_kobo) of the one specific
--     qualifying purchase itself (the earliest purchase meeting the ₦500 floor).
--
--   writer_earnings — the platform fee summed across every one of that author's successful sales
--     to date (amount_kobo - author_amount_kobo per purchases row, author_id = the referred
--     writer) — the same population of rows referral_writer_signal already sums
--     author_amount_kobo over to check the ₦5,000 earnings floor, just reading the OTHER side of
--     the same split.
--
--   guild_activity — the platform fee behind the guild's own real revenue: for every
--     'anthology_share' distribution, the fee (amount_kobo - author_amount_kobo) on the ONE
--     underlying purchase it was distributed from (via source_purchase_id — not multiplied by
--     however many members that sale's proceeds were split across, since the fee itself was
--     charged once, on the original sale, before any splitting happened); for every
--     'event_revenue' distribution, the summed fee (amount_kobo - net_kobo) across that Guild
--     Event's own successful entries (via project_event_id). Both fee sources were already real,
--     externally-verified Paystack charges before distribute_guild_revenue() ever ran — this
--     just reads what Inkroot already kept from them.
--
-- Never touches an author's or a guild member's own share: every formula below reads ONLY the
-- `gross - net` (or `amount_kobo - author_amount_kobo`) side of each row — the side that was
-- already Inkroot's, before this migration existed. author_amount_kobo, net_kobo, and every
-- guild_treasury_transactions distribution amount are exactly what they always were.
--
-- Past grants are NOT retroactively changed: any referral_grants row already written under
-- migration 56's flat amounts keeps that value forever — referral_grants is a permanent ledger,
-- never rewritten, same as achievement_grants. Only a reward granted from this migration onward
-- uses the formula below. (On a fresh install, 55/56/57 all run before any real referral
-- activity exists, so this distinction never actually matters in practice — it matters only for
-- a deployment that had already been live on 56.)
--
-- Safe to run anytime: the three new *_reward_kobo() functions are pure additive reads, and
-- grant_referral_reward() is the only thing changed to call them instead of its old fixed case
-- statement — referral_grants' own shape, RLS, and referral_reward_progress() are all untouched.

-- ============================================================================================
-- referral_fee_share_bps — the one number this whole migration is actually about. 2000 = 20% of
-- Inkroot's own platform fee on the qualifying activity. A business threshold, not a technical
-- constant — tune it here if the percentage proves wrong; nothing else in this migration needs
-- to change if it does.
-- ============================================================================================

create or replace function referral_fee_share_bps()
returns integer
language sql immutable as $$
  select 2000; -- 20%
$$;

-- ============================================================================================
-- referral_reader_reward_kobo — 20% of the platform fee on the ONE purchase that made this
-- referral eligible (the earliest of the referee's successful purchases at/above the ₦500
-- floor — same row referral_reader_signal already checks exists). Returns null if there is no
-- such purchase (the caller only ever calls this after referral_reader_signal already confirmed
-- there is).
-- ============================================================================================

create or replace function referral_reader_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  select round((p.amount_kobo - p.author_amount_kobo) * referral_fee_share_bps() / 10000.0)::bigint
  from purchases p
  where p.buyer_id = p_referee_id and p.status = 'success' and p.amount_kobo >= 50000
  order by coalesce(p.paid_at, p.created_at) asc
  limit 1;
$$;

revoke all on function referral_reader_reward_kobo(uuid) from public;
grant execute on function referral_reader_reward_kobo(uuid) to authenticated;

-- ============================================================================================
-- referral_writer_reward_kobo — 20% of the total platform fee Inkroot has collected across every
-- one of the referred writer's successful sales to date. Reads amount_kobo - author_amount_kobo
-- (Inkroot's side) on exactly the rows referral_writer_signal sums author_amount_kobo (the
-- author's side) over to check the ₦5,000 earnings floor — same population, opposite column.
-- ============================================================================================

create or replace function referral_writer_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  select round(coalesce(sum(p.amount_kobo - p.author_amount_kobo), 0) * referral_fee_share_bps() / 10000.0)::bigint
  from purchases p
  where p.author_id = p_referee_id and p.status = 'success';
$$;

revoke all on function referral_writer_reward_kobo(uuid) from public;
grant execute on function referral_writer_reward_kobo(uuid) to authenticated;

-- ============================================================================================
-- referral_guild_reward_kobo — 20% of the total platform fee behind the referred guild owner's
-- own real guild revenue (anthology_share + event_revenue, the same two kinds
-- referral_guild_signal already restricts to). Each underlying sale/event's fee is counted
-- exactly once (DISTINCT on source_purchase_id / project_event_id) regardless of how many guild
-- members that sale's NET proceeds were subsequently split across — the fee itself was charged
-- once, on the original gross amount, before any splitting happened.
-- ============================================================================================

create or replace function referral_guild_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  with owned_guild_ids as (
    select id from player_guilds where owner_id = p_referee_id
  ),
  anthology_sources as (
    select distinct t.source_purchase_id
    from guild_treasury_transactions t
    where t.guild_id in (select id from owned_guild_ids)
      and t.kind = 'anthology_share' and t.status = 'success' and t.source_purchase_id is not null
  ),
  anthology_fee as (
    select coalesce(sum(p.amount_kobo - p.author_amount_kobo), 0) as fee_kobo
    from anthology_sources s
    join purchases p on p.id = s.source_purchase_id
  ),
  event_sources as (
    select distinct t.project_event_id
    from guild_treasury_transactions t
    where t.guild_id in (select id from owned_guild_ids)
      and t.kind = 'event_revenue' and t.status = 'success' and t.project_event_id is not null
  ),
  event_fee as (
    select coalesce(sum(e.amount_kobo - e.net_kobo), 0) as fee_kobo
    from event_sources s
    join guild_event_entries e on e.event_id = s.project_event_id and e.status = 'success'
  )
  select round(
    (coalesce((select fee_kobo from anthology_fee), 0) + coalesce((select fee_kobo from event_fee), 0))
    * referral_fee_share_bps() / 10000.0
  )::bigint;
$$;

revoke all on function referral_guild_reward_kobo(uuid) from public;
grant execute on function referral_guild_reward_kobo(uuid) to authenticated;

-- ============================================================================================
-- grant_referral_reward — re-declared (same signature, same idempotent/locking shape as
-- 56_migration_referral_rewards.sql) to source v_reward_kobo from the three *_reward_kobo()
-- functions above instead of a fixed ₦200/₦2,000/₦3,000 case statement. Eligibility itself
-- (referral_reader_signal / referral_writer_signal / referral_guild_signal) is UNCHANGED —
-- still what decides whether a reward exists AT ALL; the functions above only decide how much,
-- now genuinely tied to what the qualifying activity actually earned Inkroot.
-- ============================================================================================

create or replace function grant_referral_reward(p_referral_id uuid, p_kind text)
returns referral_grants
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referral referrals%rowtype;
  v_row referral_grants;
  v_reward_kobo bigint;
  v_eligible boolean;
begin
  select * into v_referral from referrals where id = p_referral_id;
  if not found then
    raise exception 'No such referral.';
  end if;

  if v_referral.referrer_id <> auth.uid() then
    raise exception 'Not your referral.';
  end if;

  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row; -- already granted — idempotent, not an error. Keeps whatever amount it was
                   -- originally granted with, even if that predates this migration.
  end if;

  if p_kind not in ('reader_purchase', 'writer_earnings', 'guild_activity') then
    raise exception 'Unknown referral reward kind.';
  end if;

  -- Locked per (referral, kind) — same shape as migration 56 and grant_naira_achievement().
  perform pg_advisory_xact_lock(hashtext('referral_reward:' || p_referral_id::text || ':' || p_kind));

  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row;
  end if;

  case p_kind
    when 'reader_purchase' then v_eligible := referral_reader_signal(v_referral.referee_id);
    when 'writer_earnings' then v_eligible := referral_writer_signal(v_referral.referee_id);
    when 'guild_activity'  then v_eligible := referral_guild_signal(v_referral.referee_id);
  end case;

  if not coalesce(v_eligible, false) then
    raise exception 'This referral has not produced qualifying activity yet.';
  end if;

  -- The actual connection to the transaction system: the reward is whatever share of Inkroot's
  -- own already-collected platform fee the qualifying activity generated — never a number
  -- independent of it, and never anything above what the fee itself was.
  case p_kind
    when 'reader_purchase' then v_reward_kobo := referral_reader_reward_kobo(v_referral.referee_id);
    when 'writer_earnings' then v_reward_kobo := referral_writer_reward_kobo(v_referral.referee_id);
    when 'guild_activity'  then v_reward_kobo := referral_guild_reward_kobo(v_referral.referee_id);
  end case;

  if coalesce(v_reward_kobo, 0) <= 0 then
    -- Shouldn't happen given the eligibility floors above (each guarantees a real, positive
    -- underlying fee) — guarded anyway since referral_grants itself requires a positive amount,
    -- and "no fee to fund this from yet" is a clearer error than a constraint violation.
    raise exception 'No platform fee available yet to fund this referral reward.';
  end if;

  insert into referral_grants (referral_id, kind, naira_reward_kobo)
  values (p_referral_id, p_kind, v_reward_kobo)
  returning * into v_row;

  update referrals set status = 'rewarded' where id = p_referral_id and status = 'pending';

  return v_row;
end;
$$;

revoke all on function grant_referral_reward(uuid, text) from public;
grant execute on function grant_referral_reward(uuid, text) to authenticated;

-- ============================================================================================
-- Migration 58 (see supabase/history/58_migration_referral_reward_limits_and_anti_abuse.sql)
-- ============================================================================================

-- Migration 58: Referral Reward limits and anti-abuse — closes the fraud vectors an unmoderated
-- referral-reward system always has to close eventually, and moves every threshold that was
-- still a hardcoded literal (the three eligibility floors from migration 56, and the fee-share
-- percentage from migration 57) into one moderator-configurable table. No new wallet, no new
-- payout pipeline, no change to referral_grants' shape or to referral_reward_progress()'s
-- contract — src/lib/referrals.js and every screen that ever calls it needs zero changes.
--
-- Run this after 57_migration_referral_reward_platform_fee_funding.sql. Safe to run anytime: the
-- new config table seeds itself with the exact values 56/57 already hardcoded (so behavior is
-- byte-for-byte identical until a moderator actually changes a setting), the new reversals table
-- is additive, and the redeclared functions keep every existing signature.
--
-- ================================================================================================
-- THREAT-BY-THREAT: what this migration does about each thing asked for
-- ================================================================================================
--
--   Self-referrals — ALREADY CLOSED, unchanged here. `check (referrer_id <> referee_id)` on
--     `referrals` itself, plus an explicit check inside redeem_referral_code() (migration 55).
--     Structural, not a threshold, so there's nothing to make configurable.
--
--   Duplicate accounts — NEW: referral_devices_linked() below reuses device_signals (migration
--     30's soft ban-evasion signal — the same "a plain, easily-cleared random id recorded per
--     sign-in" table src/shared-utils/device-signal.js already documents at length) to check
--     whether a referrer and their referee have ever signed in on the same browser. That table's
--     own comment is explicit that the signal "never auto-blocks anything on its own" for
--     moderation purposes — worth being honest that this migration treats it differently, and
--     why: moderation there means banning an account or restricting content, a real and
--     hard-to-reverse cost against a signal that's trivial to spoof by clearing storage. Here it
--     only ever withholds a NOT-yet-paid reward — the account, its content, and its ability to
--     keep using Inkroot are completely untouched, redemption/tracking (migration 55) still
--     happens normally, and it's fully reversible (a moderator can always grant manually via
--     SQL, the same escape hatch every other edge case in this schema already relies on). That
--     asymmetry — cheap to apply, cheap to reverse, blocks money rather than speech or access —
--     is why grant_referral_reward() below is allowed to gate on it directly instead of only
--     surfacing it to a human.
--
--   Repeated purchases designed to farm rewards — ALREADY MOSTLY CLOSED (unique(referral_id,
--     kind) in migration 56 means a given referral can pay out `reader_purchase` at most once,
--     ever, no matter how many purchases the referee goes on to make), TIGHTENED here by the new
--     eligibility holding period (see below) so a purchase can't fund a reward until it's had
--     time to prove it will actually stick.
--
--   Refund abuse — NEW, two parts. (a) Every eligibility signal and every reward-amount function
--     below now also requires the qualifying purchase(s)/distribution(s) to be older than the
--     new configurable `eligibility_holding_period_days` — a purchase that gets refunded or
--     disputed inside that window (see migration 50's `refunded` status and its webhook handler)
--     simply never reaches `status = 'success'` for long enough to fund anything in the first
--     place. (b) For the rarer case where a reward was already granted before a refund/dispute
--     landed, reconcile_referral_grants() below re-derives eligibility for every past grant and
--     permanently reverses (via the new append-only referral_grant_reversals ledger — grants
--     themselves are still never updated or deleted, same permanence as achievement_grants and
--     guild_treasury_transactions) any grant whose underlying activity no longer qualifies.
--     author_balance_kobo() nets reversals out; referral_reward_progress() still shows the
--     original grant as history, same "ledger is history, balance is the net" split this schema
--     already uses for withdrawals and guild treasury. A grant, once reversed, can never be
--     re-granted (unique(referral_id, kind) still holds) — closing the "buy, get paid, refund,
--     rebuy" loop for good on that specific (referral, kind) pair.
--
--   Fake activity — ALREADY MOSTLY CLOSED (every signal re-derives eligibility from a real,
--     externally-verified row: a Paystack-confirmed `purchases.status = 'success'`, a real
--     30k-word `published_books`/`guild_published_books` row, a real `guild_treasury_
--     transactions` distribution — never anything the client reports about itself), TIGHTENED by
--     the same holding period and reconciliation as refund abuse above, since "fake" activity
--     that gets reversed shortly after is now caught the same way refunded activity is.
--
--   Referral chains designed to generate unlimited rewards — ALREADY STRUCTURALLY BOUNDED
--     (a referrer is only ever paid for their OWN direct referees' activity; migration 55's
--     `unique(referee_id)` means an account can be referred exactly once ever, and nothing in
--     this schema gives a referrer credit for who their referee goes on to refer — there is no
--     multi-level attribution to chain in the first place), now given a hard ceiling regardless:
--     the new `max_lifetime_referral_earnings_kobo` caps one referrer's total referral income no
--     matter how many accounts (real or fabricated) end up crediting them, and
--     referral_devices_linked() closes the specific "one operator, many sockpuppet referees"
--     version of this that a lifetime cap alone wouldn't catch quickly.
--
-- ================================================================================================
-- CONFIGURABLE LIMITS ADDED (all four asked for, all in one moderator-managed row):
--   - reward per referral      -> max_reward_per_referral_kobo (hard ceiling on any single
--                                  (referral, kind) grant, on top of the existing fee-share math)
--   - lifetime referral earnings -> max_lifetime_referral_earnings_kobo (hard ceiling on one
--                                  referrer's total referral income, ever)
--   - qualifying transaction amount -> reader_min_purchase_kobo / writer_min_earnings_kobo /
--                                  guild_min_revenue_kobo (were literal 50000/500000/500000 in
--                                  migration 56 — same values, now moderator-editable)
--   - reward eligibility period -> eligibility_holding_period_days (new: how long a qualifying
--                                  purchase/distribution must sit unrefunded before it can fund
--                                  a reward at all)
--   - fee_share_bps is also moved in alongside these (was migration 57's hardcoded
--     referral_fee_share_bps() literal 2000) since it's exactly the same kind of value and
--     belongs in the same one place.
-- ================================================================================================

-- ============================================================================================
-- referral_reward_config — singleton config row, same shape/trust-tier as rising_star_config
-- (migration 38) and guilds_on_rise_config: moderator read/update only, nothing here is
-- client-writable, and it seeds itself with migration 56/57's exact original values so nothing
-- changes behaviorally until a moderator actually edits a setting.
-- ============================================================================================

create table if not exists referral_reward_config (
  id boolean primary key default true check (id),
  reader_min_purchase_kobo bigint not null default 50000 check (reader_min_purchase_kobo >= 0),
  writer_min_earnings_kobo bigint not null default 500000 check (writer_min_earnings_kobo >= 0),
  guild_min_revenue_kobo bigint not null default 500000 check (guild_min_revenue_kobo >= 0),
  fee_share_bps integer not null default 2000 check (fee_share_bps between 0 and 10000),
  max_reward_per_referral_kobo bigint not null default 500000 check (max_reward_per_referral_kobo > 0),
  max_lifetime_referral_earnings_kobo bigint not null default 5000000 check (max_lifetime_referral_earnings_kobo > 0),
  eligibility_holding_period_days integer not null default 7 check (eligibility_holding_period_days between 0 and 90),
  updated_at timestamptz not null default now()
);

insert into referral_reward_config (id) values (true) on conflict (id) do nothing;

alter table referral_reward_config enable row level security;

-- Not publicly readable, same reasoning as rising_star_config: the exact floors/caps are part of
-- what makes this hard to game, and there's no legitimate reader-facing reason to expose them.
create policy "moderators read referral reward config" on referral_reward_config
  for select using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));
create policy "moderators update referral reward config" on referral_reward_config
  for update using (exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator));

-- ============================================================================================
-- referral_devices_linked — the duplicate-account signal, scoped to exactly one question: has
-- this referrer and this referee ever signed in on the same browser. Security definer so it can
-- read device_signals (moderator-only by RLS otherwise) while returning only a boolean, same
-- narrow-result shape referral_reader_signal/etc. already use.
-- ============================================================================================

create or replace function referral_devices_linked(p_referrer_id uuid, p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from device_signals a
    join device_signals b on b.device_id = a.device_id
    where a.user_id = p_referrer_id and b.user_id = p_referee_id
  );
$$;

revoke all on function referral_devices_linked(uuid, uuid) from public;
grant execute on function referral_devices_linked(uuid, uuid) to authenticated;

-- ============================================================================================
-- referral_fee_share_bps — redeclared to read from referral_reward_config instead of a hardcoded
-- literal. Same name, same zero-argument signature, so referral_reader_reward_kobo/writer/guild
-- below (migration 57) keep calling it exactly as before with no changes of their own needed to
-- this function's callers. No longer `immutable` (it now reads a table) — `stable` instead, which
-- is what every other config-reading function in this schema already uses.
-- ============================================================================================

create or replace function referral_fee_share_bps()
returns integer
language sql stable as $$
  select fee_share_bps from referral_reward_config;
$$;

-- ============================================================================================
-- referral_reader_signal / referral_writer_signal / referral_guild_signal — redeclared: same
-- signatures, same eligibility QUESTIONS as migration 56, but the floors now come from
-- referral_reward_config instead of a literal, and every qualifying row must additionally be
-- older than eligibility_holding_period_days (make_interval(days => 0) — the config's own
-- minimum — collapses back to "no waiting period", so this is opt-in strictness, not a forced
-- delay). A purchase that's since flipped to 'refunded' (migration 50) was never going to pass
-- `status = 'success'` here regardless of age — the holding period's real job is making sure a
-- purchase has SAT at 'success' long enough for a refund/dispute to have had a real chance to
-- land before it can fund anything.
-- ============================================================================================

create or replace function referral_reader_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from purchases p
    where p.buyer_id = p_referee_id
      and p.status = 'success'
      and p.amount_kobo >= (select reader_min_purchase_kobo from referral_reward_config)
      and coalesce(p.paid_at, p.created_at)
            <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config))
  );
$$;

revoke all on function referral_reader_signal(uuid) from public;
grant execute on function referral_reader_signal(uuid) to authenticated;

create or replace function referral_writer_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select
    exists (
      select 1 from published_books where author_id = p_referee_id and word_count >= 30000
      union all
      select 1 from guild_published_books where author_id = p_referee_id and word_count >= 30000
    )
    and
    coalesce((
      select sum(p.author_amount_kobo) from purchases p
      where p.author_id = p_referee_id and p.status = 'success'
        and coalesce(p.paid_at, p.created_at)
              <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config))
    ), 0) >= (select writer_min_earnings_kobo from referral_reward_config);
$$;

revoke all on function referral_writer_signal(uuid) from public;
grant execute on function referral_writer_signal(uuid) to authenticated;

create or replace function referral_guild_signal(p_referee_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(sum(t.amount_kobo), 0) >= (select guild_min_revenue_kobo from referral_reward_config)
  from guild_treasury_transactions t
  join player_guilds g on g.id = t.guild_id
  where g.owner_id = p_referee_id
    and t.kind in ('anthology_share', 'event_revenue')
    and t.status = 'success'
    and t.created_at <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config));
$$;

revoke all on function referral_guild_signal(uuid) from public;
grant execute on function referral_guild_signal(uuid) to authenticated;

-- ============================================================================================
-- referral_reader_reward_kobo / referral_writer_reward_kobo / referral_guild_reward_kobo —
-- redeclared: same fee-share math as migration 57 (still 20% of Inkroot's own already-collected
-- platform fee, never anything above it), but the floor and the aging requirement now match the
-- signal functions above exactly — same population of rows, same config-driven values, so what
-- gets counted as eligible and what gets counted as fundable can never drift apart from each
-- other.
-- ============================================================================================

create or replace function referral_reader_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  select round((p.amount_kobo - p.author_amount_kobo) * referral_fee_share_bps() / 10000.0)::bigint
  from purchases p
  where p.buyer_id = p_referee_id
    and p.status = 'success'
    and p.amount_kobo >= (select reader_min_purchase_kobo from referral_reward_config)
    and coalesce(p.paid_at, p.created_at)
          <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config))
  order by coalesce(p.paid_at, p.created_at) asc
  limit 1;
$$;

revoke all on function referral_reader_reward_kobo(uuid) from public;
grant execute on function referral_reader_reward_kobo(uuid) to authenticated;

create or replace function referral_writer_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  select round(coalesce(sum(p.amount_kobo - p.author_amount_kobo), 0) * referral_fee_share_bps() / 10000.0)::bigint
  from purchases p
  where p.author_id = p_referee_id
    and p.status = 'success'
    and coalesce(p.paid_at, p.created_at)
          <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config));
$$;

revoke all on function referral_writer_reward_kobo(uuid) from public;
grant execute on function referral_writer_reward_kobo(uuid) to authenticated;

create or replace function referral_guild_reward_kobo(p_referee_id uuid)
returns bigint
language sql stable security definer set search_path = public as $$
  with owned_guild_ids as (
    select id from player_guilds where owner_id = p_referee_id
  ),
  anthology_sources as (
    select distinct t.source_purchase_id
    from guild_treasury_transactions t
    where t.guild_id in (select id from owned_guild_ids)
      and t.kind = 'anthology_share' and t.status = 'success' and t.source_purchase_id is not null
      and t.created_at <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config))
  ),
  anthology_fee as (
    select coalesce(sum(p.amount_kobo - p.author_amount_kobo), 0) as fee_kobo
    from anthology_sources s
    join purchases p on p.id = s.source_purchase_id
  ),
  event_sources as (
    select distinct t.project_event_id
    from guild_treasury_transactions t
    where t.guild_id in (select id from owned_guild_ids)
      and t.kind = 'event_revenue' and t.status = 'success' and t.project_event_id is not null
      and t.created_at <= now() - make_interval(days => (select eligibility_holding_period_days from referral_reward_config))
  ),
  event_fee as (
    select coalesce(sum(e.amount_kobo - e.net_kobo), 0) as fee_kobo
    from event_sources s
    join guild_event_entries e on e.event_id = s.project_event_id and e.status = 'success'
  )
  select round(
    (coalesce((select fee_kobo from anthology_fee), 0) + coalesce((select fee_kobo from event_fee), 0))
    * referral_fee_share_bps() / 10000.0
  )::bigint;
$$;

revoke all on function referral_guild_reward_kobo(uuid) from public;
grant execute on function referral_guild_reward_kobo(uuid) to authenticated;

-- ============================================================================================
-- grant_referral_reward — redeclared: same signature, same idempotent/locking shape as
-- migrations 56/57, with three new gates layered in before a grant can ever be inserted:
--   1. device correlation (referral_devices_linked) — blocks the whole (referral, kind) attempt
--      outright, before any kind-specific eligibility is even checked.
--   2. per-grant ceiling (max_reward_per_referral_kobo) — clamps the computed amount down, never
--      up; the fee-share math can only ever produce LESS than this ceiling.
--   3. lifetime ceiling (max_lifetime_referral_earnings_kobo) — clamps further based on what this
--      referrer has already earned (net of any reversals), down to whatever headroom remains;
--      raises instead of silently granting ₦0 once headroom is fully used up.
-- Locked on TWO keys, not one: the existing per-(referral, kind) key (unchanged from migration
-- 56/57 — still what makes a retry of the exact same grant idempotent) AND a new
-- per-REFERRER key, so two concurrent grants for the same referrer (different referrals, or
-- different kinds of the same referral) can't both read the same pre-grant lifetime total and
-- both slip under the cap.
-- ============================================================================================

create or replace function grant_referral_reward(p_referral_id uuid, p_kind text)
returns referral_grants
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referral referrals%rowtype;
  v_row referral_grants;
  v_reward_kobo bigint;
  v_eligible boolean;
  v_config referral_reward_config%rowtype;
  v_lifetime_granted_kobo bigint;
  v_lifetime_reversed_kobo bigint;
  v_remaining_headroom_kobo bigint;
begin
  select * into v_referral from referrals where id = p_referral_id;
  if not found then
    raise exception 'No such referral.';
  end if;

  if v_referral.referrer_id <> auth.uid() then
    raise exception 'Not your referral.';
  end if;

  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row; -- already granted (or already granted-then-reversed) — idempotent either way;
                   -- a reversed (referral, kind) never re-grants, by design (see this migration's
                   -- header, "refund abuse" section).
  end if;

  if p_kind not in ('reader_purchase', 'writer_earnings', 'guild_activity') then
    raise exception 'Unknown referral reward kind.';
  end if;

  -- Duplicate-account gate — checked before any lock or kind-specific work, since it's the same
  -- answer regardless of kind and should short-circuit as cheaply as possible.
  if referral_devices_linked(v_referral.referrer_id, v_referral.referee_id) then
    raise exception 'This referral is not eligible for a reward.';
  end if;

  -- Locked per (referral, kind) — same shape as migrations 56/57 — AND per-referrer, so a
  -- concurrent grant attempt for a different (referral, kind) pair belonging to the SAME
  -- referrer can't race the lifetime-cap check below.
  perform pg_advisory_xact_lock(hashtext('referral_reward:' || p_referral_id::text || ':' || p_kind));
  perform pg_advisory_xact_lock(hashtext('referral_lifetime_cap:' || v_referral.referrer_id::text));

  select * into v_row from referral_grants where referral_id = p_referral_id and kind = p_kind;
  if found then
    return v_row;
  end if;

  case p_kind
    when 'reader_purchase' then v_eligible := referral_reader_signal(v_referral.referee_id);
    when 'writer_earnings' then v_eligible := referral_writer_signal(v_referral.referee_id);
    when 'guild_activity'  then v_eligible := referral_guild_signal(v_referral.referee_id);
  end case;

  if not coalesce(v_eligible, false) then
    raise exception 'This referral has not produced qualifying activity yet.';
  end if;

  case p_kind
    when 'reader_purchase' then v_reward_kobo := referral_reader_reward_kobo(v_referral.referee_id);
    when 'writer_earnings' then v_reward_kobo := referral_writer_reward_kobo(v_referral.referee_id);
    when 'guild_activity'  then v_reward_kobo := referral_guild_reward_kobo(v_referral.referee_id);
  end case;

  select * into v_config from referral_reward_config;

  -- Gate 2: per-grant ceiling.
  if coalesce(v_reward_kobo, 0) > v_config.max_reward_per_referral_kobo then
    v_reward_kobo := v_config.max_reward_per_referral_kobo;
  end if;

  -- Gate 3: lifetime ceiling, net of any past reversals on this referrer's other grants.
  select coalesce(sum(g.naira_reward_kobo), 0) into v_lifetime_granted_kobo
  from referral_grants g join referrals r on r.id = g.referral_id
  where r.referrer_id = v_referral.referrer_id;

  select coalesce(sum(x.kobo_reversed), 0) into v_lifetime_reversed_kobo
  from referral_grant_reversals x
  join referral_grants g on g.id = x.referral_grant_id
  join referrals r on r.id = g.referral_id
  where r.referrer_id = v_referral.referrer_id;

  v_remaining_headroom_kobo := v_config.max_lifetime_referral_earnings_kobo
                                - (v_lifetime_granted_kobo - v_lifetime_reversed_kobo);

  if v_remaining_headroom_kobo <= 0 then
    raise exception 'This referrer has reached the lifetime referral earnings limit.';
  end if;

  if v_reward_kobo > v_remaining_headroom_kobo then
    v_reward_kobo := v_remaining_headroom_kobo;
  end if;

  if coalesce(v_reward_kobo, 0) <= 0 then
    raise exception 'No platform fee available yet to fund this referral reward.';
  end if;

  insert into referral_grants (referral_id, kind, naira_reward_kobo)
  values (p_referral_id, p_kind, v_reward_kobo)
  returning * into v_row;

  update referrals set status = 'rewarded' where id = p_referral_id and status = 'pending';

  return v_row;
end;
$$;

revoke all on function grant_referral_reward(uuid, text) from public;
grant execute on function grant_referral_reward(uuid, text) to authenticated;

-- ============================================================================================
-- referral_grant_reversals — one permanent row per (referral_grants row that turned out not to
-- qualify anymore). Mirrors referral_grants' own permanence: never updated or deleted. A grant
-- can be reversed at most once, ever (unique below) — there's nothing to reverse twice, and a
-- reversed (referral, kind) can never be re-granted (grant_referral_reward's own idempotent
-- lookup returns the original, still-reversed row forever).
-- ============================================================================================

create table if not exists referral_grant_reversals (
  id uuid primary key default gen_random_uuid(),
  referral_grant_id uuid not null references referral_grants(id) on delete cascade,
  kobo_reversed bigint not null check (kobo_reversed > 0),
  reason text not null check (char_length(reason) <= 500),
  created_at timestamptz not null default now(),
  unique (referral_grant_id)
);

alter table referral_grant_reversals enable row level security;

-- Readable by the referrer it affects, same join-back shape referral_grants' own select policy
-- already uses.
create policy "a referrer reads their own referral grant reversals" on referral_grant_reversals
  for select using (
    exists (
      select 1 from referral_grants g join referrals r on r.id = g.referral_id
      where g.id = referral_grant_reversals.referral_grant_id and r.referrer_id = auth.uid()
    )
  );
-- No client insert/update/delete policy at all — every row is created only by
-- reverse_referral_grant() below, which only service_role or a moderator can call.

create index if not exists referral_grant_reversals_grant_id_idx on referral_grant_reversals (referral_grant_id);

-- ============================================================================================
-- reverse_referral_grant — the one place a referral_grant_reversals row is ever created.
-- Idempotent (a retry against an already-reversed grant returns the existing reversal rather
-- than raising), same contract as every other grant/redeem function in this file.
-- ============================================================================================

create or replace function reverse_referral_grant(
  p_grant_id uuid,
  p_reason text default 'underlying activity no longer qualifies (refund or chargeback)'
)
returns referral_grant_reversals
language plpgsql
security definer
set search_path = public
as $$
declare
  v_grant referral_grants%rowtype;
  v_row referral_grant_reversals;
begin
  if coalesce(auth.role(), '') <> 'service_role'
     and not exists (select 1 from profiles where id = auth.uid() and is_moderator) then
    raise exception 'Not authorized.';
  end if;

  select * into v_grant from referral_grants where id = p_grant_id;
  if not found then
    raise exception 'No such referral grant.';
  end if;

  select * into v_row from referral_grant_reversals where referral_grant_id = p_grant_id;
  if found then
    return v_row; -- already reversed — idempotent, not an error
  end if;

  insert into referral_grant_reversals (referral_grant_id, kobo_reversed, reason)
  values (p_grant_id, v_grant.naira_reward_kobo, p_reason)
  returning * into v_row;

  return v_row;
end;
$$;

revoke all on function reverse_referral_grant(uuid, text) from public;

-- ============================================================================================
-- reconcile_referral_grants — re-derives eligibility for every referral_grants row that hasn't
-- already been reversed, using the exact same signal functions grant_referral_reward() itself
-- calls, and reverses anything that no longer qualifies (a refund or dispute landed after the
-- reward was already granted). Service-role only, scheduled daily via pg_cron below — same
-- pattern purge_expired_account_deletions() (schema.sql) already establishes for a periodic
-- background sweep. Returns the number of grants reversed on this run, purely for observability
-- in the cron job's own log.
-- ============================================================================================

create or replace function reconcile_referral_grants()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_grant record;
  v_still_eligible boolean;
  v_reversed_count integer := 0;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized.';
  end if;

  for v_grant in
    select g.id, g.kind, r.referee_id
    from referral_grants g
    join referrals r on r.id = g.referral_id
    where not exists (select 1 from referral_grant_reversals x where x.referral_grant_id = g.id)
  loop
    case v_grant.kind
      when 'reader_purchase' then v_still_eligible := referral_reader_signal(v_grant.referee_id);
      when 'writer_earnings' then v_still_eligible := referral_writer_signal(v_grant.referee_id);
      when 'guild_activity'  then v_still_eligible := referral_guild_signal(v_grant.referee_id);
      else v_still_eligible := true; -- unknown kind: never written by this schema, leave untouched
    end case;

    if not coalesce(v_still_eligible, false) then
      perform reverse_referral_grant(v_grant.id, 'underlying activity no longer qualifies (refund or chargeback)');
      v_reversed_count := v_reversed_count + 1;
    end if;
  end loop;

  return v_reversed_count;
end;
$$;

revoke all on function reconcile_referral_grants() from public;

-- Requires the pg_cron extension (same one purge_expired_account_deletions already needs — see
-- schema.sql's own comment on that schedule call for how to enable it). Runs daily at 04:00 UTC,
-- staggered an hour after the account-deletion purge. Re-running is always safe: every grant it
-- touches is either already reversed (skipped, per the `not exists` filter above) or genuinely
-- re-evaluated fresh each time.
select cron.schedule('reconcile-referral-grants', '0 4 * * *', $$select reconcile_referral_grants();$$);

-- ============================================================================================
-- author_balance_kobo — extended once more (same function, same signature) so a reversed
-- referral grant actually reduces what its referrer can withdraw. Based on the copy in
-- 56_migration_referral_rewards.sql, the latest one actually redefined — same pre-existing
-- schema.sql drift note applies as it did there.
-- ============================================================================================

create or replace function author_balance_kobo(check_user_id uuid)
returns bigint as $$
  select
    coalesce((select sum(p.author_amount_kobo) from purchases p
              where p.author_id = check_user_id and p.status = 'success'
                and not exists (
                  select 1 from guild_anthologies a where a.published_book_id = p.book_id
                )), 0)
    -
    coalesce((select sum(amount_kobo) from withdrawals
              where user_id = check_user_id and status in ('pending', 'success')), 0)
    -
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where created_by = check_user_id and kind = 'contribution' and status in ('pending', 'success')), 0)
    +
    coalesce((select sum(amount_kobo) from guild_treasury_transactions
              where member_id = check_user_id and kind = 'release_to_member' and status = 'success'), 0)
    +
    coalesce((select sum(naira_reward_kobo) from achievement_grants
              where user_id = check_user_id), 0)
    +
    coalesce((select sum(rg.naira_reward_kobo) from referral_grants rg
              join referrals r on r.id = rg.referral_id
              where r.referrer_id = check_user_id), 0)
    -
    coalesce((select sum(x.kobo_reversed) from referral_grant_reversals x
              join referral_grants rg on rg.id = x.referral_grant_id
              join referrals r on r.id = rg.referral_id
              where r.referrer_id = check_user_id), 0);
$$ language sql stable security definer set search_path = public;

revoke all on function author_balance_kobo(uuid) from public;
grant execute on function author_balance_kobo(uuid) to authenticated;

-- ============================================================================================
-- Migration 59 (see supabase/history/59_migration_referral_reward_progress_reflects_reversals.sql)
-- ============================================================================================

-- Migration 59: two fixes found during a full audit of the referral reward system (55–58)
-- against ten specific correctness/security requirements. Everything else audited clean; these
-- are the only two gaps found, both scoped narrowly, neither touching money math, RLS, or the
-- withdrawal/purchase/wallet tables at all.
--
-- ================================================================================================
-- FIX 1 — reverse_referral_grant() was missing its execute grant, making the manual/moderator
-- reversal path unreachable from the client.
-- ================================================================================================
--
-- 58_migration_referral_reward_limits_and_anti_abuse.sql wrote reverse_referral_grant() with an
-- internal check explicitly designed to allow TWO callers: `auth.role() = 'service_role'` OR a
-- signed-in user with `profiles.is_moderator = true`. But the migration only wrote
-- `revoke all on function reverse_referral_grant(uuid, text) from public;` and never followed it
-- with a `grant execute ... to authenticated` — the exact two-line pattern every other
-- moderator-callable function in this schema uses (see admin_set_login_ban(), which is otherwise
-- the closest analog: internal is_moderator check, external grant to authenticated so the RPC
-- call can even reach that check).
--
-- Net effect before this fix: a moderator calling supabase.rpc('reverse_referral_grant', {...})
-- from a client gets a Postgres permission-denied error before the function body's own
-- authorization check ever runs — the manual reversal path was completely dead code. The
-- automated path (reconcile_referral_grants(), on its daily pg_cron sweep) was NOT affected by
-- this — it calls reverse_referral_grant() from inside a security-definer function it owns, which
-- executes with the owner's privileges regardless of GRANT/REVOKE on the callee, the same reason
-- create_withdrawal_locked() and create_guild_event_entry_locked() correctly need no explicit
-- service_role grant of their own. So refunds WERE already being reversed daily; only the
-- on-demand moderator override was broken. Fixed by adding the missing grant — no change to the
-- function's own body, its idempotency, or its authorization check.

grant execute on function reverse_referral_grant(uuid, text) to authenticated;

-- ================================================================================================
-- FIX 2 — referral_reward_progress() didn't reflect a reversal, so a referrer's own dashboard
-- kept showing a clawed-back reward as still "unlocked" and counted its kobo in their displayed
-- lifetime-earnings total, forever.
-- ================================================================================================
--
-- author_balance_kobo() has always correctly netted out reversals (58_migration_..._anti_abuse.sql
-- extended it to subtract referral_grant_reversals the same migration that introduced them) — the
-- real, withdrawable balance was never wrong, and create_withdrawal_locked() reads that same
-- function, so nothing here ever let a referrer withdraw clawed-back money. This fix is entirely
-- about referral_reward_progress()'s OWN output — the RPC src/library/referral-dashboard.jsx
-- calls to render "Earned rewards" / "Lifetime referral earnings" / each referral's reward
-- badges — which read naira_reward_kobo straight off referral_grants and never checked
-- referral_grant_reversals at all, so a reversed grant kept reporting unlocked = true with its
-- original, no-longer-real amount, indistinguishably from a still-valid one.
--
-- This is NOT the same thing 58's own header meant by "referral_reward_progress() still shows the
-- original grant as history, same 'ledger is history, balance is the net' split" — that line was
-- about the underlying referral_grants row correctly staying in place forever (append-only, never
-- deleted, so there's always a permanent record a reward WAS granted). Keeping the history row is
-- right and unchanged here. The bug is that "history" and "still true right now" were being
-- collapsed into a single unlocked boolean the client had no way to tell apart, on the one screen
-- whose entire job is telling a referrer how much they've earned.
--
-- Fix: add a `reversed` column (a plain existence check against referral_grant_reversals, same
-- shape every other signal function here already uses) and make `unlocked` mean what the client
-- actually needs it to mean — "you still have this" — false once reversed, rather than "was ever
-- granted." The row itself, and its original naira_reward_kobo, are still returned every time;
-- nothing is hidden, only correctly labeled. Same signature otherwise, same idempotent
-- attempt-then-report shape, same security definer / search_path — only the returns table shape
-- and the two lines computing naira_reward_kobo/unlocked change.

create or replace function referral_reward_progress()
returns table (referral_id uuid, referee_id uuid, kind text, unlocked boolean, naira_reward_kobo bigint, reversed boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_referral referrals%rowtype;
  v_kind text;
  v_kinds text[] := array['reader_purchase', 'writer_earnings', 'guild_activity'];
begin
  for v_referral in select * from referrals where referrer_id = auth.uid() loop
    foreach v_kind in array v_kinds loop
      begin
        perform grant_referral_reward(v_referral.id, v_kind);
      exception when others then
        null; -- not eligible yet — expected, not an error worth surfacing here
      end;

      referral_id := v_referral.id;
      referee_id := v_referral.referee_id;
      kind := v_kind;

      select g.naira_reward_kobo, (x.id is not null)
        into naira_reward_kobo, reversed
        from referral_grants g
        left join referral_grant_reversals x on x.referral_grant_id = g.id
        where g.referral_id = v_referral.id and g.kind = v_kind;

      reversed := coalesce(reversed, false);
      unlocked := naira_reward_kobo is not null and not reversed;
      return next;
    end loop;
  end loop;
end;
$$;

revoke all on function referral_reward_progress() from public;
grant execute on function referral_reward_progress() to authenticated;

-- Safe to run anytime: FIX 1 only adds a grant (no behavior change for any caller that could
-- already reach the function). FIX 2 is create-or-replace on a function whose only caller,
-- src/lib/referrals.js's fetchReferralRewardProgress(), is updated in the same change to read
-- the new `reversed` field — a deployment that updates the database without yet updating the
-- client keeps working exactly as before, since the client only reads the columns it already
-- knew about (naira_reward_kobo, unlocked) and simply won't surface `reversed` until it's
-- updated. No table, RLS policy, or money-computing function (author_balance_kobo,
-- grant_referral_reward, any *_signal or *_reward_kobo function) is touched by this migration.

-- ============================================================================================
-- Migration 60 (see supabase/history/60_migration_book_view_analytics.sql)
-- ============================================================================================

-- Migration 60: Creator Dashboard's Analytics tab — "Reader activity, traffic sources, and
-- trends across every published work" — was a CreatorComingSoonPanel (see creator-dashboard.jsx)
-- because there was no events-tracking table, exactly the gap Phase 2's README flagged as
-- deliberately out of scope for that phase ("Readers tab doesn't have traffic sources or page
-- views — that needs a separate events-tracking table, not part of this phase"). This migration
-- is that table.
--
-- Scope, deliberately: two event types only — `detail_view` (a reader opened a book's detail
-- card in the Grand Library) and `read_start` (a reader began reading the full text, from
-- anywhere: Grand Library, Author's Hall, or a Guild Bookshelf). Nothing here tracks reading
-- *progress* (how far into a book someone got, time spent, page turns) — that's a meaningfully
-- bigger scope (needs a durable per-reader reading-position signal, which this app doesn't have
-- even locally for someone else's book) and a separate decision if it's ever worth building.
--
-- Privacy posture: raw rows are never client-readable, by anyone, under any policy — no select
-- policy exists on this table at all, matching guild_treasury_transactions' "no client select
-- policy, everything through a function" stance, but here the reason is privacy rather than
-- money: a raw row ties a specific account (or none) to a specific book at a specific timestamp,
-- and nobody except that book's own author has a legitimate reason to see that traffic, in
-- aggregate, not as a list of who-viewed-what. `fetch_book_view_summary()` below is the only
-- read path, and it only ever returns aggregate counts (never a viewer's identity) to the book's
-- own author.
--
-- Anti-abuse posture, honestly scoped: `record_book_view()` dedupes a signed-in viewer's own
-- repeat views of the same book within a 5-minute window (a page reload or a double-tap
-- shouldn't count twice), the same spirit as this schema's other "a rapid repeat of the same
-- action shouldn't double-count" guards (e.g. 06_migration_guard_guild_member_stats_delta.sql).
-- An anonymous (signed-out) viewer has no durable identity to dedupe against — see
-- shared-utils/device-signal.js's own header for why nothing client-generated survives a cleared
-- browser or a private window — so an anonymous view count is an honest approximate signal, not
-- an abuse-hardened one, same as every other anonymous-traffic count on the open web. Good enough
-- to show a writer roughly how much interest a listing is getting; not something anything else in
-- this schema (payouts, rankings, achievements) ever reads or depends on.

create table if not exists book_view_events (
  id uuid primary key default gen_random_uuid(),
  book_id text not null references published_books(id) on delete cascade,
  -- Null for a signed-out viewer. Never a client-supplied id — record_book_view() always sets
  -- this from auth.uid() itself, the same "never trust what the client reports" stance every
  -- other security-definer write in this schema takes.
  viewer_id uuid references auth.users(id) on delete set null,
  event_type text not null check (event_type in ('detail_view', 'read_start')),
  -- Where the view originated. 'direct' covers every path not worth a dedicated bucket yet (a
  -- shared link, a bookmark, a guild anthology deep-link) — see record_book_view()'s own default.
  source text not null check (source in (
    'featured', 'new_releases', 'top_rated', 'discover', 'cart',
    'author_profile', 'guild_bookshelf', 'most_read', 'trending', 'direct'
  )),
  created_at timestamptz not null default now()
);

alter table book_view_events enable row level security;
-- No select/insert/update/delete policy at all, for any role — see the privacy note above.
-- Every read goes through fetch_book_view_summary() (author-only, aggregate); every write goes
-- through record_book_view() (validates event_type/source itself via the column checks, sets
-- viewer_id from auth.uid()). Both are security definer functions, so they run with the table
-- owner's privileges regardless of what RLS would otherwise allow a caller directly.

create index if not exists book_view_events_book_id_created_at_idx
  on book_view_events (book_id, created_at desc);
-- Backs record_book_view()'s own dedupe check (book_id, viewer_id, event_type, recent
-- created_at) as well as fetch_book_view_summary()'s per-book aggregation.
create index if not exists book_view_events_book_id_viewer_id_idx
  on book_view_events (book_id, viewer_id, event_type, created_at desc);

-- ================================================================================================
-- record_book_view — the only way a row lands in book_view_events. Callable signed-in OR signed-
-- out (this is the one function in this schema granted to the `anon` role, not just
-- `authenticated` — reading a free book has never required signing in, see grand-library-cards.jsx
-- BookDetailModal, so tracking that a book was viewed can't require it either).
-- ================================================================================================
create or replace function record_book_view(p_book_id text, p_event_type text, p_source text default 'direct')
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_viewer_id uuid := auth.uid(); -- null when called signed-out; never trusted from the client
begin
  -- Unknown book id: a no-op, not an error. A stale client (an already-unpublished book still
  -- open in a reader's tab) shouldn't surface a visible failure for something this cosmetic.
  if not exists (select 1 from published_books where id = p_book_id) then
    return;
  end if;

  -- Dedupe a signed-in viewer's own rapid repeat of the same (book, event_type) — see header.
  if v_viewer_id is not null and exists (
    select 1 from book_view_events
    where book_id = p_book_id and viewer_id = v_viewer_id and event_type = p_event_type
      and created_at > now() - interval '5 minutes'
  ) then
    return;
  end if;

  -- p_event_type/p_source are validated by the table's own check constraints below — an invalid
  -- value here raises rather than silently coercing, same as every other constrained-text insert
  -- in this schema.
  insert into book_view_events (book_id, viewer_id, event_type, source)
  values (p_book_id, v_viewer_id, p_event_type, coalesce(p_source, 'direct'));
end;
$$;

revoke all on function record_book_view(text, text, text) from public;
grant execute on function record_book_view(text, text, text) to authenticated, anon;

-- ================================================================================================
-- fetch_book_view_summary — the only read path. Author-only: raises if the caller isn't the
-- book's own author, same shape as save_bank_account's "Not your saved bank account" check.
-- Returns one row: total counts by event_type, a rough unique-viewer count (signed-in viewers
-- only — an anonymous view has no identity to de-duplicate by, counted in total_views but not in
-- unique_viewers), a source breakdown, and a 30-day daily trend — everything the Analytics tab
-- needs in one round trip, same "one summary call, not N" shape as guild_treasury_summary().
-- ================================================================================================
create or replace function fetch_book_view_summary(p_book_id text)
returns table (
  total_detail_views bigint,
  total_read_starts bigint,
  unique_viewers bigint,
  views_by_source jsonb,
  daily_trend jsonb
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_author_id uuid;
begin
  select author_id into v_author_id from published_books where id = p_book_id;
  if v_author_id is null then
    raise exception 'No published book found with that id.';
  end if;
  if v_author_id <> auth.uid() then
    raise exception 'Only this book''s own author can view its analytics.';
  end if;

  return query
  select
    (select count(*) from book_view_events where book_id = p_book_id and event_type = 'detail_view'),
    (select count(*) from book_view_events where book_id = p_book_id and event_type = 'read_start'),
    (select count(distinct viewer_id) from book_view_events where book_id = p_book_id and viewer_id is not null),
    (select coalesce(jsonb_object_agg(source, cnt), '{}'::jsonb)
       from (select source, count(*) as cnt from book_view_events where book_id = p_book_id group by source) s),
    (select coalesce(jsonb_agg(jsonb_build_object('date', day, 'count', cnt) order by day), '[]'::jsonb)
       from (
         select date_trunc('day', created_at)::date as day, count(*) as cnt
         from book_view_events
         where book_id = p_book_id and created_at > now() - interval '30 days'
         group by 1
       ) d);
end;
$$;

revoke all on function fetch_book_view_summary(text) from public;
grant execute on function fetch_book_view_summary(text) to authenticated;

-- ============================================================================================
-- Guild Order manuscript (Migration 65) — see supabase/history/65_migration_guild_order_manuscript.sql
-- for the full rationale.
-- ============================================================================================

-- Migration 65: Guild Order — a real shared manuscript, for both guild types.
--
-- guild-order.jsx's own HONESTY NOTE has said since it was written: "Inkroot has no backend, so
-- there are no other real writers in this guild yet... Swapping the simulated roster/seed content
-- for real members later only touches goBuildRoster and the *_SEED constants." The Roster tab is
-- swapped over in this same pass (client-only change, no schema needed — it reads
-- founder_guild_members/player_guild_members, both of which already existed). The Manuscript tab
-- needs real storage, which is what this migration adds.
--
-- Two tables, not one, on purpose:
--   - guild_order_chapters: the chapter list itself — title, status, who proposed it. One row per
--     chapter, mutable (status advances; a member correcting a typo in the title updates in place).
--   - guild_order_passages: an append-only log of real prose contributions to a chapter, each
--     attributed to whichever real member wrote it. Deliberately NOT a single mutable `content`
--     column on the chapter row — a single shared text field would mean two members editing at
--     once silently clobber each other (this app's usual last-write-wins sync model is fine for a
--     solo writer's own device, not for two different PEOPLE typing into the same field), and it
--     would erase who-wrote-what the moment a second contributor touched it. A passage per
--     contribution keeps every real writer's actual words attributed to them, permanently, and
--     sidesteps the write-conflict problem entirely — this is closer to how the Fireside already
--     works (fireside_posts is append-only too) than to a single editable document.
--
-- guild_id is `text`, not `uuid`, on both — a Founder Guild's id is one of the fixed
-- ('fantasy'/'romance'/...) keys founder_guild_members.guild_id already uses, a Player Guild's is
-- player_guilds' real uuid stringified. guild_type is the explicit discriminator so RLS below
-- knows which membership table to check rather than guessing from the string's shape.
--
-- Permission model — deliberately lighter than GO_PERMISSIONS' full six-rung ladder:
--   - Any real member (of either guild type) can propose a chapter (status starts 'draft') and add
--     a passage to any chapter.
--   - Any real member can advance a chapter's status, EXCEPT to 'approved' — that needs real
--     standing: for a Player Guild, the owner or a treasurer/officer (player_guild_members.role,
--     see 44_migration_guild_treasury_roles_and_approvals.sql — already real, already
--     RLS-authoritative, so this reuses it rather than inventing a second role system); for a
--     Founder Guild, at least one quality-length published book (published_books.word_count >=
--     15000, the same REPUTATION_QUALITY_MIN_WORDS bar author-reputation.jsx already uses to decide
--     whether a book counts toward Reputation at all). That bar is a real, honest, cheap-to-check
--     SQL proxy for "an established member of this guild" — it is NOT a re-implementation of
--     author-reputation.jsx's full diminishing-returns Reputation formula (follow/purchase/rating/
--     review/etc., each with its own sqrt curve): duplicating that formula in SQL would be a second
--     copy of business logic that can silently drift from the client's own, for a threshold that
--     only ever gates one binary action here. The client still computes and displays each real
--     member's full Reputation-based role/rung on the Roster tab; this migration only gates the one
--     write that actually needs enforcing.
--   - Deleting a chapter or a passage is restricted to whoever proposed/wrote it, and (for a
--     chapter) only while it's still a draft — once any real passage has been added or it's moved
--     to review, it's part of the guild's shared record and no longer deletable by the proposer.
--
-- No `alter publication supabase_realtime add table` for either — unlike the Fireside, there's no
-- live subscription for the manuscript in this pass; readers see new chapters/passages on their
-- next fetch (opening the tab, or after their own action), not the instant another member posts.

create table if not exists guild_order_chapters (
  id uuid primary key default gen_random_uuid(),
  guild_type text not null check (guild_type in ('founder', 'player')),
  guild_id text not null,
  order_index integer not null default 0,
  title text not null check (char_length(title) <= 200),
  status text not null default 'draft' check (status in ('draft', 'in review', 'approved')),
  proposed_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists guild_order_passages (
  id uuid primary key default gen_random_uuid(),
  chapter_id uuid not null references guild_order_chapters(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  content text not null check (char_length(content) > 0 and char_length(content) <= 8000),
  created_at timestamptz not null default now()
);

alter table guild_order_chapters enable row level security;
alter table guild_order_passages enable row level security;

-- Real-member check, inlined per policy rather than pulled into a shared function — matches this
-- schema's existing style (see founder_guild_members/player_guild_members checks scattered
-- throughout above) of a few repeated lines over one more moving part.
create policy "members read their guild's chapters" on guild_order_chapters
  for select using (
    (guild_type = 'founder' and exists (
      select 1 from founder_guild_members m where m.guild_id = guild_order_chapters.guild_id and m.user_id = auth.uid()
    ))
    or (guild_type = 'player' and (
      exists (select 1 from player_guild_members m where m.guild_id = guild_order_chapters.guild_id::uuid and m.user_id = auth.uid())
      or exists (select 1 from player_guilds g where g.id = guild_order_chapters.guild_id::uuid and g.owner_id = auth.uid())
    ))
  );

create policy "members propose chapters" on guild_order_chapters
  for insert with check (
    proposed_by = auth.uid()
    and not is_banned(auth.uid())
    and status = 'draft'
    and (
      (guild_type = 'founder' and exists (
        select 1 from founder_guild_members m where m.guild_id = guild_order_chapters.guild_id and m.user_id = auth.uid()
      ))
      or (guild_type = 'player' and (
        exists (select 1 from player_guild_members m where m.guild_id = guild_order_chapters.guild_id::uuid and m.user_id = auth.uid())
        or exists (select 1 from player_guilds g where g.id = guild_order_chapters.guild_id::uuid and g.owner_id = auth.uid())
      ))
    )
  );

-- Any real member can update a chapter (retitle it, send it to review) — approving it is the one
-- transition that needs real standing, checked in `with check` against the row's post-update
-- state rather than in `using`, so an ordinary member can still freely make every OTHER edit.
create policy "members update chapters, approving needs standing" on guild_order_chapters
  for update using (
    (guild_type = 'founder' and exists (
      select 1 from founder_guild_members m where m.guild_id = guild_order_chapters.guild_id and m.user_id = auth.uid()
    ))
    or (guild_type = 'player' and (
      exists (select 1 from player_guild_members m where m.guild_id = guild_order_chapters.guild_id::uuid and m.user_id = auth.uid())
      or exists (select 1 from player_guilds g where g.id = guild_order_chapters.guild_id::uuid and g.owner_id = auth.uid())
    ))
  )
  with check (
    status <> 'approved'
    or (guild_type = 'founder' and exists (
      select 1 from published_books b where b.author_id = auth.uid() and b.destination = 'inkroot' and b.word_count >= 15000
    ))
    or (guild_type = 'player' and (
      exists (select 1 from player_guilds g where g.id = guild_order_chapters.guild_id::uuid and g.owner_id = auth.uid())
      or exists (select 1 from player_guild_members m where m.guild_id = guild_order_chapters.guild_id::uuid and m.user_id = auth.uid() and m.role in ('treasurer', 'officer'))
    ))
  );

create policy "proposer deletes their own still-draft chapter" on guild_order_chapters
  for delete using (proposed_by = auth.uid() and status = 'draft');

create policy "members read their guild's passages" on guild_order_passages
  for select using (
    exists (
      select 1 from guild_order_chapters c where c.id = guild_order_passages.chapter_id
      and (
        (c.guild_type = 'founder' and exists (
          select 1 from founder_guild_members m where m.guild_id = c.guild_id and m.user_id = auth.uid()
        ))
        or (c.guild_type = 'player' and (
          exists (select 1 from player_guild_members m where m.guild_id = c.guild_id::uuid and m.user_id = auth.uid())
          or exists (select 1 from player_guilds g where g.id = c.guild_id::uuid and g.owner_id = auth.uid())
        ))
      )
    )
  );

create policy "members add passages to their guild's chapters" on guild_order_passages
  for insert with check (
    author_id = auth.uid()
    and not is_banned(auth.uid())
    and exists (
      select 1 from guild_order_chapters c where c.id = guild_order_passages.chapter_id
      and (
        (c.guild_type = 'founder' and exists (
          select 1 from founder_guild_members m where m.guild_id = c.guild_id and m.user_id = auth.uid()
        ))
        or (c.guild_type = 'player' and (
          exists (select 1 from player_guild_members m where m.guild_id = c.guild_id::uuid and m.user_id = auth.uid())
          or exists (select 1 from player_guilds g where g.id = c.guild_id::uuid and g.owner_id = auth.uid())
        ))
      )
    )
  );

create policy "authors delete their own passages" on guild_order_passages
  for delete using (author_id = auth.uid());

create index if not exists guild_order_chapters_guild_idx on guild_order_chapters (guild_type, guild_id);
create index if not exists guild_order_passages_chapter_idx on guild_order_passages (chapter_id);

-- updated_at bookkeeping, same pattern as published_books/player_guilds above — set on every
-- update so "last touched" is real rather than left at insert time.
create or replace function touch_guild_order_chapters_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists touch_guild_order_chapters_updated_at_trigger on guild_order_chapters;
create trigger touch_guild_order_chapters_updated_at_trigger
  before update on guild_order_chapters
  for each row execute function touch_guild_order_chapters_updated_at();

-- ============================================================================================
-- Guild Order manuscript realtime (Migration 66) — see
-- supabase/history/66_migration_guild_order_manuscript_realtime.sql for the full rationale.
-- ============================================================================================

-- Migration 66: live sync for the Guild Order's shared manuscript.
--
-- Phase 21 (migration 65) made guild_order_chapters/guild_order_passages real but deliberately
-- not live — each device only saw another member's new chapter or passage on its own next
-- fetch. This closes that gap the same way 39_migration_realtime_fireside.sql (folded into
-- schema.sql as the `fireside_posts`/`fireside_reactions` publication lines) did for the
-- Fireside: adding both tables to the supabase_realtime publication so a Postgres Changes
-- subscription can stream inserts/updates as they happen, instead of only on refetch.
--
-- No RLS changes here — Realtime respects the same row-level security policies migration 65
-- already put in place, so a subscriber only ever receives change events for rows they could
-- already SELECT.
alter publication supabase_realtime add table guild_order_chapters;
alter publication supabase_realtime add table guild_order_passages;

-- ============================================================================================
-- Guild Order World Bible (Migration 81) — see
-- supabase/history/81_migration_guild_order_world_bible.sql for the full rationale.
-- ============================================================================================

create table if not exists guild_order_world_entries (
  id uuid primary key default gen_random_uuid(),
  guild_type text not null check (guild_type in ('founder', 'player')),
  guild_id text not null,
  category text not null check (char_length(category) <= 60),
  title text not null check (char_length(title) > 0 and char_length(title) <= 200),
  blurb text not null check (char_length(blurb) <= 2000),
  author_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table guild_order_world_entries enable row level security;

create policy "members read their guild's world bible" on guild_order_world_entries
  for select using (
    (guild_type = 'founder' and exists (
      select 1 from founder_guild_members m where m.guild_id = guild_order_world_entries.guild_id and m.user_id = auth.uid()
    ))
    or (guild_type = 'player' and (
      exists (select 1 from player_guild_members m where m.guild_id = guild_order_world_entries.guild_id::uuid and m.user_id = auth.uid())
      or exists (select 1 from player_guilds g where g.id = guild_order_world_entries.guild_id::uuid and g.owner_id = auth.uid())
    ))
  );

create policy "members add entries to their guild's world bible" on guild_order_world_entries
  for insert with check (
    author_id = auth.uid()
    and (
      (guild_type = 'founder' and exists (
        select 1 from founder_guild_members m where m.guild_id = guild_order_world_entries.guild_id and m.user_id = auth.uid()
      ))
      or (guild_type = 'player' and (
        exists (select 1 from player_guild_members m where m.guild_id = guild_order_world_entries.guild_id::uuid and m.user_id = auth.uid())
        or exists (select 1 from player_guilds g where g.id = guild_order_world_entries.guild_id::uuid and g.owner_id = auth.uid())
      ))
    )
  );

create policy "authors delete their own world bible entries" on guild_order_world_entries
  for delete using (author_id = auth.uid());

create index if not exists guild_order_world_entries_guild_idx on guild_order_world_entries (guild_type, guild_id, created_at desc);

alter publication supabase_realtime add table guild_order_world_entries;

-- ============================================================================================
-- Guild Order Council (Migration 82) — see supabase/history/82_migration_guild_order_council.sql
-- for the full rationale.
-- ============================================================================================

create table if not exists guild_order_proposals (
  id uuid primary key default gen_random_uuid(),
  guild_type text not null check (guild_type in ('founder', 'player')),
  guild_id text not null,
  title text not null check (char_length(title) > 0 and char_length(title) <= 200),
  body text not null check (char_length(body) <= 2000),
  opened_by uuid not null references auth.users(id) on delete cascade,
  status text not null default 'open' check (status in ('open', 'closed')),
  created_at timestamptz not null default now(),
  closed_at timestamptz
);

create table if not exists guild_order_votes (
  id uuid primary key default gen_random_uuid(),
  proposal_id uuid not null references guild_order_proposals(id) on delete cascade,
  voter_id uuid not null references auth.users(id) on delete cascade,
  choice text not null check (choice in ('yes', 'no', 'abstain')),
  created_at timestamptz not null default now(),
  unique (proposal_id, voter_id)
);

alter table guild_order_proposals enable row level security;
alter table guild_order_votes enable row level security;

create policy "members read their guild's proposals" on guild_order_proposals
  for select using (
    (guild_type = 'founder' and exists (
      select 1 from founder_guild_members m where m.guild_id = guild_order_proposals.guild_id and m.user_id = auth.uid()
    ))
    or (guild_type = 'player' and (
      exists (select 1 from player_guild_members m where m.guild_id = guild_order_proposals.guild_id::uuid and m.user_id = auth.uid())
      or exists (select 1 from player_guilds g where g.id = guild_order_proposals.guild_id::uuid and g.owner_id = auth.uid())
    ))
  );

create policy "members open proposals in their own guild" on guild_order_proposals
  for insert with check (
    opened_by = auth.uid()
    and (
      (guild_type = 'founder' and exists (
        select 1 from founder_guild_members m where m.guild_id = guild_order_proposals.guild_id and m.user_id = auth.uid()
      ))
      or (guild_type = 'player' and (
        exists (select 1 from player_guild_members m where m.guild_id = guild_order_proposals.guild_id::uuid and m.user_id = auth.uid())
        or exists (select 1 from player_guilds g where g.id = guild_order_proposals.guild_id::uuid and g.owner_id = auth.uid())
      ))
    )
  );

create policy "openers close their own proposal" on guild_order_proposals
  for update using (opened_by = auth.uid()) with check (opened_by = auth.uid());

create policy "members read votes on proposals they can see" on guild_order_votes
  for select using (exists (
    select 1 from guild_order_proposals p where p.id = guild_order_votes.proposal_id
  ));

create policy "members cast their own vote" on guild_order_votes
  for insert with check (
    voter_id = auth.uid()
    and exists (select 1 from guild_order_proposals p where p.id = guild_order_votes.proposal_id and p.status = 'open')
  );

create policy "members change their own vote while open" on guild_order_votes
  for update using (voter_id = auth.uid()) with check (
    voter_id = auth.uid()
    and exists (select 1 from guild_order_proposals p where p.id = guild_order_votes.proposal_id and p.status = 'open')
  );

create index if not exists guild_order_proposals_guild_idx on guild_order_proposals (guild_type, guild_id, status, created_at desc);
create index if not exists guild_order_votes_proposal_idx on guild_order_votes (proposal_id);

alter publication supabase_realtime add table guild_order_proposals;
alter publication supabase_realtime add table guild_order_votes;


-- ============================================================================================
-- Book Discussion Hall (Migration 67) — see supabase/history/67_migration_book_discussion_hall.sql
-- for the full rationale.
-- ============================================================================================

-- Migration 67: a real, shared Book Discussion Hall.
--
-- DiscussionHallModal's own comment (grand-library-cards.jsx) has said since it was written:
-- "a real, working thread of the reader's own posts about a book, kept on this device... honestly
-- marked as device-local until Inkroot has a shared backend to carry every reader's posts to
-- every device." This is that backend.
--
-- book_discussion_posts mirrors `reviews` immediately above almost exactly on purpose — same
-- shape of problem (a reader's own content about a book, meant to be visible to every other
-- reader), same answer: `book_id text references published_books(id)` (published_books.id is
-- text, not uuid — it's the app's own local project id, see that table's own comment), open
-- `select` for anyone, insert/delete gated to the post's own author, and the same is_banned()
-- check on insert reviews already uses. The one real difference: reviews are one-per-reader-per-
-- book (upserted), a discussion is an ongoing conversation — so this is insert/delete only, no
-- update, and no uniqueness constraint; a reader can post as many times as they like, same as a
-- Fireside post or a Guild Order passage.
create table if not exists book_discussion_posts (
  id uuid primary key default gen_random_uuid(),
  book_id text not null references published_books(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (char_length(body) > 0 and char_length(body) <= 500),
  created_at timestamptz not null default now()
);

alter table book_discussion_posts enable row level security;

create policy "anyone can read discussion posts" on book_discussion_posts
  for select using (true);
create policy "signed-in readers post their own" on book_discussion_posts
  for insert with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "authors delete their own posts" on book_discussion_posts
  for delete using (auth.uid() = author_id);

create index if not exists book_discussion_posts_book_idx on book_discussion_posts (book_id, created_at);

-- Enables Realtime for the Discussion Hall — same mechanism the Fireside and (as of migration 66)
-- the Guild Order manuscript use: `postgres_changes` filtered on book_id, subscribed per open
-- modal.
alter publication supabase_realtime add table book_discussion_posts;

-- Backs the Grand Library's "Book Discussion Halls" shelf (grand-library-screen.jsx) — same
-- ranked-ids-then-hydrate-each-via-fetchPublishedBookById shape as Most Read/Trending
-- (compute_most_read/compute_trending), not gated to signed-in callers the way those two are:
-- they guard genuinely sensitive verified purchase/read activity, while a public post *count* on
-- a public book isn't sensitive the same way, so there's no reason to make a signed-out browser
-- fall back to nothing here.
create or replace function most_discussed_books(p_result_limit integer default null)
returns table (book_id text, post_count bigint) as $$
  select book_id, count(*) as post_count
  from book_discussion_posts
  group by book_id
  order by post_count desc
  limit coalesce(p_result_limit, 8)
$$ language sql stable;


-- ============================================================================================
-- Admin role revocation (Migration 77) — see
-- supabase/history/77_migration_admin_role_revocation.sql for the full rationale.
-- ============================================================================================

-- Migration 77: in-app revocation of is_platform_admin / is_moderator, with an audit log.
--
-- Fix-tracker item 7 originally asked for a "manage admins" screen backed by an RPC that both
-- grants AND revokes is_platform_admin/is_moderator. That's a direct reversal of a rule this
-- schema already states on purpose in two places:
--
--   - protect_admin_profile_columns()'s own comment: "an admin can't mint another admin any
--     more than a moderator can mint another moderator."
--   - src/lib/moderation.js's setVerified() comment: "is_moderator itself is NOT grantable this
--     way (or any way from the client) ... minting a moderator stays a service_role-only
--     action."
--
-- That rule caps the blast radius of a compromised admin account: even with full control of an
-- admin's session, an attacker still can't mint themselves (or anyone else) a second admin or
-- moderator account through the app. Reversing it for the sake of a self-service screen would
-- undo that protection.
--
-- Per product decision, this migration takes the middle path: REVOKING is_platform_admin or
-- is_moderator is now possible in-app (an admin account already trusted with real authority
-- removing trust from another account is a fundamentally lower-risk action than minting new
-- trust), but GRANTING either flag still requires the same manual service_role/SQL step it
-- always has — protect_admin_profile_columns is untouched for the grant direction. Every
-- revocation is logged to admin_role_revocations so there's a real audit trail of who removed
-- whose access and why, which is the auditability gap item 7 was actually chasing.

create table if not exists admin_role_revocations (
  id uuid primary key default gen_random_uuid(),
  -- set null (not cascade) on either side: the log entry should survive even if one of the
  -- accounts involved is later deleted — this is a historical record, not a live reference.
  target_user_id uuid references auth.users(id) on delete set null,
  revoked_by uuid references auth.users(id) on delete set null,
  role text not null check (role in ('moderator', 'platform_admin')),
  reason text check (reason is null or char_length(reason) <= 500),
  created_at timestamptz not null default now()
);

alter table admin_role_revocations enable row level security;

-- Only a platform admin can read the log. No insert/update/delete policy at all — same posture
-- as guild_event_hosting_fee_rates: the only writer is admin_revoke_platform_role() below, a
-- security definer function that inserts as its owner (bypassing RLS the same way
-- set_guild_event_hosting_fee already does for that table), never the client directly.
create policy "admins read the role-revocation log" on admin_role_revocations
  for select using (is_inkroot_admin());

create index if not exists admin_role_revocations_created_idx
  on admin_role_revocations (created_at desc);

-- The only in-app path that can flip is_platform_admin or is_moderator to false. Deliberately
-- one-directional (there is no admin_grant_platform_role) — see this migration's header comment.
create or replace function admin_revoke_platform_role(target_user_id uuid, role text, reason text default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not is_inkroot_admin() then
    raise exception 'Only an Inkroot admin can revoke a platform role.';
  end if;
  if target_user_id = auth.uid() then
    raise exception 'Cannot revoke your own role.';
  end if;
  if role not in ('moderator', 'platform_admin') then
    raise exception 'Unknown role.';
  end if;

  -- Same narrow, transaction-scoped bypass admin_set_login_ban already uses to update
  -- login_banned through protect_admin_profile_columns's lockdown — see that trigger's own
  -- comment. is_local = true (the third set_config argument) means this can never leak into any
  -- later, unrelated statement.
  perform set_config('inkroot.trusted_admin_rpc', 'true', true);
  if role = 'moderator' then
    update profiles set is_moderator = false where id = target_user_id;
  else
    update profiles set is_platform_admin = false where id = target_user_id;
  end if;

  insert into admin_role_revocations (target_user_id, revoked_by, role, reason)
  values (target_user_id, auth.uid(), role, nullif(trim(coalesce(reason, '')), ''));
end;
$$;

grant execute on function admin_revoke_platform_role(uuid, text, text) to authenticated;


-- ============================================================================================
-- Moderator content removal (Migration 78) — see
-- supabase/history/78_migration_moderator_content_removal.sql for the full rationale.
-- ============================================================================================

-- ============================================================================================
-- Migration 78: Moderator content removal for published_books, fireside_posts, reviews,
-- guild_book_feedback, and book_discussion_posts.
--
-- Closes item 8 of the audit: every is_moderator-gated policy up to now only granted read/update
-- on content_reports and admin config — none granted removal rights over the content itself.
-- The queue's only real levers were changing a report's status, or banning the account behind
-- it (which doesn't retroactively hide anything they already posted, since is_banned() is only
-- ever checked on INSERT/UPDATE, never SELECT). A confirmed scam/plagiarized/harassing post
-- stayed visible indefinitely unless the author deleted it themselves.
--
-- Soft-hide (a `removed_by_moderator` flag plus a filtered SELECT policy), not a hard DELETE —
-- this preserves the row for later investigation (repeat-offender patterns, appeals, undoing a
-- mistaken removal) instead of destroying evidence the moment a moderator acts. The author can
-- still see their own removed content (so it doesn't just vanish on them without explanation);
-- everyone else can't; a moderator can always see everything, removed or not.
--
-- The tricky part isn't hiding content, it's making sure the new moderator-scoped UPDATE policy
-- can ONLY flip that one flag and nothing else — Postgres RLS has no native per-column
-- restriction (this schema hits that same wall in protect_admin_profile_columns above, for
-- profiles). protect_content_from_moderator_edits() below is that trigger's sibling for content
-- tables: one generic, parameterized function (the owning column name is passed in per-table via
-- TG_ARGV) instead of five near-identical copies, since the actual check — "if the caller is a
-- moderator acting on someone else's row, only removed_by_moderator may differ from the old
-- row" — is identical across all five tables.
-- ============================================================================================

alter table published_books add column if not exists removed_by_moderator boolean not null default false;
alter table fireside_posts add column if not exists removed_by_moderator boolean not null default false;
alter table reviews add column if not exists removed_by_moderator boolean not null default false;
alter table guild_book_feedback add column if not exists removed_by_moderator boolean not null default false;
alter table book_discussion_posts add column if not exists removed_by_moderator boolean not null default false;

-- The column-level safety net described above. TG_ARGV[0] is the table's own author/owner
-- column name (author_id for four of the five tables, reviewer_id for reviews) — passed by each
-- CREATE TRIGGER below rather than hardcoded, so this one function covers all five tables.
-- to_jsonb(new) - 'removed_by_moderator' strips that one key before comparing the rest of the
-- row to its old value; if anything else changed, the update is rejected outright.
create or replace function protect_content_from_moderator_edits()
returns trigger
language plpgsql
as $$
declare
  acting_is_moderator boolean;
  author_column text := TG_ARGV[0];
  old_owner uuid;
begin
  select p.is_moderator into acting_is_moderator from profiles p where p.id = auth.uid();
  execute format('select ($1).%I', author_column) into old_owner using old;

  if coalesce(acting_is_moderator, false) and auth.uid() is distinct from old_owner then
    if (to_jsonb(new) - 'removed_by_moderator') is distinct from (to_jsonb(old) - 'removed_by_moderator') then
      raise exception 'A moderator acting on someone else''s content may only change removed_by_moderator.';
    end if;
  end if;

  return new;
end;
$$;

-- ---------- published_books ----------
-- Restricting the existing fully-open read policy means moderators (who need to see removed
-- content too, e.g. to undo a mistaken removal or review a repeat offender's history) need their
-- own bypass — same pattern fireside_posts/guild_book_feedback already use below.
drop policy if exists "anyone can read published books" on published_books;
create policy "anyone can read published books" on published_books
  for select using (not removed_by_moderator or auth.uid() = author_id);
create policy "moderators read all published books" on published_books
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "moderators remove published books" on published_books
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
drop trigger if exists protect_from_moderator_edits on published_books;
create trigger protect_from_moderator_edits
  before update on published_books
  for each row execute function protect_content_from_moderator_edits('author_id');

-- ---------- reviews ----------
drop policy if exists "anyone can read reviews" on reviews;
create policy "anyone can read reviews" on reviews
  for select using (not removed_by_moderator or auth.uid() = reviewer_id);
create policy "moderators read all reviews" on reviews
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "moderators remove reviews" on reviews
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
drop trigger if exists protect_from_moderator_edits on reviews;
create trigger protect_from_moderator_edits
  before update on reviews
  for each row execute function protect_content_from_moderator_edits('reviewer_id');

-- ---------- fireside_posts ----------
-- The general read policy already excludes non-members entirely; this just adds the removal
-- filter on top of it. "moderators read all fireside posts" already exists (see schema.sql) and
-- needs no change — it's already an unconditional bypass.
drop policy if exists "guild members read fireside posts" on fireside_posts;
create policy "guild members read fireside posts" on fireside_posts
  for select using (
    (not removed_by_moderator or auth.uid() = author_id)
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = fireside_posts.guild_id and m.user_id = auth.uid()
    )
  );
create policy "moderators remove fireside posts" on fireside_posts
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
drop trigger if exists protect_from_moderator_edits on fireside_posts;
create trigger protect_from_moderator_edits
  before update on fireside_posts
  for each row execute function protect_content_from_moderator_edits('author_id');

-- ---------- guild_book_feedback ----------
-- Same shape as fireside_posts immediately above; "moderators read all guild feedback" already
-- exists unconditionally and needs no change.
drop policy if exists "guild members read guild feedback" on guild_book_feedback;
create policy "guild members read guild feedback" on guild_book_feedback
  for select using (
    (not removed_by_moderator or auth.uid() = author_id)
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );
create policy "moderators remove guild feedback" on guild_book_feedback
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
drop trigger if exists protect_from_moderator_edits on guild_book_feedback;
create trigger protect_from_moderator_edits
  before update on guild_book_feedback
  for each row execute function protect_content_from_moderator_edits('author_id');

-- ---------- book_discussion_posts ----------
-- This table previously had no UPDATE policy at all (see its own migration's comment: "insert/
-- delete only, no update" — a reader can post as many times as they like, never edit one). This
-- adds the FIRST update policy on the table, and it's moderator-only: an ordinary author still
-- cannot update their own discussion post, only delete it, exactly as before.
drop policy if exists "anyone can read discussion posts" on book_discussion_posts;
create policy "anyone can read discussion posts" on book_discussion_posts
  for select using (not removed_by_moderator or auth.uid() = author_id);
create policy "moderators read all discussion posts" on book_discussion_posts
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
create policy "moderators remove discussion posts" on book_discussion_posts
  for update using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.is_moderator)
  );
drop trigger if exists protect_from_moderator_edits on book_discussion_posts;
create trigger protect_from_moderator_edits
  before update on book_discussion_posts
  for each row execute function protect_content_from_moderator_edits('author_id');


-- ============================================================================================
-- Account deletion guild-ownership check (Migration 79) — see
-- supabase/history/79_migration_account_deletion_guild_check.sql for the full rationale.
-- ============================================================================================

-- ============================================================================================
-- Migration 79: don't let a Player Guild owner request account deletion without knowing what
-- it does to their guild.
--
-- Correction to the original audit item: the account_deletions header comment (see
-- "Account deletion — 30-day grace period, then a non-destructive purge" above) already
-- documents that purge_expired_account_deletions() does NOT delete the auth.users row — it bans
-- sign-in and anonymizes the profile, but never triggers player_guilds.owner_id's
-- `on delete cascade`. So the guild itself, its treasury, events, and anthologies do NOT get
-- destroyed on purge, contrary to what the audit assumed.
--
-- The real bug is quieter but just as bad: purge deletes the departing owner's OWN
-- player_guild_members row (see purge_expired_account_deletions' "delete from
-- player_guild_members where user_id = rec.user_id") and permanently bans their account, but
-- player_guilds.owner_id is left pointing at that now-permanently-banned account. Nothing in the
-- app can ever change player_guilds.owner_id today (see create_or_get_own_guild's own comment:
-- "no feature does that today") — so the guild is left with an owner who can never sign in
-- again, forever. Every member stays, the treasury/events/anthologies stay, but there is no path
-- back to a working owner: no one can approve events, manage the treasury, or found a
-- replacement (the one-guild-per-owner unique index means even a re-signed-up account can't
-- just make a new one for the same members). Functionally permanent, even though nothing was
-- literally deleted — and, same as the audit found, requested with zero warning to the other
-- members about to inherit an orphaned guild.
--
-- Fix: block requesting deletion while the account owns a Player Guild (is_founder_guild=false;
-- a Founder Guild has no owner_id per player_guilds' own check constraint, so it's never
-- affected either way), unless the request explicitly acknowledges it via the new
-- acknowledges_owned_guild_impact column. There's still no ownership-transfer feature to offer
-- as an alternative — this is the "require an explicit confirmation" branch from the fix
-- tracker, not the "block outright" or "offer a transfer" branches, since neither of those fits
-- what already exists.
-- ============================================================================================

alter table account_deletions add column if not exists acknowledges_owned_guild_impact boolean not null default false;

create or replace function check_account_deletion_guild_impact()
returns trigger
language plpgsql
as $$
begin
  if new.status = 'pending' and not new.acknowledges_owned_guild_impact
     and exists (
       select 1 from player_guilds g
       where g.owner_id = new.user_id and not g.is_founder_guild
     )
  then
    -- A distinct, greppable message (not a generic one) so the client can catch this specific
    -- case and show the guild-specific warning instead of a plain failure — see
    -- src/lib/account-deletion.js's requestAccountDeletion.
    raise exception 'ACCOUNT_DELETION_BLOCKED_OWNS_PLAYER_GUILD';
  end if;
  return new;
end;
$$;

drop trigger if exists check_account_deletion_guild_impact_trigger on account_deletions;
create trigger check_account_deletion_guild_impact_trigger
  before insert or update on account_deletions
  for each row execute function check_account_deletion_guild_impact();

-- ============================================================================================
-- Fireside announcement officer gate (Migration 80) — see
-- supabase/history/80_migration_fireside_announcement_officer_gate.sql for the full rationale.
-- ============================================================================================

-- ============================================================================================
-- Migration 80: fireside_posts didn't restrict who can set category = 'announcement' — any
-- guild member could tag their own post that way, even though src/guild/notice-board.jsx
-- already filters it out on the read/render side unless the author holds officer-or-above
-- authority (rung >= OFFICER_RUNG_THRESHOLD in that file). Not currently exploitable through the
-- app's own UI, but worth locking down here defensively in case that display-side filter is ever
-- loosened or bypassed by a direct API call.
--
-- Matches notice-board.jsx's own Founder Guild check exactly: "any Inkroot admin"
-- (profiles.is_platform_admin), not any per-member role — see that file's header comment for why
-- a Founder Guild's officer authority is delegated that way instead of to a role. This has to
-- live down here rather than editing the original policy up where fireside_posts is first
-- created, because profiles.is_platform_admin doesn't exist yet at that point in a fresh run of
-- this file (it's added later by Migration 43 above) — same reason the moderator-removal and
-- account-deletion sections above are also appended here instead of edited in place.
--
-- No Player Guild branch is added here: the membership check in this same policy only ever
-- admits founder_guild_members rows, and founder_guild_members.guild_id is check-constrained to
-- the ten fixed Founder Guild keys, so a Player Guild's (uuid) id can never satisfy it — confirmed
-- by src/shell/home-screen.jsx passing guildId: null into FiresideBoard for a Player Guild, i.e.
-- Player Guild Fireside posting isn't wired up at all today. If that ever changes, this check
-- needs revisiting together with the membership check, not in isolation.
-- ============================================================================================

drop policy if exists "guild members post to fireside" on fireside_posts;
create policy "guild members post to fireside" on fireside_posts
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from founder_guild_members m
      where m.guild_id = fireside_posts.guild_id and m.user_id = auth.uid()
    )
    and (
      category is distinct from 'announcement'
      or exists (select 1 from profiles p where p.id = auth.uid() and p.is_platform_admin)
    )
  );


-- ============================================================================================
-- Author Inbox notifications (Migration 83) — see
-- supabase/history/83_migration_notifications.sql for the full rationale.
-- ============================================================================================

-- Migration 83: a real backend for the Author Inbox (fix-tracker item 18).
--
-- src/library/inbox-and-living-universe.jsx's Inbox has always been entirely local — every
-- letter across all eight categories is either sample seed data (seedInboxItems()) or, for
-- Guild Events specifically, nothing at all. This migration is the scoped slice of that agreed
-- with the app owner: push-on-write notifications (same Realtime-table pattern
-- guild_order_world_entries/guild_order_proposals already use — see 81/82 above) for exactly
-- seven real events:
--   1. new_follower              — someone follows you                    (follows insert)
--   2. new_review                — someone reviews one of your books      (reviews insert)
--   3. guild_order_proposal_opened      — a Council proposal opens in your guild
--   4. guild_order_chapter_added        — a Manuscript chapter is proposed in your guild
--   5. guild_order_passage_added        — a passage is added to your guild's Manuscript
--   6. guild_order_world_entry_added    — a World Bible entry is added in your guild
--   7. guild_event_result_posted        — your guild event results were approved/settled
--
-- Everything else the Inbox shows (reader Messages, Sales, Marketplace, Achievements, System,
-- and the non-event-driven half of Guild Notifications like invitations/mentions) has no real
-- backend concept yet and is deliberately left alone — those are items 19/21/22 and the
-- Achievements/System notice board, not this one. This migration only ever INSERTs; it never
-- reads or modifies any table this fix-tracker has already closed.
--
-- Delivery is push-on-write, not pull-on-open: each source event's own trigger writes directly
-- into `notifications` in the same transaction as the row that caused it, and the table rides
-- the existing supabase_realtime publication so a signed-in device's Inbox can subscribe live
-- instead of only seeing new mail on its next open (see src/lib/notifications.js).
--
-- A Guild Order event is normally broadcast to every OTHER real member of the guild it happened
-- in (matching how Council/Manuscript/World Bible themselves already work) — reused as one
-- helper, notify_guild_order_members(), instead of repeating the founder/player membership
-- branch four times. guild_event_result_posted is different on purpose: it's not a guild-wide
-- broadcast, it's addressed to just the specific contributors named in that settlement's own
-- placements, which is who the payout actually concerns.

-- ============================================================================================
-- 1. notifications — one row per (recipient, event). actor_id is nullable because a settled
--    event's placements don't reduce to one single "who did this" person; payload carries
--    whatever type-specific ids/labels the client needs to render and link back to the source
--    (book id, guild type/id, proposal/chapter/entry id and title, place/share_bps, etc.) without
--    a second round-trip for the common case.
-- ============================================================================================

create table if not exists notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references auth.users(id) on delete cascade,
  type text not null check (type in (
    'new_follower', 'new_review',
    'guild_order_proposal_opened', 'guild_order_chapter_added',
    'guild_order_passage_added', 'guild_order_world_entry_added',
    'guild_event_result_posted'
  )),
  actor_id uuid references auth.users(id) on delete set null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table notifications enable row level security;

create policy "a writer reads their own notifications" on notifications
  for select using (auth.uid() = recipient_id);
-- Deliberately no insert/update/delete policy for authenticated — every row here is written
-- only by the trigger functions below (security definer), same reasoning as follow_events'/
-- book_publish_events' own "no insert policy, trigger-only" comment (migration 37, folded into
-- schema.sql above): a client can't backdate or spoof its own mail.

create index if not exists notifications_recipient_idx on notifications (recipient_id, created_at desc);

alter publication supabase_realtime add table notifications;

-- ============================================================================================
-- 2. New follower (follows insert) — mirrors log_follow_event()'s own self-follow guard.
-- ============================================================================================

create or replace function notify_new_follower()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.follower_id = new.followee_id then
    return new;
  end if;
  insert into notifications (recipient_id, type, actor_id, payload)
  values (new.followee_id, 'new_follower', new.follower_id, '{}'::jsonb);
  return new;
end;
$$;

drop trigger if exists follows_notify on follows;
create trigger follows_notify
  after insert on follows
  for each row execute function notify_new_follower();

-- ============================================================================================
-- 3. New review (reviews insert only — an edited rating via the existing update policy doesn't
--    re-notify, since it isn't a new review). Looks the book's author up server-side rather than
--    trusting a client-supplied recipient, same reasoning as every other trigger here.
-- ============================================================================================

create or replace function notify_new_review()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_author uuid;
begin
  select author_id into v_author from published_books where id = new.book_id;
  if v_author is null or v_author = new.reviewer_id then
    return new; -- book gone, or (defensively) a self-review somehow slipping past the app's own UI
  end if;
  insert into notifications (recipient_id, type, actor_id, payload)
  values (v_author, 'new_review', new.reviewer_id,
    jsonb_build_object('book_id', new.book_id, 'rating', new.rating, 'review_id', new.id));
  return new;
end;
$$;

drop trigger if exists reviews_notify on reviews;
create trigger reviews_notify
  after insert on reviews
  for each row execute function notify_new_review();

-- ============================================================================================
-- 4. Shared Guild Order broadcast helper — every real member of (guild_type, guild_id) except
--    the actor. Founder Guild membership is founder_guild_members(guild_id text, user_id); Player
--    Guild membership is player_guild_members(guild_id uuid, user_id) — and per
--    create_or_get_own_guild()'s own comment above, the owner is always folded into
--    player_guild_members as a member row too, so no separate owner_id branch is needed here the
--    way some SELECT policies defensively repeat one.
-- ============================================================================================

create or replace function notify_guild_order_members(p_guild_type text, p_guild_id text, p_actor_id uuid, p_type text, p_payload jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_guild_type = 'founder' then
    insert into notifications (recipient_id, type, actor_id, payload)
    select m.user_id, p_type, p_actor_id, p_payload
    from founder_guild_members m
    where m.guild_id = p_guild_id and m.user_id <> p_actor_id;
  elsif p_guild_type = 'player' then
    insert into notifications (recipient_id, type, actor_id, payload)
    select m.user_id, p_type, p_actor_id, p_payload
    from player_guild_members m
    where m.guild_id = p_guild_id::uuid and m.user_id <> p_actor_id;
  end if;
end;
$$;

-- ---- 4a. Council: a proposal opens (guild_order_proposals insert) ----

create or replace function notify_guild_order_proposal_opened()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform notify_guild_order_members(new.guild_type, new.guild_id, new.opened_by,
    'guild_order_proposal_opened',
    jsonb_build_object('guild_type', new.guild_type, 'guild_id', new.guild_id, 'proposal_id', new.id, 'title', new.title));
  return new;
end;
$$;

drop trigger if exists guild_order_proposals_notify on guild_order_proposals;
create trigger guild_order_proposals_notify
  after insert on guild_order_proposals
  for each row execute function notify_guild_order_proposal_opened();

-- ---- 4b. Manuscript: a chapter is proposed (guild_order_chapters insert) ----

create or replace function notify_guild_order_chapter_added()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform notify_guild_order_members(new.guild_type, new.guild_id, new.proposed_by,
    'guild_order_chapter_added',
    jsonb_build_object('guild_type', new.guild_type, 'guild_id', new.guild_id, 'chapter_id', new.id, 'title', new.title));
  return new;
end;
$$;

drop trigger if exists guild_order_chapters_notify on guild_order_chapters;
create trigger guild_order_chapters_notify
  after insert on guild_order_chapters
  for each row execute function notify_guild_order_chapter_added();

-- ---- 4c. Manuscript: a passage is added (guild_order_passages insert) — passages don't carry
--          guild_type/guild_id directly, so this looks its parent chapter up first, same join
--          subscribeGuildManuscriptRealtime's own client-side passage handling already needs. ----

create or replace function notify_guild_order_passage_added()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_chapter guild_order_chapters%rowtype;
begin
  select * into v_chapter from guild_order_chapters where id = new.chapter_id;
  if not found then
    return new;
  end if;
  perform notify_guild_order_members(v_chapter.guild_type, v_chapter.guild_id, new.author_id,
    'guild_order_passage_added',
    jsonb_build_object('guild_type', v_chapter.guild_type, 'guild_id', v_chapter.guild_id,
      'chapter_id', v_chapter.id, 'chapter_title', v_chapter.title, 'passage_id', new.id));
  return new;
end;
$$;

drop trigger if exists guild_order_passages_notify on guild_order_passages;
create trigger guild_order_passages_notify
  after insert on guild_order_passages
  for each row execute function notify_guild_order_passage_added();

-- ---- 4d. World Bible: an entry is added (guild_order_world_entries insert) ----

create or replace function notify_guild_order_world_entry_added()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform notify_guild_order_members(new.guild_type, new.guild_id, new.author_id,
    'guild_order_world_entry_added',
    jsonb_build_object('guild_type', new.guild_type, 'guild_id', new.guild_id, 'entry_id', new.id,
      'title', new.title, 'category', new.category));
  return new;
end;
$$;

drop trigger if exists guild_order_world_entries_notify on guild_order_world_entries;
create trigger guild_order_world_entries_notify
  after insert on guild_order_world_entries
  for each row execute function notify_guild_order_world_entry_added();

-- ============================================================================================
-- 5. Guild event results posted (guild_event_results update, status -> 'approved') — the moment
--    approve_guild_event_results() sets status='approved'/settled_at=now() above, i.e. the real
--    "results are final and paid" moment, not the organizer's earlier pending submission. Unlike
--    the four Guild Order events above this isn't a guild-wide broadcast: it's addressed to just
--    the contributors named in that settlement's own placements (the same contributor_id/place/
--    share_bps shape settle_guild_event() itself consumes), since a payout notice is personal,
--    not guild news. guild_event_results.guild_id is always a Player Guild (see that table's own
--    FK) so there's no founder/player branch to make here.
-- ============================================================================================

create or replace function notify_guild_event_result_posted()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'approved' and old.status is distinct from 'approved' then
    insert into notifications (recipient_id, type, actor_id, payload)
    select (p->>'contributor_id')::uuid, 'guild_event_result_posted', new.reviewed_by,
      jsonb_build_object('guild_id', new.guild_id, 'event_id', new.event_id,
        'place', (p->>'place')::int, 'share_bps', (p->>'share_bps')::int)
    from jsonb_array_elements(new.placements) p
    where (p->>'contributor_id')::uuid is not null;
  end if;
  return new;
end;
$$;

drop trigger if exists guild_event_results_notify on guild_event_results;
create trigger guild_event_results_notify
  after update on guild_event_results
  for each row execute function notify_guild_event_result_posted();

-- ================================================================================================
-- Living Universe public feed (Migration 84) — see
-- supabase/history/84_migration_living_universe_public_feed.sql for the full rationale.
-- ================================================================================================

-- Migration 84: list_living_universe_feed() — a real, platform-wide backend for the Living
-- Universe activity Feed (fix-tracker item 19).
--
-- Per the app owner's own call on this item: the Feed is a PUBLIC/cross-user view over the same
-- kind of real events item 18 (Author Inbox / notifications, migration 83) already made real —
-- not a second, separate "platform highlights" concept. It deliberately does NOT read from
-- `notifications` itself: that table is recipient-gated ("your book got reviewed"), which is the
-- wrong shape for a public feed ("a book got reviewed") even before RLS would block it outright.
--
-- Every source table this function reads already has an "anyone can read" policy of its own —
-- follow_events (migration 37), book_publish_events (migration 37), reviews (original schema),
-- guild_join_events (migration 39) — so this is purely a read-side convenience layer (one call,
-- names/titles already resolved) over data a client could already see, exactly the same
-- "returns strictly less than, or the same public shape as, what it reads" posture as
-- list_public_guild_events()/get_public_guild_profile() (migration 51). No existing table,
-- policy, or trigger is touched — this migration only adds a new function.
--
-- Guild Order activity (Council/Manuscript/World Bible) and guild event payouts are deliberately
-- EXCLUDED here even though they're part of item 18's real event set: those tables are
-- member-scoped by their own RLS ("members read their guild's..."), so surfacing them on a public,
-- platform-wide feed would mean showing one guild's internal activity to everyone, which is a
-- privacy regression this migration does not make. If a "real Guild Hall news" feed is ever
-- wanted, that is a new, guild-scoped question, not this one.
--
-- Four real sources, matching the local simulation's own vocabulary (luMakeEntry) where it lines
-- up, so LivingUniverseScreen's Chronicle keeps the shape it already renders:
--   'release' <- book_publish_events   (a book's true first-ever publish)
--   'follow'  <- follow_events         (a genuinely new follow)
--   'review'  <- reviews               (a reader reviewed a book)
--   'guild'   <- guild_join_events     (someone joined a Player Guild)
-- Author/reviewer/follower/joiner names are resolved server-side from `profiles` (display_name,
-- falling back to pen_name) so the client never needs a second round-trip per row, same
-- convenience fetchNotifications() already provides for the Inbox.
--
-- `id` is synthesized as a deterministic uuid (md5 of a per-source-table tag + the row's own
-- primary key) rather than added as a new physical column on any of the four source tables —
-- stable across repeated calls, so a client that de-dupes by id across refetches (same as
-- mergeRealNotifications does for the Inbox) works correctly.

create or replace function list_living_universe_feed(p_result_limit integer default null)
returns table (
  id uuid, kind text, created_at timestamptz, payload jsonb
)
language plpgsql stable security definer set search_path = public as $$
begin
  return query
  select u.id, u.kind, u.created_at, u.payload from (
    -- Releases: a book's true first-ever publish (book_publish_events already pins this
    -- permanently, independent of unpublish/republish — see that table's own header).
    select
      md5('release:' || e.book_id)::uuid as id,
      'release'::text as kind,
      e.first_published_at as created_at,
      jsonb_build_object(
        'book_id', e.book_id, 'title', b.title, 'genre', b.genre,
        'author_name', coalesce(p.display_name, p.pen_name, 'A writer')
      ) as payload
    from book_publish_events e
    join published_books b on b.id = e.book_id
    left join profiles p on p.id = e.author_id

    union all

    -- Follows: a genuinely new follow (follow_events is already an anti-cycling, insert-only
    -- ledger of first-time follows only — see its own header).
    select
      md5('follow:' || fe.id::text)::uuid,
      'follow'::text,
      fe.created_at,
      jsonb_build_object(
        'follower_name', coalesce(pf.display_name, pf.pen_name, 'A writer'),
        'followee_name', coalesce(pe.display_name, pe.pen_name, 'a writer')
      )
    from follow_events fe
    left join profiles pf on pf.id = fe.follower_id
    left join profiles pe on pe.id = fe.followee_id

    union all

    -- Reviews: a reader reviewed a book (reviews is already publicly readable in full).
    select
      md5('review:' || r.id::text)::uuid,
      'review'::text,
      r.created_at,
      jsonb_build_object(
        'book_id', r.book_id, 'title', b.title, 'rating', r.rating,
        'reviewer_name', coalesce(p.display_name, p.pen_name, 'A reader')
      )
    from reviews r
    join published_books b on b.id = r.book_id
    left join profiles p on p.id = r.reviewer_id

    union all

    -- Guild joins: someone joined a Player Guild (guild_join_events is already the same kind of
    -- anti-cycling, first-join-only ledger as follow_events).
    select
      md5('guildjoin:' || ge.id::text)::uuid,
      'guild'::text,
      ge.created_at,
      jsonb_build_object(
        'guild_id', ge.guild_id, 'guild_name', g.name,
        'user_name', coalesce(p.display_name, p.pen_name, 'A writer')
      )
    from guild_join_events ge
    join player_guilds g on g.id = ge.guild_id
    left join profiles p on p.id = ge.user_id
  ) u
  order by u.created_at desc
  limit coalesce(p_result_limit, 60);
end;
$$;

revoke all on function list_living_universe_feed(integer) from public;
grant execute on function list_living_universe_feed(integer) to authenticated;

-- Safe to run anytime: purely additive (one new function). No existing table, column, policy, or
-- trigger is modified.

-- Migration 85: a real discovery + purchase/download backend for Worldbuilding Packs
-- (fix-tracker item 20).
--
-- Two gaps closed here, found while scoping item 20 against current source rather than trusting
-- the tracker's own description of it:
--
-- 1. DISCOVERY (not mentioned in the tracker item, but a precondition for the rest of it to mean
--    anything): grand-library-screen.jsx's Worldbuilding Packs shelf has only ever been built
--    from `projects.flatMap(...)` — this device's own local `projects` state — never a real
--    cross-author fetch. Unlike published_books (which has fetchDiscoverBooks), there has never
--    been a server-side table for a pack at all. That means, as shipped, a reader can only ever
--    see packs THEY published themselves — another author's pack was never visible to anyone but
--    that author, on any device. `published_packs` below is the missing directory, mirroring
--    published_books' own shape and RLS almost exactly.
--
-- 2. PURCHASE + GATED CONTENT: WorldbuildingPackDetailModal (grand-library-cards.jsx) shows a
--    real pack summary (name/snippet only per entry — see packSummaryForIndex in
--    src/worldbuilding/book-cover.jsx) but ends in a ComingSoonNotice. Per the app owner's own
--    call on this item: content delivery mirrors published_book_content's shape (one jsonb blob,
--    written at publish time) but — unlike that table — is gated by purchase, not open-read. This
--    is a deliberate divergence from the book pattern, not an oversight: published_book_content
--    is intentionally public because reading a book is free by product design (Buy/tip there is
--    support, not a paywall — see that migration's own header). A pack has no such "free to
--    read" story; Buy IS the only gate a pack has, so mirroring published_book_content's
--    open-read policy verbatim would leave nothing left to sell.
--
-- A free pack (price = 0) still goes through the purchases flow rather than skipping it — also
-- the app owner's call, for the same audit-trail consistency purchases already gives every other
-- kind of transaction. Paystack itself won't process a zero-amount charge, so
-- paystack-init-pack-purchase (see that function) writes a `success`, `amount_kobo = 0` row
-- directly instead of ever calling Paystack for a free pack. That's the one existing constraint
-- this migration has to loosen: purchases.amount_kobo's `> 0` check is relaxed to `>= 0` below —
-- book and tip purchases are unaffected (both already refuse to create a purchases row at all
-- for a free book, or below the tip minimum, so neither has ever produced a 0-amount row and
-- neither starts now).

-- ============================================================================================
-- published_packs — the public directory a Worldbuilding Pack never had. `id` is the same
-- "<projectId>:<packKey>" composite string grand-library-screen.jsx already uses locally as
-- `selectedPackKey`, so no new id scheme has to be threaded through the client — a remote row's
-- id lines up with what the UI already computes. `categories` stores exactly the shape
-- packSummaryForIndex() already produces client-side (name/snippet per entry, not full content —
-- see published_pack_content below for that), so the browse card and detail modal keep rendering
-- unchanged whether a pack came from this device's own `projects` or from this table.
-- ============================================================================================

create table if not exists published_packs (
  id text primary key,
  author_id uuid not null references auth.users(id) on delete cascade,
  project_id text not null,
  pack_key text not null,
  title text not null check (char_length(title) <= 200),
  subtitle text check (subtitle is null or char_length(subtitle) <= 200),
  description text check (description is null or char_length(description) <= 2000),
  genre text,
  tags jsonb,
  cover_image_url text,
  -- Same "display-only until a real processor exists" reasoning published_books.price's own
  -- comment gives no longer applies here — Paystack is real (see paystack-init-pack-purchase) —
  -- but the >= 0 floor is the same defensive minimum published_books.price already enforces.
  price numeric default 0 check (price >= 0),
  categories jsonb not null default '[]'::jsonb,
  total_entries integer not null default 0,
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table published_packs enable row level security;

create policy "anyone can read published packs" on published_packs
  for select using (true);
create policy "author creates own pack listings" on published_packs
  for insert with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author updates own pack listings" on published_packs
  for update using (auth.uid() = author_id and not is_banned(auth.uid()))
  with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author deletes own pack listings" on published_packs
  for delete using (auth.uid() = author_id);

create index if not exists published_packs_author_idx on published_packs (author_id);

-- ============================================================================================
-- published_pack_content — the full, downloadable contents of a pack (every selected entry in
-- full, not the name/snippet teaser `categories` above carries). Shaped the same single-jsonb-
-- blob way as published_book_content (see 70_migration_published_book_content.sql) — nothing
-- server-side ever needs to query inside it — but with a purchase check folded into the SELECT
-- policy instead of that table's unconditional "anyone can read": see this migration's own
-- header for why that divergence is deliberate here.
-- ============================================================================================

create table if not exists published_pack_content (
  pack_id text primary key references published_packs(id) on delete cascade,
  content jsonb not null,
  updated_at timestamptz not null default now(),
  check (octet_length(content::text) <= 20971520)
);

alter table published_pack_content enable row level security;

-- A pack's own author can always read their own content (same as an author previewing their own
-- unpublished-elsewhere work); anyone else needs a successful purchases row for this exact pack —
-- the free-pack case is covered too, since paystack-init-pack-purchase writes that same
-- success/pack_id row even when no money moved.
create policy "author or buyer reads pack content" on published_pack_content
  for select using (
    exists (
      select 1 from published_packs pk
      where pk.id = pack_id and pk.author_id = auth.uid()
    )
    or exists (
      select 1 from purchases pu
      where pu.pack_id = published_pack_content.pack_id
        and pu.buyer_id = auth.uid()
        and pu.status = 'success'
    )
  );

create policy "author writes own pack content" on published_pack_content
  for insert with check (
    exists (
      select 1 from published_packs pk
      where pk.id = pack_id and pk.author_id = auth.uid()
    )
    and not is_banned(auth.uid())
  );

create policy "author updates own pack content" on published_pack_content
  for update using (
    exists (
      select 1 from published_packs pk
      where pk.id = pack_id and pk.author_id = auth.uid()
    )
    and not is_banned(auth.uid())
  )
  with check (
    exists (
      select 1 from published_packs pk
      where pk.id = pack_id and pk.author_id = auth.uid()
    )
    and not is_banned(auth.uid())
  );

-- No explicit delete policy: content is only ever removed via the `on delete cascade` from
-- published_packs, matching published_book_content's own reasoning.

create or replace function stamp_published_pack_content()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists published_pack_content_stamp on published_pack_content;
create trigger published_pack_content_stamp
  before insert or update on published_pack_content
  for each row execute function stamp_published_pack_content();

-- ============================================================================================
-- purchases — add 'pack' as a third kind, alongside 'book'/'tip', and a nullable pack_id
-- (mirrors book_id: set null on the pack's deletion rather than blocking it, same reasoning
-- purchases.book_id's own "on delete set null" already documents — a buyer's purchase history
-- shouldn't disappear just because the thing they bought was later taken down).
-- ============================================================================================

alter table purchases drop constraint if exists purchases_kind_check;
alter table purchases add constraint purchases_kind_check
  check (kind in ('book', 'tip', 'pack'));

alter table purchases add column if not exists pack_id text references published_packs(id) on delete set null;

create index if not exists purchases_pack_id_idx on purchases (pack_id) where pack_id is not null;

-- Loosened for the free-pack case described in this migration's header — a $0 purchases row is
-- now valid. Book and tip purchases never reach 0 (both already refuse to create a row at that
-- amount at the application layer), so this is additive, not a behavior change for either.
alter table purchases drop constraint if exists purchases_amount_kobo_check;
alter table purchases add constraint purchases_amount_kobo_check
  check (amount_kobo >= 0);

-- Migration 86: a real sharing backend for Addons (fix-tracker item 21).
--
-- Addons (src/writing/addon-data.jsx) have always been a flat, device-only list in
-- localStorage (readAddons/writeAddons) — not even synced across one writer's own devices via
-- the app's `storage` layer (see storage.js), let alone shared with anyone else. Authoring an
-- addon and installing it into your own projects already worked; there was no way to publish
-- one for another writer to find and add. `published_addons` below is that missing directory,
-- following packSummaryForIndex's Worldbuilding Pack pattern per the fix-tracker item's own
-- instruction, simplified where a Pack's own complexity doesn't apply here:
--
--   - No project scoping / composite id: a Worldbuilding Pack lives inside a specific project
--     (hence published_packs' "<projectId>:<packKey>" id and project_id/pack_key columns); an
--     addon is a standalone, device-global manifest with its own id already, so this table just
--     uses that id directly as its primary key, same reasoning published_books' own id column
--     comment already gives for reusing a local id instead of inventing a mapping layer.
--   - No separate gated-content table: a Pack needed published_pack_content split out from
--     published_packs because a pack's full entries are the thing being sold and had to stay
--     behind a purchase check (see migration 85's header). An addon's `contains` manifest IS its
--     public listing — there's no teaser/full-content split to make here.
--   - Free-to-install, no purchases integration, and no content_reports content_type — both by
--     the app owner's own call on this item, not an oversight. If either is wanted later, this
--     table is the same shape published_packs already used for both — no rework needed to add
--     them, just a follow-up migration.
--
-- `contains` (worldCategories + healthRules) is copied in full at publish time, same "declarative
-- manifest, not code" posture addon-data.jsx's own top comment already describes — nothing here
-- executes anything, it's read the same way installedAddonManifests() already reads a local
-- addon's `contains` today.

create table if not exists published_addons (
  id text primary key,
  author_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) <= 200),
  icon text,
  description text check (description is null or char_length(description) <= 2000),
  category text,
  version text,
  manifest_version integer not null default 1,
  contains jsonb not null default '{}'::jsonb,
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Same defensive cap reasoning as published_book_content/published_pack_content's own —
  -- bound against an unbounded/malicious payload, sized generously above what a real manifest
  -- (a handful of world-category and health-rule definitions) ever needs.
  check (octet_length(contains::text) <= 1048576)
);

alter table published_addons enable row level security;

create policy "anyone can read published addons" on published_addons
  for select using (true);
create policy "author creates own addon listings" on published_addons
  for insert with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author updates own addon listings" on published_addons
  for update using (auth.uid() = author_id and not is_banned(auth.uid()))
  with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author deletes own addon listings" on published_addons
  for delete using (auth.uid() = author_id);

create index if not exists published_addons_author_idx on published_addons (author_id);

create or replace function stamp_published_addons()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists published_addons_stamp on published_addons;
create trigger published_addons_stamp
  before insert or update on published_addons
  for each row execute function stamp_published_addons();

-- Migration 87: a real sharing backend for Templates (fix-tracker item 22).
--
-- Same gap, same fix shape as migration 86 (Addons, item 21): templates.jsx's readTemplates/
-- writeTemplates is a flat, device-only localStorage list with no discovery or sharing backend
-- at all. Applying a template to your own current project already worked; there was no way to
-- publish one for another writer to find and use. `published_templates` below follows
-- published_addons' own pattern almost exactly — same reasoning for the same simplifications
-- (no project scoping, no gated-content split, free-to-use, no purchases integration, no
-- content_reports content_type — all the app owner's own call on this item too, same as item
-- 21). One difference from published_addons: a template's shape varies by `type` (book/chapter/
-- character/worldbuilding — see TEMPLATE_TYPES), so its type-specific fields are kept in one
-- `payload` jsonb column rather than one column per possible field, the same "manifest, not
-- fixed columns" reasoning published_addons.contains already uses for its own varying shape.

create table if not exists published_templates (
  id text primary key,
  author_id uuid not null references auth.users(id) on delete cascade,
  type text not null check (type in ('book', 'chapter', 'character', 'worldbuilding')),
  name text not null check (char_length(name) <= 200),
  payload jsonb not null default '{}'::jsonb,
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Same defensive cap as published_addons.contains — a template's payload is a handful of
  -- short text fields, nowhere near this bound in ordinary use.
  check (octet_length(payload::text) <= 1048576)
);

alter table published_templates enable row level security;

create policy "anyone can read published templates" on published_templates
  for select using (true);
create policy "author creates own template listings" on published_templates
  for insert with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author updates own template listings" on published_templates
  for update using (auth.uid() = author_id and not is_banned(auth.uid()))
  with check (auth.uid() = author_id and not is_banned(auth.uid()));
create policy "author deletes own template listings" on published_templates
  for delete using (auth.uid() = author_id);

create index if not exists published_templates_author_idx on published_templates (author_id);

create or replace function stamp_published_templates()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists published_templates_stamp on published_templates;
create trigger published_templates_stamp
  before insert or update on published_templates
  for each row execute function stamp_published_templates();

-- Migration 88: real cross-member Guild Reputation for Founder Guilds (audit finding #1,
-- post-fix-tracker session).
--
-- guild_member_stats (see its own header above) made a Player Guild's Level/XP/Reputation a
-- real sum across its actual members instead of each device computing it from local activity
-- alone — but it explicitly left Founder Guilds uncovered, and at the time that was honest:
-- every OTHER "member" of a Founder Guild really was a simulated presence, so there was no real
-- roster to sum yet. That's no longer true. founder_guild_members has held every Founder
-- Guild's real join/leave history since Phase 8, and Guild Order's Roster/Manuscript/World
-- Bible/Council/Treasury/Anthology were all made real for Founder Guilds by later fix-tracker
-- items (15-17) — Guild Reputation is the one piece of "real once a real roster exists" that
-- never got extended to match.
--
-- This is a NEW table rather than widening guild_member_stats, for one hard reason:
-- guild_member_stats.guild_id is `uuid`, with a composite foreign key to
-- player_guild_members(guild_id, user_id) — but a Founder Guild's membership lives in
-- founder_guild_members, keyed by guild_id `text` (one of the ten fixed founder slugs —
-- 'fantasy', 'romance', etc.), a completely different id space. Retyping guild_member_stats's
-- existing column (and its FK, and every existing Player Guild row already in it) to
-- accommodate a second, incompatible id space would be a real, risky change to a table already
-- holding live data, for no benefit Player Guilds need. founder_guild_member_stats below is the
-- same shape, same check ceilings, same delta-guard trigger (reusing
-- guard_guild_member_stats_delta() as-is — it's already generic over column names, not tied to
-- one table) — just keyed against founder_guild_members instead.
--
-- Client-side, sumGuildMemberStats (guild-progression.jsx) already reduces raw rows into totals
-- generically by column name, so it works unchanged against rows from either table — no
-- duplicate reduction logic needed, just a second fetch/push pointed at this table for a
-- Founder Guild (see guild-progression-remote.js/home-screen.jsx).

create table if not exists founder_guild_member_stats (
  guild_id text not null check (guild_id in (
    'fantasy', 'romance', 'scifi', 'historical', 'horror',
    'mystery', 'comedy', 'worldbuilders', 'poetry', 'general'
  )),
  user_id uuid not null,
  published_count integer not null default 0 check (published_count between 0 and 10000),
  quests_completed integer not null default 0 check (quests_completed between 0 and 50),
  quest_guild_xp integer not null default 0 check (quest_guild_xp between 0 and 100000),
  writing_day_count integer not null default 0 check (writing_day_count between 0 and 20000),
  fireside_post_count integer not null default 0 check (fireside_post_count between 0 and 200000),
  updated_at timestamptz not null default now(),
  primary key (guild_id, user_id),
  -- Same reasoning as guild_member_stats' own FK: ties every stats row to an actual current
  -- membership row, so leaving a Founder Guild cascades into dropping this row too, instead of
  -- a stale ex-member's numbers still counting toward the guild's total forever.
  foreign key (guild_id, user_id) references founder_guild_members (guild_id, user_id) on delete cascade
);

alter table founder_guild_member_stats enable row level security;

create policy "guild members read founder guild member stats" on founder_guild_member_stats
  for select using (
    exists (
      select 1 from founder_guild_members m
      where m.guild_id = founder_guild_member_stats.guild_id and m.user_id = auth.uid()
    )
  );

create policy "a member inserts their own founder guild stats row" on founder_guild_member_stats
  for insert with check (
    auth.uid() = user_id
    and not is_banned(auth.uid())
    and exists (select 1 from founder_guild_members m where m.guild_id = founder_guild_member_stats.guild_id and m.user_id = auth.uid())
  );
create policy "a member updates their own founder guild stats row" on founder_guild_member_stats
  for update using (auth.uid() = user_id);

-- Reuses guild_member_stats' own delta-guard function unchanged — same column names, same
-- non-decreasing/per-write-delta reasoning applies identically here.
drop trigger if exists founder_guild_member_stats_guard_delta on founder_guild_member_stats;
create trigger founder_guild_member_stats_guard_delta
  before insert or update on founder_guild_member_stats
  for each row execute function guard_guild_member_stats_delta();

-- ============================================================================================
-- Paid book content access (Migration 89) — see
-- supabase/history/89_migration_paid_book_content_access.sql for the full rationale.
-- ============================================================================================

-- Migration 89: enforce purchase-gated manuscript access at the database level (release
-- blocker, pre-launch audit finding #1).
--
-- The bug: published_book_content's original "anyone can read published book content" policy
-- (created earlier in this file, where the table itself is defined) was readable by anyone with
-- the anon key, regardless of a book's price. lib/library.js's checkBookReadAccess and
-- ink-root.jsx's openReaderBook already gate the APP's own reading UI correctly (free books, a
-- book's own author, and a reader with a status:'success' purchases row all pass; everyone else
-- sees the "locked" screen) — but that's a React-side gate only. Nothing stopped a direct
-- `supabase.from('published_book_content').select('content').eq('book_id', ...)` call, or the
-- Grand Library's own "Peek at the opening" sample loader (BookDetailModal's loadSample in
-- grand-library-cards.jsx), from pulling a priced book's ENTIRE manuscript over the wire for
-- free — checkBookReadAccess was never consulted by either the raw table grant or that second
-- call site. This is folded in down here, not edited in place up where published_book_content is
-- first created, because the purchasers-read-paid-content policy below has to reference
-- `purchases`, which doesn't exist yet at that earlier point in a fresh run of this file (same
-- reason the moderator-removal, account-deletion, and fireside-announcement sections above are
-- also appended here instead of edited in place).
--
-- Free books (price <= 0) stay exactly as public as they've always been — reading a free book in
-- full was always the product's own design (see grand-library-cards.jsx's "reading in full stays
-- free either way" comment, still true and unchanged), never a bug. Only a priced book's actual
-- text changes behavior here: readable by its own author, or by a buyer with a real
-- status:'success' row in `purchases` for that exact book_id — status flips to 'success' only
-- from the paystack-webhook Edge Function after Paystack itself confirms the charge (see
-- PAYMENTS.md), never from anything a client can claim about its own payment. Everyone else gets
-- no row back for a priced book's content, same as any other RLS-denied read — no error, just an
-- empty result, which is exactly what checkBookReadAccess-driven UI already expects and handles.
--
-- One consequence of dropping the single open policy: BookDetailModal's sample preview used to
-- fall back to this same table for every reader who isn't the author, then truncate to 640
-- characters client-side — meaning the full text of a priced book was already sitting in that
-- reader's browser memory (and on the wire) before any truncation happened, an incidental second
-- copy of the exact hole above. A locked-down published_book_content can no longer serve that
-- fallback at all for a priced, unpurchased book. published_book_samples below is the fix: a
-- small, always-public, author-written mirror holding ONLY a short opening excerpt — never the
-- full manuscript — kept in sync automatically by a trigger on published_book_content so nothing
-- in src/lib/library.js's write path (publishBookContentRemote) has to change at all; only the
-- sample's read path does (see fetchPublishedBookSample, added alongside this migration).

-- published_book_samples — the public "read a sample" mirror. Deliberately tiny (2000-char cap,
-- vs. published_book_content's 20MB full-manuscript cap) and always openly readable regardless
-- of a book's price — previewing the opening of a priced book is marketing for the Buy button,
-- not the paywall itself, same product philosophy as the sample feature already had before this
-- migration, just made safe to expose unconditionally.
create table if not exists published_book_samples (
  book_id text primary key references published_books(id) on delete cascade,
  sample text not null default '' check (char_length(sample) <= 2000),
  updated_at timestamptz not null default now()
);

alter table published_book_samples enable row level security;

-- Narrowed further by Migration 90, just below the published_book_content policies near the end
-- of this file — a guild-only book's sample shouldn't be any more public than its full content
-- is. Kept here unmodified, same "original shape first" reasoning as published_books/
-- published_book_content's own pointer comments.
create policy "anyone can read published book samples" on published_book_samples
  for select using (true);
-- No client insert/update/delete policy at all, on purpose: the only writer is
-- sync_published_book_sample() below, a security definer trigger function that re-derives the
-- sample itself from published_book_content every time that table changes — never a value a
-- client hands over directly. Deletion rides published_books' own on delete cascade above.

-- Re-derives a short plain-text opening excerpt from a book's full content every time
-- published_book_content is written, and keeps published_book_samples in sync — so the sample a
-- reader sees can never drift from, or leak more than, whatever the author's latest publish
-- actually contains, and no client-supplied "sample" text is ever trusted directly. Walks
-- chapters in order and takes the first one with any real text after stripping markup,
-- mirroring (deliberately approximately, not character-for-character — this is a marketing
-- preview, not an export) the same "first non-empty chapter, HTML stripped" logic
-- grand-library-cards.jsx's own loadSample already used client-side; see
-- shared-utils/strip-html.jsx's stripHtml for the full client-side version this approximates.
-- Truncated to 640 characters, matching the length the client has always truncated a sample
-- display to.
create or replace function sync_published_book_sample()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_chapter jsonb;
  v_raw text;
  v_plain text := null;
begin
  if new.content ? 'chapters' and jsonb_typeof(new.content->'chapters') = 'array' then
    for v_chapter in select * from jsonb_array_elements(new.content->'chapters') loop
      v_raw := regexp_replace(coalesce(v_chapter->>'text', ''), '<[^>]+>', ' ', 'g');
      v_raw := regexp_replace(v_raw, '&nbsp;', ' ', 'gi');
      v_raw := btrim(regexp_replace(v_raw, '\s+', ' ', 'g'));
      if char_length(v_raw) > 0 then
        v_plain := v_raw;
        exit;
      end if;
    end loop;
  end if;
  insert into published_book_samples (book_id, sample, updated_at)
  values (new.book_id, coalesce(left(v_plain, 640), ''), now())
  on conflict (book_id) do update set sample = excluded.sample, updated_at = now();
  return new;
end;
$$;

drop trigger if exists published_book_content_sync_sample on published_book_content;
create trigger published_book_content_sync_sample
  after insert or update on published_book_content
  for each row execute function sync_published_book_sample();

-- Backfill: every book published before this migration has a published_book_content row but no
-- published_book_samples row yet (the trigger above only fires on a future insert/update, i.e.
-- the next time each book is re-published). Re-runs the exact same extraction as the trigger, so
-- readers of an already-published book get a working sample immediately rather than an empty one
-- until its author happens to hit Publish again. Harmless/idempotent on a fresh install (the
-- loop simply has nothing to iterate over yet).
do $$
declare
  r record;
  v_chapter jsonb;
  v_raw text;
  v_plain text;
begin
  for r in select book_id, content from published_book_content loop
    v_plain := null;
    if r.content ? 'chapters' and jsonb_typeof(r.content->'chapters') = 'array' then
      for v_chapter in select * from jsonb_array_elements(r.content->'chapters') loop
        v_raw := regexp_replace(coalesce(v_chapter->>'text', ''), '<[^>]+>', ' ', 'g');
        v_raw := regexp_replace(v_raw, '&nbsp;', ' ', 'gi');
        v_raw := btrim(regexp_replace(v_raw, '\s+', ' ', 'g'));
        if char_length(v_raw) > 0 then
          v_plain := v_raw;
          exit;
        end if;
      end loop;
    end if;
    insert into published_book_samples (book_id, sample, updated_at)
    values (r.book_id, coalesce(left(v_plain, 640), ''), now())
    on conflict (book_id) do update set sample = excluded.sample, updated_at = now();
  end loop;
end $$;

-- The actual fix: replace the single open "anyone can read" policy with three narrower
-- permissive policies (Postgres OR's every applicable permissive select policy together, same
-- pattern purchases' own "buyer reads own" / "author reads sales" pair already uses two policies
-- for) — a request passes if ANY of the three match, so an author reading their own priced book,
-- anyone reading a free book, and a verified buyer reading what they paid for all still work with
-- a single unmodified `supabase.from('published_book_content').select(...).eq('book_id', id)`
-- call; nobody else gets a row back for a priced book.
drop policy if exists "anyone can read published book content" on published_book_content;

create policy "author reads own book content" on published_book_content
  for select using (
    exists (select 1 from published_books b where b.id = book_id and b.author_id = auth.uid())
  );

create policy "free book content is public" on published_book_content
  for select using (
    exists (select 1 from published_books b where b.id = book_id and b.price <= 0)
  );

create policy "purchasers read paid book content" on published_book_content
  for select using (
    exists (
      select 1 from purchases p
      where p.book_id = published_book_content.book_id
        and p.kind = 'book'
        and p.buyer_id = auth.uid()
        and p.status = 'success'
    )
  );

-- ============================================================================================
-- Guild book privacy (Migration 90) — see
-- supabase/history/90_migration_guild_book_privacy.sql for the full rationale.
-- ============================================================================================

-- Migration 90: Guild privacy — a book published specifically to a Guild must only be
-- readable/discoverable by actual Guild members, never through published_books or
-- published_book_content's own open policies (release blocker #2).
--
-- The bug: publishBookWithDetails (ink-root.jsx) writes EVERY publish — regardless of
-- destination — into published_books (publishBookRemote) and published_book_content
-- (publishBookContentRemote). Both tables' own select policies were "for select using (true)":
-- fully public, by design, for the Grand Library's Discover feed (destination = 'inkroot'). A
-- book published with destination = 'guild' got the exact same open policies, so its listing
-- (title/blurb/cover/price/...) and its ENTIRE manuscript were both world-readable to anyone
-- with the anon key, purchase or membership aside. The app's own UI never surfaces a guild book
-- outside the Guild Bookshelf (fetchDiscoverBooks/fetchPublishedBooksByAuthor both filter to
-- destination = 'inkroot' client-side — see lib/library.js), but that's a UI filter, not a
-- permission boundary: a direct `supabase.from('published_books').select(...)` (no
-- `.eq('destination', ...)` needed) or `.from('published_book_content').select('content')` call
-- returned every guild-only book's full listing and text regardless of who asked.
--
-- guild_published_books (the Guild Bookshelf's own real shelf — see its own header comment
-- earlier in this file) already gates a Founder Guild book's *listing copy* correctly, by real
-- founder_guild_members membership. This migration makes published_books/published_book_content/
-- published_book_samples agree with that same boundary for the SAME book id, instead of leaving
-- a second, fully-open copy of the same content sitting a table over.
--
-- Player Guilds were originally unaffected either way: guild_published_books' own header
-- documented Player/Joined Guild bookshelves as local-only, no shared-shelf feature built for
-- them yet — a destination:'guild' book from a Player Guild writer never got a
-- guild_published_books row at all, so after this migration it was readable by its own author
-- only. That was strictly more correct than the fully-public hole it had before, not a feature
-- regression: nothing in the app ever legitimately showed that book to anyone but its author
-- regardless.
--
-- Update (92_migration_player_guild_book_publishing.sql): a Player Guild's Bookshelf is now real
-- too — the write side (ink-root.jsx pushing a guild_published_books row) and this read side
-- both now recognize player_guild_members membership alongside founder_guild_members, via
-- sibling permissive policies folded in near the end of this file. Left this paragraph unedited
-- above rather than quietly rewritten, so this file's own history stays honest about what was
-- and wasn't true at each point — see the fix tracker's own standing lesson about "Confirmed"
-- claims for why.
--
-- checkBookReadAccess/fetchPublishedBookContent/openReaderBook (lib/library.js, ink-root.jsx)
-- are unchanged and don't need to be. checkBookReadAccess reads price/author_id from
-- published_books, which for a non-member now comes back as no row (RLS-denied) instead of a
-- real price — a harmless quirk, since its `(book && book.price) || 0` falls through to
-- `{allowed: true, price: 0}` — because the actual manuscript fetch right after it
-- (fetchPublishedBookContent, gated by the same membership check below) still returns no row
-- either, and openReaderBook already shows "book unavailable" for exactly that case, same as any
-- other network/lookup failure. A legitimate guild member's or the book's own author's read of
-- both tables passes normally under the new policies below.
-- ============================================================================================

-- ---------- published_books ----------
-- Replaces the single open "anyone can read published books" policy with four narrower
-- permissive ones (same OR-together pattern Migration 89 used for published_book_content) — a
-- request passes if ANY one matches, so the Grand Library's own public Discover query
-- (`.eq('destination', 'inkroot')`, no auth needed), an author's own Author Studio listing (any
-- destination), a Founder Guild member's Guild Bookshelf lookup, and the moderation queue's
-- 'published_book' report-preview lookup (fetchReportedContentPreview in lib/moderation.js) all
-- keep working unmodified; nobody else gets a row back for a guild-only book.
drop policy if exists "anyone can read published books" on published_books;

create policy "anyone can read grand library books" on published_books
  for select using (destination = 'inkroot' and not removed_by_moderator);

create policy "author reads own book listing" on published_books
  for select using (auth.uid() = author_id);

create policy "guild members read their guild's book listings" on published_books
  for select using (
    destination = 'guild'
    and not removed_by_moderator
    and exists (
      select 1
      from guild_published_books g
      join founder_guild_members m on m.guild_id = g.guild_id and m.user_id = auth.uid()
      where g.book_id = published_books.id
    )
  );

-- Bugfix, pre-launch audit: the four policies above replace what used to be one policy —
-- "anyone can read published books" — that carried `not removed_by_moderator or auth.uid() =
-- author_id` (see the moderator-content-removal section earlier in this file). That condition
-- didn't make it into any of the four replacements when this migration was first written, so a
-- moderator-removed book quietly became publicly/guild-readable again the moment this migration
-- ran — the takedown stayed recorded in the column but stopped doing anything. Restored above (on
-- the two non-author policies here — "anyone can read grand library books" and this one) and on
-- the Player Guild sibling below; the author's own policy intentionally stays unconditional, same
-- as every other table's "author sees their own removed content" carve-out (reviews,
-- fireside_posts, guild_book_feedback, book_discussion_posts all follow the same pattern), and
-- the moderator policy is unconditional on purpose — moderators need to see removed content too.
-- published_book_content/published_book_samples need no matching edit: their own policies join
-- back to this table, and a subquery is subject to the querying user's RLS on the table it reads,
-- so a row this table now hides from a non-author/non-moderator is invisible to those subqueries
-- too, automatically.

-- Same moderator bypass guild_published_books already carries, so the moderation queue's
-- 'published_book' report preview keeps resolving a book's title/blurb regardless of
-- destination. NOT recreated here on purpose (bugfix, pre-launch audit): a policy of this exact
-- name and definition already exists on this table — see the moderator-content-removal section
-- above ("Restricting the existing fully-open read policy means moderators..."). Re-declaring it
-- here with no `drop policy if exists` first duplicated the name, which Postgres rejects
-- ("policy already exists") — on a fresh install this aborted schema.sql at this exact
-- statement, silently skipping every migration after it (this guild-privacy block included, plus
-- anthology content and Player Guild publishing). Left as a comment, not a repeated statement,
-- so nothing here shadows or depends on drop-then-recreate ordering.

-- ---------- published_book_content ----------
-- "free book content is public" (Migration 89) needs the same destination = 'inkroot' scoping —
-- as written it would otherwise still hand out a guild-only book's ENTIRE manuscript to anyone,
-- for free, the moment its price is 0 (the common case: guild books aren't usually priced).
drop policy if exists "free book content is public" on published_book_content;

create policy "free grand library book content is public" on published_book_content
  for select using (
    exists (
      select 1 from published_books b
      where b.id = published_book_content.book_id and b.destination = 'inkroot' and b.price <= 0
    )
  );

-- The missing piece: an actual Founder Guild member reading a book published to THEIR OWN
-- guild's shelf. "author reads own book content" and "purchasers read paid book content" (both
-- Migration 89) are left exactly as they were — both are destination-agnostic on purpose, since
-- authorship or a real purchase proves the right thing regardless of where a book was published.
create policy "guild members read their guild's book content" on published_book_content
  for select using (
    exists (
      select 1
      from published_books b
      join guild_published_books g on g.book_id = b.id
      join founder_guild_members m on m.guild_id = g.guild_id and m.user_id = auth.uid()
      where b.id = published_book_content.book_id and b.destination = 'guild'
    )
  );

-- ---------- published_book_samples ----------
-- The "Peek at the opening" mirror (Migration 89) is derived straight from
-- published_book_content by a trigger, and was just as fully public ("anyone can read published
-- book samples", using (true)) as published_book_content itself used to be — the same leak, just
-- capped at 640 characters instead of the full manuscript. Nothing in the app's own UI ever
-- calls fetchPublishedBookSample for a guild-only book (BookDetailModal only ever opens from the
-- Grand Library's Discover feed or an Author's Hall, both filtered to destination = 'inkroot' —
-- see lib/library.js), but that's the same UI-filter-not-a-permission-boundary gap
-- published_books/published_book_content had, so it gets the same fix here, mirroring the
-- policies above.
drop policy if exists "anyone can read published book samples" on published_book_samples;

create policy "anyone can read grand library book samples" on published_book_samples
  for select using (
    exists (
      select 1 from published_books b
      where b.id = published_book_samples.book_id and b.destination = 'inkroot'
    )
  );

create policy "author reads own book sample" on published_book_samples
  for select using (
    exists (
      select 1 from published_books b
      where b.id = published_book_samples.book_id and b.author_id = auth.uid()
    )
  );

create policy "guild members read their guild's book sample" on published_book_samples
  for select using (
    exists (
      select 1
      from published_books b
      join guild_published_books g on g.book_id = b.id
      join founder_guild_members m on m.guild_id = g.guild_id and m.user_id = auth.uid()
      where b.id = published_book_samples.book_id and b.destination = 'guild'
    )
  );

-- ============================================================================================
-- Migration 92: Player Guild books — completes the ordinary-book-to-Guild publishing path for
-- self-founded/joined Player Guilds (release blocker #1). Folded in here, after
-- player_guild_members exists, rather than back up alongside guild_book_feedback/published_books/
-- published_book_content/published_book_samples' own definitions above, since a policy's
-- predicate is validated against real tables at creation time and player_guild_members is
-- defined later in this file than all four of those tables. See
-- 92_migration_player_guild_book_publishing.sql for the full write-up of the bug this closes;
-- guild_published_books' own sibling policies are folded in place instead (it's defined after
-- player_guild_members, so no ordering problem there).
-- ============================================================================================

-- ---------- guild_book_feedback (deferred from its own definition above) ----------
create policy "player guild members read guild feedback" on guild_book_feedback
  for select using (
    exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );

create policy "player guild members post guild feedback" on guild_book_feedback
  for insert with check (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );

create policy "player guild members update own feedback" on guild_book_feedback
  for update using (
    auth.uid() = author_id
    and not is_banned(auth.uid())
    and exists (
      select 1 from player_guild_members m
      where m.guild_id::text = guild_book_feedback.guild_id and m.user_id = auth.uid()
    )
  );

-- ---------- published_books / published_book_content / published_book_samples ----------
-- Mirrors migration 90's own Founder Guild read policies immediately above each table's block,
-- checking player_guild_members instead. Additional permissive SELECT policies (ORed with every
-- existing one, migration 90's Founder Guild policies included) — nothing existing is dropped.

create policy "player guild members read their guild's book listings" on published_books
  for select using (
    destination = 'guild'
    and not removed_by_moderator
    and exists (
      select 1
      from guild_published_books g
      join player_guild_members m on m.guild_id::text = g.guild_id and m.user_id = auth.uid()
      where g.book_id = published_books.id
    )
  );

create policy "player guild members read their guild's book content" on published_book_content
  for select using (
    exists (
      select 1
      from published_books b
      join guild_published_books g on g.book_id = b.id
      join player_guild_members m on m.guild_id::text = g.guild_id and m.user_id = auth.uid()
      where b.id = published_book_content.book_id and b.destination = 'guild'
    )
  );

create policy "player guild members read their guild's book sample" on published_book_samples
  for select using (
    exists (
      select 1
      from published_books b
      join guild_published_books g on g.book_id = b.id
      join player_guild_members m on m.guild_id::text = g.guild_id and m.user_id = auth.uid()
      where b.id = published_book_samples.book_id and b.destination = 'guild'
    )
  );

-- ============================================================================================
-- Migration 93: Guild Anthology publish now actually reaches the guild it was written for
-- (fix-tracker item 30, found in a final full-system audit). publish_guild_anthology() assembled
-- every approved contributor's real content into published_books/published_book_content
-- correctly, but never inserted the matching guild_published_books row those tables' own
-- Migration 90/92 read policies require to resolve who's allowed to see a 'guild' destination
-- book — so a published anthology was readable by nobody but the officer who published it. See
-- 93_migration_anthology_guild_shelf.sql for the full write-up.
-- ============================================================================================

-- Migration 93: Guild Anthology publish now actually reaches the guild it was written for
-- (fix-tracker item 30, found in a final full-system audit).
--
-- The bug: publish_guild_anthology() (migration 35, extended by 36/37/48/69/73/74/91) correctly
-- assembles every approved contributor's real content and inserts atomically into published_books
-- + published_book_content with destination:'guild' — but never inserted the matching row into
-- guild_published_books. Every guild-scoped read policy on published_books/published_book_content
-- (migrations 90 and 92) resolves who's allowed to see a 'guild' destination book by joining
-- through guild_published_books; with no row there, only the book's own author_id (the officer who
-- ran Publish) and moderators could ever see it under RLS. Concretely: it never appeared on the
-- Guild Bookshelf (fetchGuildPublishedBooks in lib/library-guild.js only ever queries
-- guild_published_books), and every other guild member — including every contributor who wrote
-- part of it — hit "book unavailable" trying to open it. A published anthology delivered a
-- readable book to exactly one person: whoever clicked Publish.
--
-- Shipped as a fresh `create or replace`, not an edit to migration 91's own file, because this bug
-- doesn't error — unlike the migration-90 duplicate-policy bug (fix-tracker item 28), a deployment
-- could already have successfully applied migration 91 exactly as originally written. Editing that
-- file after the fact would do nothing for a database that already ran it; this migration is the
-- one that actually reaches it, going forward, regardless of whether migration 91 was applied
-- before or after this fix existed.
--
-- The fix adds exactly one insert, in the same function, same transaction, right after the
-- published_book_content insert it was always meant to sit beside — the listing, the manuscript,
-- and now the guild shelf row either all land together or none do, same atomicity guarantee the
-- rest of this function already had. guild_anthologies.guild_id has a hard foreign key to
-- player_guilds(id) (migration 35), so an anthology's guild is always a Player Guild, never a
-- Founder Guild slug — hence the ::text cast below, matching guild_published_books' own "player
-- guild members ..." policies (migration 92) rather than the Founder Guild ones.
--
-- Full function body restated (not a partial diff) since `create or replace function` always
-- needs the complete definition — this is byte-identical to migration 91's version with exactly
-- one new insert added, nothing else changed.
create or replace function publish_guild_anthology(p_anthology_id uuid)
returns published_books
language plpgsql security definer set search_path = public as $$
declare
  v_anth guild_anthologies%rowtype;
  v_word_count integer;
  v_book_id text;
  v_book published_books%rowtype;
  v_agreement guild_anthology_revenue_agreements%rowtype;
  v_pending_count integer;
  v_mismatch_count integer;
  v_missing_content_count integer;
  v_guild_name text;
  v_chapters jsonb := '[]'::jsonb;
  v_sub record;
  v_author_name text;
  v_chap jsonb;
begin
  select * into v_anth from guild_anthologies where id = p_anthology_id for update;
  if not found then
    raise exception 'Anthology not found.';
  end if;

  if not is_guild_officer(v_anth.guild_id) then
    raise exception 'Only the guild owner can publish this anthology.';
  end if;
  if v_anth.status <> 'reviewing' then
    raise exception 'Close submissions and finish reviewing before publishing.';
  end if;
  if v_anth.published_book_id is not null then
    raise exception 'This anthology has already been published.';
  end if;

  select coalesce(sum(word_count), 0) into v_word_count
  from guild_anthology_submissions where anthology_id = p_anthology_id and review_status = 'approved';
  if v_word_count < min_anthology_publish_word_count() then
    raise exception 'This anthology''s approved submissions total % words — at least % are needed before publishing.', v_word_count, min_anthology_publish_word_count();
  end if;

  select count(*) into v_missing_content_count
  from guild_anthology_submissions
  where anthology_id = p_anthology_id and review_status = 'approved' and content is null;
  if v_missing_content_count > 0 then
    raise exception '% approved contributor(s) haven''t attached their manuscript yet — ask them to open "Submit your work" again (or Edit their entry) before publishing.', v_missing_content_count;
  end if;

  select * into v_agreement from guild_anthology_revenue_agreements where anthology_id = p_anthology_id for update;
  if not found then
    raise exception 'Propose a revenue agreement and get every contributor''s approval before publishing.';
  end if;

  select count(*) into v_mismatch_count from (
    select contributor_id from (
      select contributor_id from guild_anthology_revenue_shares where agreement_id = v_agreement.id
      union all
      select contributor_id from guild_anthology_submissions
        where anthology_id = p_anthology_id and review_status = 'approved'
    ) all_ids
    group by contributor_id
    having count(*) <> 2
  ) mismatches;
  if v_mismatch_count > 0 then
    raise exception 'The revenue agreement''s contributors no longer match this anthology''s approved submissions — propose it again before publishing.';
  end if;

  select count(*) into v_pending_count
  from guild_anthology_revenue_shares where agreement_id = v_agreement.id and approved_at is null;
  if v_pending_count > 0 then
    raise exception '% contributor(s) still need to approve the revenue agreement before this can be published.', v_pending_count;
  end if;

  select g.name into v_guild_name from player_guilds g where g.id = v_anth.guild_id;

  for v_sub in
    select s.id, s.contributor_id, s.title, s.blurb, s.content
    from guild_anthology_submissions s
    where s.anthology_id = p_anthology_id and s.review_status = 'approved'
    order by s.submitted_at asc
  loop
    select coalesce(p.pen_name, p.display_name) into v_author_name from profiles p where p.id = v_sub.contributor_id;
    if v_author_name is null then
      v_author_name := 'Writer ' || substr(v_sub.contributor_id::text, 1, 8);
    end if;

    v_chapters := v_chapters || jsonb_build_array(jsonb_build_object(
      'id', 'section-' || v_sub.id::text,
      'title', v_sub.title,
      'text', '<p><em>By ' || v_author_name || '</em></p>'
        || case when v_sub.blurb is not null and v_sub.blurb <> '' then '<p>' || v_sub.blurb || '</p>' else '' end
    ));

    for v_chap in select * from jsonb_array_elements(coalesce(v_sub.content -> 'chapters', '[]'::jsonb))
    loop
      v_chapters := v_chapters || jsonb_build_array(jsonb_build_object(
        'id', v_sub.id::text || '-' || coalesce(v_chap ->> 'id', gen_random_uuid()::text),
        'title', coalesce(v_chap ->> 'title', ''),
        'text', coalesce(v_chap ->> 'text', '')
      ));
    end loop;
  end loop;

  v_book_id := 'anthology-' || p_anthology_id::text;

  insert into published_books (id, author_id, title, blurb, cover, price, word_count, destination)
  values (v_book_id, auth.uid(), v_anth.title, v_anth.description, v_anth.cover, v_anth.price, v_word_count, 'guild')
  returning * into v_book;

  insert into published_book_content (book_id, content)
  values (v_book_id, jsonb_build_object(
    'title', v_anth.title,
    'subtitle', null,
    'seriesName', null,
    'author', coalesce(v_guild_name, 'The Guild') || ' — a Guild Anthology',
    'cover', v_anth.cover,
    'storyFormat', 'book',
    'chapters', v_chapters
  ))
  on conflict (book_id) do update set content = excluded.content;

  -- The actual fix (see this migration's header): without this insert, the anthology's
  -- listing+content rows above were the only place it existed — readable by its own author_id
  -- and moderators only, invisible to the Guild Bookshelf and to every other guild member,
  -- including its own contributors.
  insert into guild_published_books (guild_id, book_id, author_id, title, cover, blurb, word_count, story_format, published_at)
  values (v_anth.guild_id::text, v_book_id, auth.uid(), v_anth.title, v_anth.cover, v_anth.description, v_word_count, 'book', now())
  on conflict (guild_id, book_id) do update set
    title = excluded.title, cover = excluded.cover, blurb = excluded.blurb,
    word_count = excluded.word_count, updated_at = now();

  perform set_config('inkroot.trusted_anthology_rpc', 'true', true);
  update guild_anthologies
    set status = 'published', published_book_id = v_book_id, published_at = now()
    where id = p_anthology_id;

  update guild_anthology_revenue_agreements
    set locked = true, locked_at = now()
    where id = v_agreement.id;

  return v_book;
end;
$$;

-- Backfill: heal any anthology that was already published before this migration existed — it
-- would have a published_books/published_book_content pair but no guild_published_books row.
-- Safe to run any number of times (plain insert-if-missing, no destructive update), and a no-op
-- on a database where nothing has been published through the old buggy function yet.
insert into guild_published_books (guild_id, book_id, author_id, title, cover, blurb, word_count, story_format, published_at)
select a.guild_id::text, b.id, b.author_id, b.title, b.cover, b.blurb, b.word_count, 'book', b.published_at
from guild_anthologies a
join published_books b on b.id = a.published_book_id
where a.published_book_id is not null
on conflict (guild_id, book_id) do nothing;

-- ============================================================================================
-- Migration 94 (see supabase/history/94_migration_official_badge_and_checkins.sql)
-- ============================================================================================

-- ============================================================================================
-- Migration 94 — The Inkroot Official Badge (gates Naira achievement payouts) and the daily
-- check-in calendar
-- ============================================================================================
--
-- Two independent features, shipped together because the first depends on nothing new and the
-- second is small; they don't share any table.
--
-- PART 1 — Inkroot Official Badge
--
-- Not the same thing as profiles.verified (that's a moderator-curated identity checkmark, set
-- manually after confirming who someone is out-of-band — see its comment on the profiles table).
-- This badge is the opposite kind of signal: fully automated, criteria-based, and recomputed live
-- on every check rather than stored — the account-age criterion is time-based, so a cached column
-- would need a cron job to ever flip false->true on its own; computing it on read avoids that
-- entirely, same choice naira_achievement_progress() already made for achievement progress.
--
-- Requirements (all four, every time it's checked):
--   1. Has purchased a book, OR published one (Grand Library or a guild) — proof of real
--      participation in the economy, not just a signed-up account.
--   2. Is a member of a guild — either kind (Founder or Player).
--   3. Has at least one successful, paid guild-event entry. guild_event_entries.amount_kobo is
--      `not null check (amount_kobo > 0)` on every row (see that table's definition) — there is no
--      such thing as a free entry in that table, so a plain existence check is already sufficient;
--      no need to join guild_events to filter by price.
--   4. Account is at least 7 days old, read from auth.users.created_at (profiles has no created_at
--      of its own — only updated_at — and auth.users is the real source of truth for account age
--      regardless; admin_set_login_ban() and the on_auth_user_created trigger already establish
--      the precedent of touching auth.users from a security definer function here).
--
-- The badge itself is inert — it's just a boolean function. The actual anti-farming enforcement
-- is wiring it into grant_naira_achievement() below: achievement PROGRESS still shows real
-- current_count to everyone (so a new writer can see they're 8,000 words from an achievement),
-- but the payout — the insert into achievement_grants that actually moves Naira — refuses until
-- all four criteria are met. naira_achievement_progress()'s existing `exception when others then
-- null` around its call to grant_naira_achievement already tolerates this new exception with zero
-- changes needed there.

create or replace function inkroot_official_badge_earned(p_user uuid)
returns boolean
language sql stable security definer set search_path = public as $$
  select
    (
      exists (select 1 from purchases where buyer_id = p_user and status = 'success')
      or exists (select 1 from published_books where author_id = p_user)
      or exists (select 1 from guild_published_books where author_id = p_user)
    )
    and (
      exists (select 1 from founder_guild_members where user_id = p_user)
      or exists (select 1 from player_guild_members where user_id = p_user)
    )
    and exists (select 1 from guild_event_entries where entrant_id = p_user and status = 'success')
    and exists (select 1 from auth.users where id = p_user and created_at <= now() - interval '7 days');
$$;

revoke all on function inkroot_official_badge_earned(uuid) from public;
grant execute on function inkroot_official_badge_earned(uuid) to authenticated;

-- Per-criterion breakdown for the UI, same table-returning convention as
-- naira_achievement_progress — lets the badge card say "3 of 4 met" with which one is missing,
-- rather than a flat yes/no the writer can't act on.
create or replace function inkroot_official_badge_status()
returns table (has_book boolean, in_guild boolean, paid_event boolean, week_old boolean, earned boolean)
language sql stable security definer set search_path = public as $$
  select
    exists (select 1 from purchases where buyer_id = auth.uid() and status = 'success')
      or exists (select 1 from published_books where author_id = auth.uid())
      or exists (select 1 from guild_published_books where author_id = auth.uid()),
    exists (select 1 from founder_guild_members where user_id = auth.uid())
      or exists (select 1 from player_guild_members where user_id = auth.uid()),
    exists (select 1 from guild_event_entries where entrant_id = auth.uid() and status = 'success'),
    exists (select 1 from auth.users where id = auth.uid() and created_at <= now() - interval '7 days'),
    inkroot_official_badge_earned(auth.uid());
$$;

revoke all on function inkroot_official_badge_status() from public;
grant execute on function inkroot_official_badge_status() to authenticated;

-- The actual gate. Everything below the idempotency check (already-granted short-circuit) and
-- above the existing `case` is new; the rest of the function is unchanged from migration 53/54's
-- version, reproduced here in full since this is a CREATE OR REPLACE and Postgres needs the whole
-- body, not a diff.
create or replace function grant_naira_achievement(p_achievement_id text)
returns achievement_grants
language plpgsql security definer set search_path = public as $$
declare
  v_row achievement_grants;
  v_target bigint;
  v_reward_kobo bigint;
  v_current bigint;
begin
  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row; -- already granted — idempotent, not an error
  end if;

  if not inkroot_official_badge_earned(auth.uid()) then
    raise exception 'The Inkroot Official Badge is required before Naira achievements can be granted.';
  end if;

  case p_achievement_id
    when 'nairaFirstPurchase'    then v_target := 1;      v_reward_kobo := 10000;
    when 'nairaBookCollector'    then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaGrandCollector'   then v_target := 100;     v_reward_kobo := 1000000;
    when 'nairaRookieMerchant'   then v_target := 10;      v_reward_kobo := 100000;
    when 'nairaHustler'          then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaSeniorMan'        then v_target := 100;     v_reward_kobo := 1500000;
    when 'nairaFirstPublication' then v_target := 1;       v_reward_kobo := 100000;
    when 'nairaFirstBook'        then v_target := 1;       v_reward_kobo := 50000;
    when 'nairaDedicatedWriter'  then v_target := 50000;   v_reward_kobo := 50000;
    when 'nairaMasterWriter'     then v_target := 100000;  v_reward_kobo := 100000;
    when 'nairaReader'           then v_target := 5;       v_reward_kobo := 50000;
    when 'nairaLoyal'            then v_target := 7;       v_reward_kobo := 100000;
    else
      raise exception 'This achievement has no server-verifiable signal yet.';
  end case;

  perform pg_advisory_xact_lock(hashtext('naira_achievement:' || auth.uid()::text || ':' || p_achievement_id));

  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row;
  end if;

  v_current := naira_achievement_current(p_achievement_id);
  if v_current is null or v_current < v_target then
    raise exception 'Achievement not yet earned.';
  end if;

  insert into achievement_grants (user_id, achievement_id, naira_reward_kobo)
  values (auth.uid(), p_achievement_id, v_reward_kobo)
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function grant_naira_achievement(text) from public;
grant execute on function grant_naira_achievement(text) to authenticated;


-- ============================================================================================
-- PART 2 — Daily check-in calendar
-- ============================================================================================
--
-- One row per user per calendar day. The date always comes from the server clock (current_date,
-- inside the security definer RPC below) — there is deliberately no client insert policy on this
-- table, so a writer can't backdate a check-in by posting an arbitrary checkin_date directly.
-- Distinct from the existing per-project "writing streak" in tab-progress.jsx, which is a
-- client-derived word-count signal, not a real server-verified daily action — the two aren't
-- meant to be merged.

create table if not exists daily_checkins (
  user_id uuid not null references auth.users(id) on delete cascade,
  checkin_date date not null,
  created_at timestamptz not null default now(),
  primary key (user_id, checkin_date)
);

alter table daily_checkins enable row level security;

drop policy if exists "a user reads their own check-ins" on daily_checkins;
create policy "a user reads their own check-ins" on daily_checkins
  for select using (auth.uid() = user_id);

-- Idempotent — check-in for today twice is a no-op, not an error, same "already done" tolerance
-- as grant_naira_achievement's own idempotency check above. Returns the resulting streak so the
-- client doesn't need a second round trip after checking in.
create or replace function check_in_today()
returns table (checked_in_today boolean, current_streak integer)
language plpgsql security definer set search_path = public as $$
begin
  insert into daily_checkins (user_id, checkin_date)
  values (auth.uid(), current_date)
  on conflict (user_id, checkin_date) do nothing;

  return query
  with days as (
    -- Gaps-and-islands: for consecutive calendar dates, (date - row_number()) lands on the same
    -- value, so the island containing today's row is exactly the current streak.
    select checkin_date,
           checkin_date - (row_number() over (order by checkin_date))::integer as grp
    from daily_checkins
    where user_id = auth.uid() and checkin_date <= current_date
  )
  select true, (select count(*)::integer from days where grp = (select grp from days where checkin_date = current_date));
end;
$$;

revoke all on function check_in_today() from public;
grant execute on function check_in_today() to authenticated;

-- Read-only fetch for a given month, so the client can render a calendar grid without a raw
-- table read (keeps the same "app talks to functions/narrow policies, not ad hoc queries"
-- shape as the rest of this schema, and leaves room to add derived fields later without a
-- client-side query change).
create or replace function fetch_checkins_for_month(p_year integer, p_month integer)
returns table (checkin_date date)
language sql stable security definer set search_path = public as $$
  select checkin_date from daily_checkins
  where user_id = auth.uid()
    and checkin_date >= make_date(p_year, p_month, 1)
    and checkin_date < (make_date(p_year, p_month, 1) + interval '1 month')::date
  order by checkin_date;
$$;

revoke all on function fetch_checkins_for_month(integer, integer) from public;
grant execute on function fetch_checkins_for_month(integer, integer) to authenticated;

-- ============================================================================================
-- Migration 95 (see supabase/history/95_migration_fix_badge_probe.sql)
-- ============================================================================================

-- ============================================================================================
-- Migration 95 — fix: inkroot_official_badge_earned let any signed-in user probe any OTHER
-- user's badge eligibility (whether they'd ever made a successful purchase or attended a paid
-- guild event), bypassing purchases' own "read your own rows only" policy in aggregate-boolean
-- form. Flagged in the production audit after migration 94 shipped.
--
-- The fix removes the parameter entirely rather than adding a guard clause — every real call
-- site (inkroot_official_badge_status, grant_naira_achievement) already only ever checked
-- auth.uid(), so there was never a legitimate reason for this to take an arbitrary target user.
-- Dropping the parameter removes the vulnerable surface outright instead of trusting every future
-- caller to remember to pass auth.uid() correctly.
--
-- Postgres treats a changed argument list as a distinct function, not a replacement, so the old
-- inkroot_official_badge_earned(uuid) has to be dropped explicitly or it would keep existing
-- (and keep being callable) side by side with the new one.
drop function if exists inkroot_official_badge_earned(uuid);

create or replace function inkroot_official_badge_earned()
returns boolean
language sql stable security definer set search_path = public as $$
  select
    (
      exists (select 1 from purchases where buyer_id = auth.uid() and status = 'success')
      or exists (select 1 from published_books where author_id = auth.uid())
      or exists (select 1 from guild_published_books where author_id = auth.uid())
    )
    and (
      exists (select 1 from founder_guild_members where user_id = auth.uid())
      or exists (select 1 from player_guild_members where user_id = auth.uid())
    )
    and exists (select 1 from guild_event_entries where entrant_id = auth.uid() and status = 'success')
    and exists (select 1 from auth.users where id = auth.uid() and created_at <= now() - interval '7 days');
$$;

revoke all on function inkroot_official_badge_earned() from public;
grant execute on function inkroot_official_badge_earned() to authenticated;

-- inkroot_official_badge_status() was already self-referential (ignored any notion of a target
-- user and only ever reported on auth.uid()), so this replacement changes nothing about its
-- behavior or its callers — only the one internal call site, updated for the new signature.
create or replace function inkroot_official_badge_status()
returns table (has_book boolean, in_guild boolean, paid_event boolean, week_old boolean, earned boolean)
language sql stable security definer set search_path = public as $$
  select
    exists (select 1 from purchases where buyer_id = auth.uid() and status = 'success')
      or exists (select 1 from published_books where author_id = auth.uid())
      or exists (select 1 from guild_published_books where author_id = auth.uid()),
    exists (select 1 from founder_guild_members where user_id = auth.uid())
      or exists (select 1 from player_guild_members where user_id = auth.uid()),
    exists (select 1 from guild_event_entries where entrant_id = auth.uid() and status = 'success'),
    exists (select 1 from auth.users where id = auth.uid() and created_at <= now() - interval '7 days'),
    inkroot_official_badge_earned();
$$;

revoke all on function inkroot_official_badge_status() from public;
grant execute on function inkroot_official_badge_status() to authenticated;

-- grant_naira_achievement already only ever called this with auth.uid() — updated for the new
-- signature, nothing else in this function's body changes from migration 94's version.
create or replace function grant_naira_achievement(p_achievement_id text)
returns achievement_grants
language plpgsql security definer set search_path = public as $$
declare
  v_row achievement_grants;
  v_target bigint;
  v_reward_kobo bigint;
  v_current bigint;
begin
  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row; -- already granted — idempotent, not an error
  end if;

  if not inkroot_official_badge_earned() then
    raise exception 'The Inkroot Official Badge is required before Naira achievements can be granted.';
  end if;

  case p_achievement_id
    when 'nairaFirstPurchase'    then v_target := 1;      v_reward_kobo := 10000;
    when 'nairaBookCollector'    then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaGrandCollector'   then v_target := 100;     v_reward_kobo := 1000000;
    when 'nairaRookieMerchant'   then v_target := 10;      v_reward_kobo := 100000;
    when 'nairaHustler'          then v_target := 50;      v_reward_kobo := 500000;
    when 'nairaSeniorMan'        then v_target := 100;     v_reward_kobo := 1500000;
    when 'nairaFirstPublication' then v_target := 1;       v_reward_kobo := 100000;
    when 'nairaFirstBook'        then v_target := 1;       v_reward_kobo := 50000;
    when 'nairaDedicatedWriter'  then v_target := 50000;   v_reward_kobo := 50000;
    when 'nairaMasterWriter'     then v_target := 100000;  v_reward_kobo := 100000;
    when 'nairaReader'           then v_target := 5;       v_reward_kobo := 50000;
    when 'nairaLoyal'            then v_target := 7;       v_reward_kobo := 100000;
    else
      raise exception 'This achievement has no server-verifiable signal yet.';
  end case;

  perform pg_advisory_xact_lock(hashtext('naira_achievement:' || auth.uid()::text || ':' || p_achievement_id));

  select * into v_row from achievement_grants
  where user_id = auth.uid() and achievement_id = p_achievement_id;
  if found then
    return v_row;
  end if;

  v_current := naira_achievement_current(p_achievement_id);
  if v_current is null or v_current < v_target then
    raise exception 'Achievement not yet earned.';
  end if;

  insert into achievement_grants (user_id, achievement_id, naira_reward_kobo)
  values (auth.uid(), p_achievement_id, v_reward_kobo)
  returning * into v_row;
  return v_row;
end;
$$;

revoke all on function grant_naira_achievement(text) from public;
grant execute on function grant_naira_achievement(text) to authenticated;
