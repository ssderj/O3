import React from 'react';
import { useSync } from './sync-context.jsx';

// ---------- Persistent sign-in status dot ----------
// Answers exactly one question: "am I online (signed in and syncing) right now?" That's
// different from the account CONTROL surface (AccountSyncControl, Home-only, lets you actually
// sign in/out/delete) — this is read-only status. Home-only on purpose (see below) — it used to
// mount once above NavigationProvider and float over every screen in the app, which meant it hung
// over project workspaces, the reader, the moderation queue, everywhere, rather than reading as
// part of the Home dashboard it's actually answering for. Rendered directly by HomeScreen now, so
// it only ever appears there.
//
// A plain color dot rather than a text pill: green while online and syncing, red the moment
// there's nothing to sync to (signed out — this device only). No label text sits next to it; the
// title tooltip carries the same detail for anyone who taps or hovers to ask.
//
// Deliberately not interactive (no onClick / navigation) — wiring this into Home's tab state
// would mean threading a callback down through InkrootApp/InkRoot just for this, and the title
// tooltip already tells anyone who's confused where to go. Revisit if that turns out not to be
// enough.
export function SyncStatusIndicator() {
    const sync = useSync();
    if (!sync || !sync.ready) return null;
    const { session } = sync;
    const online = !!session;
    return React.createElement(
        'div',
        {
            title: online
                ? `Online \u2014 syncing${session.user.email ? ` (${session.user.email})` : ''}. Manage this from Home.`
                : "Offline \u2014 this device only. Sign in from Home to back up and sync across devices.",
            style: {
                position: 'fixed', top: 10, right: 10, zIndex: 40,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: 22, height: 22, borderRadius: '50%',
                background: 'rgba(23,19,14,0.88)', border: '1px solid #3A3020',
                pointerEvents: 'auto', userSelect: 'none', backdropFilter: 'blur(2px)',
            },
        },
        React.createElement('span', {
            style: {
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: online ? '#5FBF6B' : '#D9534F',
                boxShadow: online ? '0 0 5px rgba(95,191,107,0.75)' : '0 0 5px rgba(217,83,79,0.75)',
            },
        })
    );
}
