import React from 'react';
import { InkRoot } from './ink-root.jsx';
import { NavigationProvider } from './nav-context.jsx';


// The original file's own mount call (`ReactDOM.createRoot(...).render(...)`) has been removed
// — main.jsx owns mounting now. This wrapper is what main.jsx renders in place of the
// placeholder, once you swap it in (see the TODO comment there).
//
// SyncStatusIndicator used to mount here, one level above NavigationProvider/InkRoot, so it
// stayed mounted and floating over every screen in the app. It's rendered by HomeScreen itself
// now (see home-screen.jsx), Home-only, so it no longer needs a seat at this top level.
export default function InkrootApp() {
    return React.createElement(NavigationProvider, { rootLabel: 'Home' }, React.createElement(InkRoot, null));
}
