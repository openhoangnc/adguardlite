import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import App from '../app/App';
import '../styles/app.css';

/**
 * Carries a bookmark from the old interface over.
 *
 * It routed on `#settings`; react-router's hash history writes `#/settings`.
 * One rewrite before the router reads the location keeps every old link
 * working, and costs nothing afterwards because the form it produces is the
 * one it leaves alone.
 */
const hash = window.location.hash;
if (/^#[a-z_]+$/.test(hash)) {
    window.location.hash = `#/${hash.slice(1)}`;
}

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
