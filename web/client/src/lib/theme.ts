import type { Theme } from '../api';

const KEY = 'sift-theme';

/**
 * Applies a theme to the document.
 *
 * `auto` follows the system, and keeps following it: the listener is replaced
 * rather than added to, so switching away from `auto` stops it.
 */
let unlisten: (() => void) | undefined;

export function applyTheme(theme: Theme): void {
    unlisten?.();
    unlisten = undefined;

    if (theme !== 'auto') {
        document.documentElement.dataset.theme = theme;
        remember(theme);

        return;
    }

    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const set = () => {
        document.documentElement.dataset.theme = media.matches ? 'dark' : 'light';
    };

    set();
    media.addEventListener('change', set);
    unlisten = () => media.removeEventListener('change', set);
    remember(theme);
}

/**
 * Keeps the last theme so a reload does not flash the wrong one.
 *
 * The profile is the authority, but it arrives a request later than the first
 * paint.
 */
function remember(theme: Theme): void {
    try {
        localStorage.setItem(KEY, theme);
    } catch {
        // Private browsing, or storage turned off.  The theme still applies.
    }
}

export function rememberedTheme(): Theme {
    try {
        const v = localStorage.getItem(KEY);
        if (v === 'light' || v === 'dark' || v === 'auto') {
            return v;
        }
    } catch {
        // As above.
    }

    return 'auto';
}
