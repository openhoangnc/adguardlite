/** Rendering values the API reports in the shapes Go gave them. */

/** Milliseconds in a day, which is the unit two config endpoints use. */
export const DAY_MS = 24 * 60 * 60 * 1000;

/** Formats a query log timestamp as a local wall-clock time. */
export function formatTime(iso: string, withDate = false): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
        return iso;
    }

    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return withDate ? `${d.toLocaleDateString()} ${time}` : time;
}

/** Formats a date, leaving Go's zero time -- which means "never" -- blank. */
export function formatDate(iso: string | undefined): string {
    if (!iso || iso.startsWith('0001-01-01')) {
        return '';
    }

    const d = new Date(iso);

    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** A count with the locale's thousands separators. */
export function num(n: number): string {
    return n.toLocaleString();
}

/** A share of a total, as a percentage with one decimal. */
export function percent(part: number, total: number): string {
    if (!total) {
        return '0%';
    }

    return `${((part / total) * 100).toFixed(2)}%`;
}

/** Seconds, as the milliseconds the dashboard labels them with. */
export function millis(seconds: number): string {
    return `${(seconds * 1000).toFixed(2)} ms`;
}

/** A duration in milliseconds, spelled the way the protection timer reads. */
export function countdown(ms: number): string {
    const total = Math.max(0, Math.round(ms / 1000));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    const pad = (n: number) => String(n).padStart(2, '0');

    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/** Splits a textarea into the list of lines an API field expects. */
export function lines(value: string): string[] {
    return value
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l !== '');
}

/** The inverse: a list of lines as one textarea value. */
export function unlines(value: string[] | null | undefined): string {
    return (value ?? []).join('\n');
}

/** Milliseconds from midnight, as `HH:MM`. */
export function clock(ms: number): string {
    const total = Math.floor(ms / 60000);

    return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
}

/** `HH:MM` back to milliseconds from midnight. */
export function unclock(value: string): number {
    const [h, m] = value.split(':').map(Number);

    return ((h ?? 0) * 60 + (m ?? 0)) * 60000;
}

/**
 * An upstream's address, short enough for a half-width table.
 *
 * `https://dns10.quad9.net:443/dns-query` becomes
 * `dns10.quad9.net/dns-query`: the scheme and the protocol's own default port
 * say nothing a reader of this table does not already know, and the full
 * address stays in the cell's tooltip.
 */
export function shortUpstream(url: string): string {
    const defaults: Record<string, string> = { 'https:': '443', 'tls:': '853', 'quic:': '853', 'http:': '80' };

    try {
        const u = new URL(url);
        const port = u.port && u.port !== defaults[u.protocol] ? `:${u.port}` : '';

        return `${u.hostname}${port}${u.pathname === '/' ? '' : u.pathname}`;
    } catch {
        // A plain `1.1.1.1:53` is not a URL, and is already short.
        return url;
    }
}

/**
 * The flag for an ISO 3166-1 country code.
 *
 * Built from the code rather than looked up: the two regional-indicator
 * symbols that spell it out *are* the flag, so `vn` becomes the Vietnamese
 * one with no icon set to ship.  Windows draws the two letters instead of a
 * flag, which still reads correctly beside the country's name.
 */
export function flag(code: string): string {
    if (!/^[a-z]{2}$/.test(code)) {
        return '';
    }

    return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

/** The single `{name: count}` pair the API wraps every top-list entry in. */
export function pair(entry: Record<string, number>): [string, number] {
    const [k, v] = Object.entries(entry)[0] ?? ['', 0];

    return [k, v];
}
