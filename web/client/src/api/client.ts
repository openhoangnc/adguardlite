/** The transport every call in `./index.ts` goes through. */

/** A refusal from the control API, carrying whatever it said. */
export class ApiError extends Error {
    readonly status: number;

    constructor(status: number, message: string) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
    }
}

const BASE = '/control';

/**
 * Whether a 401 sends the browser to the login form.
 *
 * The login page itself turns this off: there, a 401 is the answer to a wrong
 * password and must be shown, not acted on.
 */
let redirectOnUnauthorized = true;

export function keepUnauthorizedHere(): void {
    redirectOnUnauthorized = false;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
    let res: Response;
    try {
        res = await fetch(BASE + path, {
            credentials: 'same-origin',
            ...init,
            headers: { ...(init?.body ? { 'Content-Type': 'application/json' } : {}), ...init?.headers },
        });
    } catch (e) {
        throw new ApiError(0, e instanceof Error ? e.message : String(e));
    }

    if (res.status === 401 || res.status === 403) {
        if (redirectOnUnauthorized) {
            window.location.replace('login.html');
            // Never settles: the page is on its way out, and resolving here
            // would flash an error the user cannot act on.
            return new Promise<T>(() => {});
        }
    }

    if (!res.ok) {
        const text = (await res.text().catch(() => '')).trim();
        throw new ApiError(res.status, text || `${res.status} ${res.statusText}`);
    }

    if (res.status === 204) {
        return undefined as T;
    }

    const body = await res.text();
    if (body === '') {
        return undefined as T;
    }

    const type = res.headers.get('Content-Type') ?? '';
    if (!type.includes('json')) {
        return body as T;
    }

    try {
        return JSON.parse(body) as T;
    } catch {
        return body as T;
    }
}

export function get<T>(path: string, query?: Record<string, string | number | undefined>): Promise<T> {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) {
        if (v !== undefined && v !== '') {
            q.set(k, String(v));
        }
    }
    const s = q.toString();

    return request<T>(s ? `${path}?${s}` : path);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
    return request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
}

export function put<T>(path: string, body?: unknown): Promise<T> {
    return request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) });
}
