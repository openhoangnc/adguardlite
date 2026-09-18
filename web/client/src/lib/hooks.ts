import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError } from '../api';

export interface Async<T> {
    data: T | undefined;
    error: string | undefined;
    loading: boolean;
    /** Runs the loader again; awaited by callers that save and then refresh. */
    reload: () => Promise<void>;
    /** Replaces the held value without a round trip, for optimistic updates. */
    set: (value: T) => void;
}

/**
 * Loads something once and hands back its state.
 *
 * `deps` is the loader's dependency list, as `useEffect` takes one.  A reload
 * that lands after the component is gone is dropped rather than warned about.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[] = []): Async<T> {
    const [data, setData] = useState<T>();
    const [error, setError] = useState<string>();
    const [loading, setLoading] = useState(true);
    const alive = useRef(true);
    const fn = useRef(load);
    fn.current = load;

    useEffect(() => {
        alive.current = true;

        return () => {
            alive.current = false;
        };
    }, []);

    const run = useCallback(async () => {
        setLoading(true);
        try {
            const v = await fn.current();
            if (alive.current) {
                setData(v);
                setError(undefined);
            }
        } catch (e) {
            if (alive.current) {
                setError(message(e));
            }
        } finally {
            if (alive.current) {
                setLoading(false);
            }
        }
    }, []);

    useEffect(() => {
        void run();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, deps);

    return { data, error, loading, reload: run, set: setData };
}

/** The text to show for whatever a failed call threw. */
export function message(e: unknown): string {
    if (e instanceof ApiError) {
        return e.status === 0 ? `Cannot reach the server: ${e.message}` : e.message;
    }

    return e instanceof Error ? e.message : String(e);
}

/** Re-runs `fn` every `ms` while the tab is visible. */
export function useInterval(fn: () => void, ms: number | null): void {
    const saved = useRef(fn);
    saved.current = fn;

    useEffect(() => {
        if (ms === null) {
            return;
        }

        const id = window.setInterval(() => {
            if (document.visibilityState === 'visible') {
                saved.current();
            }
        }, ms);

        return () => window.clearInterval(id);
    }, [ms]);
}
