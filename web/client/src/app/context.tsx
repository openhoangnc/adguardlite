/**
 * What every page needs to know: who is signed in, what the server is, and
 * whether protection is on.
 *
 * Held here rather than fetched per page because the header shows all three
 * and a page switch should not re-ask for them.  There is no store beyond
 * this: the rest of the state belongs to whichever page loaded it.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import * as api from '../api';
import type { Profile, ServerStatus, Theme, VersionInfo } from '../api';
import { useAsync, useInterval } from '../lib/hooks';
import { applyTheme } from '../lib/theme';

interface Server {
    status: ServerStatus;
    profile: Profile;
    version: VersionInfo | undefined;
    /** Asks the server about releases again, and reports what it said. */
    checkVersion: (recheck?: boolean) => Promise<VersionInfo>;
    /** Re-reads the status, which is what a protection change moves. */
    refresh: () => Promise<void>;
    setProtection: (enabled: boolean, durationMs?: number) => Promise<void>;
    setTheme: (t: Theme) => Promise<void>;
}

const Ctx = createContext<Server | null>(null);

export function useServer(): Server {
    const v = useContext(Ctx);
    if (!v) {
        throw new Error('useServer outside the provider');
    }

    return v;
}

export function ServerProvider({
    status,
    profile,
    reload,
    children,
}: {
    status: ServerStatus;
    profile: Profile;
    reload: () => Promise<void>;
    children: ReactNode;
}) {
    const [version, setVersion] = useState<VersionInfo>();

    // Never blocks a page. A request that fails outright is recorded as a
    // failed check rather than left undefined, because the header has to be
    // able to tell "up to date" from "nobody has answered" -- the two used to
    // render the same way, which is to say not at all.
    const checkVersion = useCallback(async (recheck = false) => {
        const info = await api.getVersion(recheck).catch(() => ({ check_failed: true }) as VersionInfo);
        setVersion(info);

        return info;
    }, []);

    useEffect(() => {
        void checkVersion();
    }, [checkVersion]);

    // Protection can lapse on its own -- it is often turned off for a set
    // time -- so the header asks again while the tab is in front.
    useInterval(() => void reload(), status.protection_enabled ? 60_000 : 10_000);

    const setProtection = useCallback(
        async (enabled: boolean, durationMs?: number) => {
            await api.setProtection(enabled, durationMs);
            await reload();
        },
        [reload],
    );

    const setTheme = useCallback(
        async (t: Theme) => {
            applyTheme(t);
            await api.updateProfile({ theme: t });
            await reload();
        },
        [reload],
    );

    const value = useMemo<Server>(
        () => ({ status, profile, version, refresh: reload, checkVersion, setProtection, setTheme }),
        [status, profile, version, reload, checkVersion, setProtection, setTheme],
    );

    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Loads the two documents the shell cannot render without. */
export function useBootstrap() {
    return useAsync(async () => {
        const [status, profile] = await Promise.all([api.getStatus(), api.getProfile()]);

        return { status, profile };
    });
}
