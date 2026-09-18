import { useEffect, useState } from 'react';

import * as api from '../api';
import type { Theme } from '../api';
import { Menu, Switch, useToast } from '../components/ui';
import { IconChevron, IconMenu, IconMoon, IconRefresh, IconSun, IconUser } from '../components/icons';
import { countdown } from '../lib/format';
import { message } from '../lib/hooks';
import { useServer } from './context';

/**
 * How long protection may be turned off for.
 *
 * `ms` is a function rather than a number because one of these is not a fixed
 * length: "until tomorrow" is however long it is until local midnight, which
 * depends on when it is asked.
 */
const DURATIONS: { label: string; ms: () => number }[] = [
    { label: 'For 30 seconds', ms: () => 30_000 },
    { label: 'For 1 minute', ms: () => 60_000 },
    { label: 'For 10 minutes', ms: () => 10 * 60_000 },
    { label: 'For 1 hour', ms: () => 60 * 60_000 },
    { label: 'Until tomorrow', ms: untilTomorrow },
];

/** Milliseconds from now until the next local midnight. */
function untilTomorrow(): number {
    const midnight = new Date();
    midnight.setHours(24, 0, 0, 0);

    return midnight.getTime() - Date.now();
}

const THEMES: { value: Theme; label: string }[] = [
    { value: 'auto', label: 'Match the system' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
];

export default function Topbar({ onBurger }: { onBurger: () => void }) {
    const { status, profile, version, setProtection, setTheme } = useServer();
    const toast = useToast();
    const [left, setLeft] = useState(status.protection_disabled_duration);

    // The server reports how long protection stays off; the countdown here is
    // only the display of it, and is re-seeded every time the status reloads.
    useEffect(() => {
        setLeft(status.protection_disabled_duration);
        if (status.protection_enabled || status.protection_disabled_duration <= 0) {
            return;
        }

        const id = window.setInterval(() => setLeft((v) => Math.max(0, v - 1000)), 1000);

        return () => window.clearInterval(id);
    }, [status.protection_disabled_duration, status.protection_enabled]);

    const change = async (enabled: boolean, ms?: number) => {
        try {
            await setProtection(enabled, ms);
            toast.ok(enabled ? 'Protection is on' : 'Protection is off');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const clearCache = async () => {
        if (!window.confirm('Empty the DNS cache? Every name will be looked up again.')) {
            return;
        }

        try {
            await api.clearCache();
            toast.ok('DNS cache cleared');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const newVersion =
        version && !version.disabled && version.new_version && version.new_version !== status.version
            ? version.new_version
            : undefined;

    return (
        <header className="topbar">
            <button type="button" className="btn ghost icon burger" onClick={onBurger} aria-label="Menu">
                <IconMenu />
            </button>

            <Switch
                checked={status.protection_enabled}
                onChange={(v) => void change(v)}
                label={status.protection_enabled ? 'Turn protection off' : 'Turn protection on'}
            />
            <span className="wide-only" style={{ fontWeight: 550 }}>
                Protection
            </span>
            {!status.protection_enabled && (
                <span
                    className="badge amber"
                    title={left > 0 ? `Protection comes back on in ${countdown(left)}` : 'Protection is off until you turn it back on'}>
                    {left > 0 ? `off for ${countdown(left)}` : 'off'}
                </span>
            )}
            {status.protection_enabled && (
                <Menu label="Turn protection off for a while" button={<IconChevron size={14} />}>
                    {/* The durations alone read as "for an hour" of nothing in
                        particular, so the menu says what it is an hour of. */}
                    <div className="menu-title">Turn protection off</div>
                    {DURATIONS.map((d) => (
                        <button
                            key={d.label}
                            type="button"
                            className="menu-item"
                            onClick={() => void change(false, d.ms())}>
                            {d.label}
                        </button>
                    ))}
                    <div className="menu-sep" />
                    <button type="button" className="menu-item" onClick={() => void change(false)}>
                        Until I turn it back on
                    </button>
                </Menu>
            )}

            <div className="spacer" />

            <button type="button" className="btn sm" onClick={() => void clearCache()} title="Empty the DNS cache">
                <IconRefresh size={15} />
                <span className="wide-only">Clear cache</span>
            </button>

            {newVersion && (
                <a
                    className="badge green"
                    href={version?.announcement_url ?? 'https://github.com/openhoangnc/sift/releases'}
                    target="_blank"
                    rel="noreferrer">
                    {newVersion} is available
                </a>
            )}

            <Menu label="Theme" button={profile.theme === 'dark' ? <IconMoon /> : <IconSun />}>
                {THEMES.map((th) => (
                    <button
                        key={th.value}
                        type="button"
                        className={`menu-item ${profile.theme === th.value ? 'active' : ''}`}
                        onClick={() => void setTheme(th.value).catch((e) => toast.fail(message(e)))}>
                        {th.label}
                    </button>
                ))}
            </Menu>

            <Menu label={profile.name} button={<IconUser />}>
                <div className="menu-item" style={{ color: 'var(--text-muted)' }}>
                    {profile.name}
                </div>
                <div className="menu-item" style={{ color: 'var(--text-faint)', fontSize: 12 }}>
                    Sift {status.version}
                </div>
                <div className="menu-sep" />
                <button
                    type="button"
                    className="menu-item"
                    onClick={() => {
                        void api.logout().finally(() => window.location.replace('login.html'));
                    }}>
                    Sign out
                </button>
            </Menu>
        </header>
    );
}
