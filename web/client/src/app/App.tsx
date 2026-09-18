import { useEffect, useState } from 'react';
import { HashRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom';

import { Loading, Notice, ToastProvider } from '../components/ui';
import {
    IconAllow,
    IconBlock,
    IconClients,
    IconDashboard,
    IconDns,
    IconGuide,
    IconLock,
    IconLog,
    IconRewrite,
    IconRules,
    IconServices,
    IconSettings,
    Logo,
} from '../components/icons';
import { applyTheme, rememberedTheme } from '../lib/theme';
import Dashboard from '../pages/Dashboard';
import QueryLog from '../pages/QueryLog';
import SetupGuide from '../pages/SetupGuide';
import Allowlist from '../pages/filters/Allowlist';
import Blocklist from '../pages/filters/Blocklist';
import CustomRules from '../pages/filters/CustomRules';
import Rewrites from '../pages/filters/Rewrites';
import Services from '../pages/filters/Services';
import Clients from '../pages/settings/Clients';
import Dns from '../pages/settings/Dns';
import Encryption from '../pages/settings/Encryption';
import General from '../pages/settings/General';
import { ServerProvider, useBootstrap, useServer } from './context';
import Topbar from './Topbar';

/**
 * The navigation, and with it the route table.
 *
 * The paths are the ones the old interface used, so a bookmark still lands on
 * the same page.  They are hash routes for a reason: signed out, the server
 * redirects `/` to the login form but answers any other path 401, so a
 * bookmarked `/settings` would be a blank 401 rather than a sign-in prompt.
 */
const NAV = [
    {
        group: '',
        items: [
            { to: '/', label: 'Dashboard', Icon: IconDashboard, end: true },
            { to: '/logs', label: 'Query log', Icon: IconLog },
            { to: '/guide', label: 'Setup guide', Icon: IconGuide },
        ],
    },
    {
        group: 'Settings',
        items: [
            { to: '/settings', label: 'General', Icon: IconSettings },
            { to: '/dns', label: 'DNS', Icon: IconDns },
            { to: '/encryption', label: 'Encryption', Icon: IconLock },
            { to: '/clients', label: 'Clients', Icon: IconClients },
        ],
    },
    {
        group: 'Filters',
        items: [
            { to: '/filters', label: 'Blocklists', Icon: IconBlock },
            { to: '/dns_allowlists', label: 'Allowlists', Icon: IconAllow },
            { to: '/dns_rewrites', label: 'DNS rewrites', Icon: IconRewrite },
            { to: '/custom_rules', label: 'Custom rules', Icon: IconRules },
            { to: '/blocked_services', label: 'Blocked services', Icon: IconServices },
        ],
    },
] as const;

export default function App() {
    // The theme is applied from the last one used before the profile arrives,
    // so a reload does not flash the wrong one.
    useEffect(() => applyTheme(rememberedTheme()), []);

    const boot = useBootstrap();
    const theme = boot.data?.profile.theme;

    // The profile is the authority, and it arrives a request later: without
    // this, a browser that has never been here keeps whatever the remembered
    // theme happened to be and the account's choice never applies.
    useEffect(() => {
        if (theme) {
            applyTheme(theme);
        }
    }, [theme]);

    if (boot.loading && !boot.data) {
        return <Loading />;
    }

    if (!boot.data) {
        return (
            <div className="page">
                <Notice kind="error">{boot.error ?? 'The server did not answer.'}</Notice>
            </div>
        );
    }

    const { status, profile } = boot.data;

    return (
        <ToastProvider>
            <ServerProvider status={status} profile={profile} reload={boot.reload}>
                <HashRouter>
                    <Shell />
                </HashRouter>
            </ServerProvider>
        </ToastProvider>
    );
}

function Shell() {
    const [open, setOpen] = useState(false);
    const { pathname } = useLocation();
    const { status } = useServer();

    // Navigating closes it, because at this width the menu covers the page it
    // just moved to.
    useEffect(() => setOpen(false), [pathname]);

    useEffect(() => {
        if (!open) {
            return;
        }

        const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
        document.addEventListener('keydown', esc);

        return () => document.removeEventListener('keydown', esc);
    }, [open]);

    return (
        <div className="shell">
            {/* Dismisses the menu from anywhere outside it, which is what a
                tap beside an open drawer is asking for. */}
            {open && (
                <div className="sidebar-backdrop" onClick={() => setOpen(false)} aria-hidden="true" />
            )}
            <nav className={`sidebar ${open ? 'open' : ''}`} aria-label="Main">
                <a className="brand" href="#/">
                    <Logo />
                    Sift
                </a>
                {NAV.map((g, i) => (
                    <div className="nav-group" key={i}>
                        {g.group && <span>{g.group}</span>}
                        {g.items.map(({ to, label, Icon, ...rest }) => (
                            <NavLink
                                key={to}
                                to={to}
                                end={'end' in rest ? rest.end : false}
                                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
                                <Icon size={17} />
                                {label}
                            </NavLink>
                        ))}
                    </div>
                ))}

                {/* At the foot, so the answer to "what is this running" is
                    on the screen rather than behind the profile menu.  That a
                    newer one exists is the top bar's to say, and saying it
                    twice on one screen is worse than saying it once. */}
                <div className="sidebar-foot">Sift {status.version}</div>
            </nav>

            <div className="main">
                <Topbar onBurger={() => setOpen((v) => !v)} />
                <div className="page">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/logs" element={<QueryLog />} />
                        <Route path="/guide" element={<SetupGuide />} />
                        <Route path="/settings" element={<General />} />
                        <Route path="/dns" element={<Dns />} />
                        <Route path="/encryption" element={<Encryption />} />
                        <Route path="/clients" element={<Clients />} />
                        <Route path="/filters" element={<Blocklist />} />
                        <Route path="/dns_allowlists" element={<Allowlist />} />
                        <Route path="/dns_rewrites" element={<Rewrites />} />
                        <Route path="/custom_rules" element={<CustomRules />} />
                        <Route path="/blocked_services" element={<Services />} />
                        <Route path="*" element={<Dashboard />} />
                    </Routes>
                    <Footer />
                </div>
            </div>
        </div>
    );
}

/**
 * The provenance statement, where users see it.
 *
 * GPL-3.0 §5(a) wants the modification stated, and NOTICE.md says this is one
 * of the places it is.
 */
function Footer() {
    const home = 'https://github.com/openhoangnc/sift';

    return (
        <footer className="footer">
            <div className="btn-row" style={{ marginBottom: 6 }}>
                <a href={home} target="_blank" rel="noreferrer">
                    Homepage
                </a>
                <a href={`${home}/issues`} target="_blank" rel="noreferrer">
                    Report an issue
                </a>
            </div>
            <div>
                © 2026 openhoangnc. Sift is free software under the{' '}
                <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noreferrer">
                    GPL-3.0
                </a>{' '}
                and comes with no warranty; the{' '}
                <a href={home} target="_blank" rel="noreferrer">
                    source
                </a>{' '}
                is public.
            </div>
            <div>
                Sift is an independent reimplementation of{' '}
                <a href="https://github.com/AdguardTeam/AdGuardHome" target="_blank" rel="noreferrer">
                    AdGuard Home
                </a>
                . It is not affiliated with, endorsed by, or supported by AdGuard.
            </div>
        </footer>
    );
}
