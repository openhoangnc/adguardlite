import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

import * as api from '../api';
import type { InstallAddresses } from '../api';
import { keepUnauthorizedHere } from '../api/client';
import { Field, Loading, Notice } from '../components/ui';
import { Logo } from '../components/icons';
import { message } from '../lib/hooks';
import { applyTheme, rememberedTheme } from '../lib/theme';
import '../styles/app.css';

keepUnauthorizedHere();
applyTheme(rememberedTheme());

/** `0.0.0.0` means every interface, and is what the wizard offers first. */
const ALL = '0.0.0.0';

interface Binding {
    ip: string;
    port: number;
}

function Wizard() {
    const [step, setStep] = useState(0);
    const [addresses, setAddresses] = useState<InstallAddresses>();
    const [error, setError] = useState<string>();
    const [busy, setBusy] = useState(false);

    const [web, setWeb] = useState<Binding>({ ip: ALL, port: 3000 });
    const [dns, setDns] = useState<Binding>({ ip: ALL, port: 53 });
    const [user, setUser] = useState('');
    const [pass, setPass] = useState('');
    const [again, setAgain] = useState('');

    useEffect(() => {
        api.getInstallAddresses()
            .then((a) => {
                setAddresses(a);
                setWeb({ ip: ALL, port: a.web_port });
                setDns({ ip: ALL, port: a.dns_port });
            })
            .catch((e) => setError(message(e)));
    }, []);

    if (error && !addresses) {
        return (
            <div className="wizard">
                <Notice kind="error">{error}</Notice>
            </div>
        );
    }

    if (!addresses) {
        return <Loading />;
    }

    const ips = [ALL, ...new Set(Object.values(addresses.interfaces).flatMap((i) => i.ip_addresses ?? []))];

    const checkPorts = async () => {
        setBusy(true);
        setError(undefined);
        try {
            const r = await api.checkInstallConfig({
                web: { ...web, autofix: false },
                dns: { ...dns, autofix: false },
                set_static_ip: false,
            });
            const bad = [r.web.status, r.dns.status].filter(Boolean).join(' ');
            if (bad) {
                setError(bad);

                return;
            }
            setStep(2);
        } catch (e) {
            setError(message(e));
        } finally {
            setBusy(false);
        }
    };

    const finish = async () => {
        if (pass !== again) {
            setError('The two passwords do not match.');

            return;
        }

        setBusy(true);
        setError(undefined);
        try {
            await api.configureInstall({ web, dns, username: user, password: pass });
            setStep(3);
        } catch (e) {
            setError(message(e));
        } finally {
            setBusy(false);
        }
    };

    const where = web.ip === ALL ? window.location.hostname : web.ip;
    const target = `${window.location.protocol}//${where}:${web.port}/`;

    return (
        <div className="wizard">
            <div className="brand" style={{ justifyContent: 'center', fontSize: 22, paddingBottom: 18 }}>
                <Logo size={28} />
                Sift
            </div>

            <div className="steps">
                {[0, 1, 2, 3].map((i) => (
                    <div key={i} className={i <= step ? 'done' : ''} />
                ))}
            </div>

            {error && <Notice kind="error">{error}</Notice>}

            {step === 0 && (
                <section className="card">
                    <h1>Welcome to Sift</h1>
                    <p className="card-desc">
                        Sift filters DNS for every device on your network, so nothing has to be installed on them. This
                        takes a minute.
                    </p>
                    <button type="button" className="btn primary" onClick={() => setStep(1)}>
                        Get started
                    </button>
                </section>
            )}

            {step === 1 && (
                <section className="card">
                    <h1>Admin interface</h1>
                    <p className="card-desc">Where this page will be served from once setup is done.</p>
                    <Binder value={web} onChange={setWeb} ips={ips} />

                    <h2 style={{ marginTop: 18 }}>DNS server</h2>
                    <p className="card-desc">
                        Where your devices will send their queries. 53 is the standard port; on Linux, binding it needs
                        the right capability.
                    </p>
                    <Binder value={dns} onChange={setDns} ips={ips} />

                    <div className="btn-row" style={{ marginTop: 10 }}>
                        <button type="button" className="btn" onClick={() => setStep(0)}>
                            Back
                        </button>
                        <button type="button" className="btn primary" disabled={busy} onClick={() => void checkPorts()}>
                            Next
                        </button>
                    </div>
                </section>
            )}

            {step === 2 && (
                <form
                    className="card"
                    onSubmit={(e) => {
                        e.preventDefault();
                        void finish();
                    }}>
                    <h1>Administrator</h1>
                    <p className="card-desc">
                        This interface can change how every device on the network resolves names, so it is worth a
                        password even on a private network.
                    </p>

                    <Field label="Username">
                        <input
                            type="text"
                            autoComplete="username"
                            required
                            value={user}
                            onChange={(e) => setUser(e.target.value)}
                        />
                    </Field>
                    <Field label="Password">
                        <input
                            type="password"
                            autoComplete="new-password"
                            required
                            value={pass}
                            onChange={(e) => setPass(e.target.value)}
                        />
                    </Field>
                    <Field label="Password again">
                        <input
                            type="password"
                            autoComplete="new-password"
                            required
                            value={again}
                            onChange={(e) => setAgain(e.target.value)}
                        />
                    </Field>

                    <div className="btn-row">
                        <button type="button" className="btn" onClick={() => setStep(1)}>
                            Back
                        </button>
                        <button type="submit" className="btn primary" disabled={busy}>
                            Finish
                        </button>
                    </div>
                </form>
            )}

            {step === 3 && (
                <section className="card">
                    <h1>All done</h1>
                    <p className="card-desc">
                        Sift is configured. Sign in, then follow the setup guide to point your devices at it.
                    </p>
                    <p>
                        Your devices should use <code className="mono">{dns.ip === ALL ? where : dns.ip}</code>
                        {dns.port !== 53 && <> on port {dns.port}</>}.
                    </p>
                    <a className="btn primary" href={target}>
                        Open Sift
                    </a>
                </section>
            )}
        </div>
    );
}

function Binder({ value, onChange, ips }: { value: Binding; onChange: (b: Binding) => void; ips: string[] }) {
    return (
        <>
            <Field label="Listen on">
                <select value={value.ip} onChange={(e) => onChange({ ...value, ip: e.target.value })}>
                    {ips.map((ip) => (
                        <option key={ip} value={ip}>
                            {ip === ALL ? `${ip} (every interface)` : ip}
                        </option>
                    ))}
                </select>
            </Field>
            <Field label="Port">
                <input
                    type="number"
                    min={1}
                    max={65535}
                    value={value.port}
                    onChange={(e) => onChange({ ...value, port: Number(e.target.value) })}
                />
            </Field>
        </>
    );
}

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <Wizard />
    </StrictMode>,
);
