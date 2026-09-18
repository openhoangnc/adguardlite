import { useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import * as api from '../api';
import type { TlsStatus } from '../api';
import { useServer } from '../app/context';
import { Card, Field, Loading, Notice } from '../components/ui';
import { IconDownload } from '../components/icons';
import { useAsync } from '../lib/hooks';
import type { Async } from '../lib/hooks';

/** How to point each kind of device at this server. */
const PLATFORMS: { id: string; label: string; note?: string; steps: string[] }[] = [
    {
        id: 'router',
        label: 'Router',
        note: 'The one setting that covers every device on the network, including the ones you cannot configure.',
        steps: [
            'Open your router’s admin page — usually http://192.168.1.1 or http://192.168.0.1.',
            'Find the DHCP or DNS section. It is often under LAN, Internet, or Advanced.',
            'Replace the DNS servers with the addresses above, and remove any others.',
            'Save, then reconnect each device so it picks up the new setting.',
        ],
    },
    {
        id: 'windows',
        label: 'Windows',
        steps: [
            'Open Settings, then Network & internet.',
            'Pick your active connection and open its properties.',
            'Next to "DNS server assignment", choose Edit and switch to Manual.',
            'Turn on IPv4, enter the addresses above, and save.',
        ],
    },
    {
        id: 'macos',
        label: 'macOS',
        steps: [
            'Open System Settings, then Network.',
            'Select your active connection and open Details.',
            'Go to the DNS tab.',
            'Remove the servers listed and add the addresses above, then click OK.',
        ],
    },
    {
        id: 'android',
        label: 'Android',
        steps: [
            'Open Settings, then Network & internet, then your Wi-Fi network.',
            'Edit the network and set IP settings to Static.',
            'Enter the addresses above as DNS 1 and DNS 2, and save.',
            'Mobile data cannot take a custom plain-DNS server; use Private DNS with an encrypted address instead.',
        ],
    },
    {
        id: 'ios',
        label: 'iOS',
        steps: [
            'Open Settings, then Wi-Fi.',
            'Tap the ⓘ beside the network you are on.',
            'Tap Configure DNS and switch to Manual.',
            'Remove what is there, add the addresses above, and save.',
        ],
    },
    {
        id: 'linux',
        label: 'Linux',
        steps: [
            'With NetworkManager: open the connection’s IPv4 settings, set the method to "Automatic (addresses only)", and put the addresses above in the DNS field.',
            'With systemd-resolved: set DNS= in /etc/systemd/resolved.conf and restart systemd-resolved.',
            'Check it took effect with `resolvectl status`.',
        ],
    },
];

/** The port each scheme is assumed to be on, and so leaves out of an address. */
const DEFAULT_PORT = { tls: 853, https: 443, quic: 853 };

/**
 * Where the server builds an Apple configuration profile for `host`.
 *
 * Under `/control`, which is where this build serves them; the profile names
 * whichever host it is given, since the settings may name none.  A ClientID is
 * passed through under upstream's own parameter name, and the server writes it
 * into the profile the way that protocol's listener reads it back.
 */
function profile(kind: 'doh' | 'dot', host: string, clientId: string, port: number) {
    const q = new URLSearchParams({ host });
    if (clientId) {
        q.set('client_id', clientId);
    }
    // Apple's DNS-over-TLS profile carries no port, so sending one would say
    // this field changes something it cannot.
    if (kind === 'doh') {
        q.set('port', String(port));
    }

    return `/control/apple/${kind}.mobileconfig?${q}`;
}

/**
 * Why `id` is not a ClientID, or null when it is one.
 *
 * The same rule the listeners apply -- `is_valid_client_id` in
 * `sift-dns/src/server.rs` -- so the field refuses what the server would, here
 * rather than after a download.
 */
function clientIdError(id: string): string | null {
    if (!id) {
        return null;
    }
    if (id.length > 63) {
        return 'A ClientID is at most 63 characters.';
    }
    if (!/^[A-Za-z0-9-]+$/.test(id)) {
        return 'Letters, digits and hyphens only — no dots, spaces or underscores.';
    }
    if (id.startsWith('-') || id.endsWith('-')) {
        return 'A ClientID cannot start or end with a hyphen.';
    }

    return null;
}

/**
 * Why `port` is not a port, or null when it is one.
 *
 * Zero is what the settings use for "not listening", which is not something a
 * device can be sent to, so it is refused here as the endpoint refuses it.
 */
function portError(port: string): string | null {
    if (!/^\d+$/.test(port.trim())) {
        return 'A port is a number.';
    }

    const n = Number(port);

    return n >= 1 && n <= 65535 ? null : 'A port is between 1 and 65535.';
}

/** `host`, with the port spelled out when it is not the scheme's own. */
function authority(host: string, port: number, scheme: keyof typeof DEFAULT_PORT) {
    return port === DEFAULT_PORT[scheme] ? host : `${host}:${port}`;
}

/**
 * The addresses for whichever encrypted listeners are running.
 *
 * A port left at zero is not listened on, so it is not offered.
 *
 * A ClientID reaches each one the way that listener reads it back: a path
 * segment under DNS-over-HTTPS, and a label below the server name — the name
 * the handshake asks for — under DNS-over-TLS and DNS-over-QUIC.
 */
function addresses(tls: TlsStatus, host: string, clientId: string, httpsPort: number) {
    const out: { label: string; address: string }[] = [];
    const sni = clientId ? `${clientId}.${host}` : host;
    const path = clientId ? `/dns-query/${clientId}` : '/dns-query';

    if (tls.port_dns_over_tls > 0) {
        out.push({ label: 'DNS-over-TLS', address: `tls://${authority(sni, tls.port_dns_over_tls, 'tls')}` });
    }
    if (tls.port_https > 0) {
        out.push({
            label: 'DNS-over-HTTPS',
            address: `https://${authority(host, httpsPort, 'https')}${path}`,
        });
    }
    if (tls.port_dns_over_quic > 0) {
        out.push({ label: 'DNS-over-QUIC', address: `quic://${authority(sni, tls.port_dns_over_quic, 'quic')}` });
    }

    return out;
}

/**
 * One profile download, or the same button refusing to offer one.
 *
 * Without an `href` the link is neither clickable nor focusable, which is what
 * a disabled control has to be: an `<a>` cannot be `:disabled`, and dimming it
 * alone leaves a download that comes back as a 400 saved to disk.
 */
function ProfileButton({
    kind,
    host,
    clientId,
    port,
    blocked,
    children,
}: {
    kind: 'doh' | 'dot';
    host: string;
    clientId: string;
    port: number;
    blocked: boolean;
    children: ReactNode;
}) {
    return (
        <a
            className="btn"
            href={blocked ? undefined : profile(kind, host, clientId, port)}
            aria-disabled={blocked || undefined}
            download>
            <IconDownload size={15} /> {children}
        </a>
    );
}

/**
 * What to tell clients about the encrypted listeners, if any are running.
 *
 * The name comes from the encryption settings when one is set there, and from
 * the certificate when one is not: the listeners run either way, serving
 * whatever the certificate covers, so a blank server name is a gap in the
 * settings rather than a reason to claim encryption is unconfigured. Saying so
 * is what this card got wrong — it reported a working DNS-over-TLS server as
 * something still to be set up.
 */
function EncryptedDns({ tls }: { tls: Async<TlsStatus> }) {
    // Null until the field is touched, so the name the settings give can keep
    // arriving after this renders and still fill the box.
    const [typed, setTyped] = useState<string | null>(null);
    const [typedPort, setTypedPort] = useState<string | null>(null);
    const [clientId, setClientId] = useState('');

    if (tls.error) {
        return <Notice kind="error">{tls.error}</Notice>;
    }

    if (!tls.data) {
        return <Loading />;
    }

    const s = tls.data;

    if (!s.enabled) {
        return (
            <Notice kind="info">
                Add a certificate under <Link to="/encryption">Encryption</Link> and turn it on, and the addresses for
                DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC appear here.
            </Notice>
        );
    }

    const named = s.server_name?.trim() ?? '';
    const configured = named || s.dns_names?.[0] || '';
    // What the box shows, and what the addresses use: an empty box means the
    // name the settings give, which is what its placeholder says.
    const box = typed ?? configured;
    const host = box.trim() || configured;

    if (!configured) {
        return (
            <Notice kind="warn">
                Encryption is on, but nothing says which name clients should ask for: the server name is blank and the
                certificate names no host. Set a server name under Encryption.
            </Notice>
        );
    }

    // The same shape as the host: the box starts on the listener's own port,
    // and a bad one falls back to it rather than writing nonsense into the
    // addresses below.
    const portBox = typedPort ?? String(s.port_https);
    const portProblem = portError(portBox);
    const httpsPort = portProblem ? s.port_https : Number(portBox);

    const idError = clientIdError(clientId);
    const id = idError ? '' : clientId;
    // The server refuses these, so a button does not offer a download that
    // would come back as a 400 the browser saves to disk.  The port reaches
    // only the HTTPS profile, so only that one waits for it.
    const running = addresses(s, host, id, httpsPort);
    const standardDot = s.port_dns_over_tls === DEFAULT_PORT.tls;
    // The label only registers when it sits below the name the listeners were
    // started with, which is `tls.server_name` and nothing else: they compare
    // the handshake's name against that one to find it.
    const sniCarriesId = Boolean(named) && host === named;

    if (!running.length) {
        return (
            <Notice kind="warn">
                Encryption is on, but every encrypted port is set to zero, so nothing is listening. Set one under
                Encryption.
            </Notice>
        );
    }

    return (
        <>
            <div className="grid grid-3">
                <Field
                    label="Hostname"
                    hint="The name clients ask for. It has to resolve to this server and be one the certificate covers.">
                    <input
                        value={box}
                        placeholder={configured}
                        onChange={(e) => setTyped(e.target.value)}
                        autoCapitalize="off"
                        autoCorrect="off"
                        spellCheck={false}
                    />
                </Field>

                <Field
                    label="HTTPS port"
                    error={portProblem}
                    hint={
                        <>
                            The port devices dial for DNS-over-HTTPS. Change it if something in front of this server
                            answers on another one.
                        </>
                    }>
                    <input
                        value={portBox}
                        inputMode="numeric"
                        onChange={(e) => setTypedPort(e.target.value)}
                    />
                </Field>

                <Field
                    label="ClientID (optional)"
                    error={idError}
                    hint={
                        <>
                            Names this one device. Give the same ClientID to a client under{' '}
                            <Link to="/clients">Clients</Link> and it gets that client’s settings, wherever it connects
                            from.
                        </>
                    }>
                    <input
                        value={clientId}
                        placeholder="kids-tablet"
                        onChange={(e) => setClientId(e.target.value)}
                        autoCapitalize="off"
                        autoCorrect="off"
                        spellCheck={false}
                    />
                </Field>
            </div>

            <ul style={{ paddingLeft: 18 }}>
                {running.map((r) => (
                    <li key={r.label}>
                        <b>{r.label}</b> — <code className="mono">{r.address}</code>
                    </li>
                ))}
            </ul>

            {!named && (
                <Notice kind="warn">
                    The server name under Encryption is blank, so these use{' '}
                    <code className="mono">{configured}</code>, the first name on the certificate. Fill the field in to
                    pick a different one, and to let clients find this server by itself.
                </Notice>
            )}

            {/* A ClientID travels differently on each transport, and only the
                HTTPS one costs nothing: the others spend a certificate name. */}
            {id && !sniCarriesId && (
                <Notice kind="warn">
                    Only the DNS-over-HTTPS address carries this ClientID. The others put it in the name the client asks
                    for, and the server reads it back only below the server name set under{' '}
                    <Link to="/encryption">Encryption</Link>
                    {named ? (
                        <>
                            , which is <code className="mono">{named}</code>
                        </>
                    ) : (
                        ', which is blank'
                    )}
                    .
                </Notice>
            )}

            {id && sniCarriesId && (s.port_dns_over_tls > 0 || s.port_dns_over_quic > 0) && (
                <Notice kind="info">
                    The DNS-over-TLS and DNS-over-QUIC addresses only work if the certificate covers{' '}
                    <code className="mono">{`${id}.${host}`}</code> — in practice a wildcard for{' '}
                    <code className="mono">{`*.${host}`}</code>. DNS-over-HTTPS carries the ClientID in the path and
                    needs nothing extra.
                </Notice>
            )}

            {/* Android’s Private DNS takes a bare host name and dials 853
                itself, so it can reach a standard listener and no other. */}
            {standardDot && (
                <p className="hint">
                    Android’s Private DNS field takes the host name on its own:{' '}
                    <code className="mono">{id && sniCarriesId ? `${id}.${host}` : host}</code>.
                </p>
            )}

            {(s.port_https > 0 || standardDot) && (
                <>
                    <h3 style={{ marginTop: 16 }}>Apple devices</h3>
                    <p className="muted">
                        Install one of these profiles and the device uses encrypted DNS everywhere, on Wi-Fi and on
                        mobile data alike — with the ClientID above, if you set one.
                    </p>
                    <div className="btn-row" style={{ marginTop: 8 }}>
                        {s.port_https > 0 && (
                            <ProfileButton
                                kind="doh"
                                host={host}
                                clientId={id}
                                port={httpsPort}
                                blocked={Boolean(idError || portProblem)}>
                                DNS-over-HTTPS profile
                            </ProfileButton>
                        )}
                        {/* Apple’s TLS profile names a host and no port, so it
                            can only describe a listener left on 853. */}
                        {standardDot && (
                            <ProfileButton
                                kind="dot"
                                host={host}
                                clientId={id}
                                port={httpsPort}
                                blocked={Boolean(idError)}>
                                DNS-over-TLS profile
                            </ProfileButton>
                        )}
                    </div>
                </>
            )}
        </>
    );
}

export default function SetupGuide() {
    const { status } = useServer();
    const [platform, setPlatform] = useState('router');
    const tls = useAsync(() => api.getTlsStatus());

    const current = PLATFORMS.find((p) => p.id === platform) ?? PLATFORMS[0]!;

    // `dns_addresses` carries the encrypted addresses too, as upstream's does.
    // They belong under Encrypted DNS below, spelled the way a client wants
    // them, rather than in among the addresses the steps say to type in.
    const plain = status.dns_addresses.filter((a) => !a.includes('://'));

    return (
        <>
            <div className="page-head">
                <h1>Setup guide</h1>
                <p>Point your devices at Sift and it starts filtering their traffic.</p>
            </div>

            <Card title="This server answers on">
                <ul className="mono" style={{ margin: 0, paddingLeft: 18 }}>
                    {plain.map((a) => (
                        <li key={a}>{a}</li>
                    ))}
                </ul>
                <p className="hint" style={{ marginBottom: 0 }}>
                    Use an address your devices can actually reach — 0.0.0.0 means "every interface", not an address to
                    type in. The encrypted addresses are under Encrypted DNS, below.
                </p>
            </Card>

            <Card title="Configure a device">
                <div className="btn-row" style={{ marginBottom: 14 }}>
                    {PLATFORMS.map((p) => (
                        <button
                            key={p.id}
                            type="button"
                            className={`btn sm ${platform === p.id ? 'primary' : ''}`}
                            onClick={() => setPlatform(p.id)}>
                            {p.label}
                        </button>
                    ))}
                </div>

                {current.note && <p className="muted">{current.note}</p>}

                <ol style={{ margin: 0, paddingLeft: 20 }}>
                    {current.steps.map((step, i) => (
                        <li key={i} style={{ marginBottom: 6 }}>
                            {step}
                        </li>
                    ))}
                </ol>
            </Card>

            <Card title="Encrypted DNS">
                <EncryptedDns tls={tls} />
            </Card>
        </>
    );
}
