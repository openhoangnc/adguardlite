import { useState } from 'react';
import { Link } from 'react-router-dom';

import * as api from '../api';
import type { TlsStatus } from '../api';
import { useServer } from '../app/context';
import { Card, Loading, Notice } from '../components/ui';
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
 * whichever host it is given, since the settings may name none.
 */
function profile(kind: 'doh' | 'dot', host: string) {
    return `/control/apple/${kind}.mobileconfig?host=${encodeURIComponent(host)}`;
}

/** `host`, with the port spelled out when it is not the scheme's own. */
function authority(host: string, port: number, scheme: keyof typeof DEFAULT_PORT) {
    return port === DEFAULT_PORT[scheme] ? host : `${host}:${port}`;
}

/**
 * The addresses for whichever encrypted listeners are running.
 *
 * A port left at zero is not listened on, so it is not offered.
 */
function addresses(tls: TlsStatus, host: string) {
    const out: { label: string; address: string }[] = [];

    if (tls.port_dns_over_tls > 0) {
        out.push({ label: 'DNS-over-TLS', address: `tls://${authority(host, tls.port_dns_over_tls, 'tls')}` });
    }
    if (tls.port_https > 0) {
        out.push({
            label: 'DNS-over-HTTPS',
            address: `https://${authority(host, tls.port_https, 'https')}/dns-query`,
        });
    }
    if (tls.port_dns_over_quic > 0) {
        out.push({ label: 'DNS-over-QUIC', address: `quic://${authority(host, tls.port_dns_over_quic, 'quic')}` });
    }

    return out;
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
    const host = named || s.dns_names?.[0] || '';

    if (!host) {
        return (
            <Notice kind="warn">
                Encryption is on, but nothing says which name clients should ask for: the server name is blank and the
                certificate names no host. Set a server name under Encryption.
            </Notice>
        );
    }

    const running = addresses(s, host);
    const standardDot = s.port_dns_over_tls === DEFAULT_PORT.tls;

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
                    <code className="mono">{host}</code>, the first name on the certificate. Fill the field in to pick a
                    different one, and to let clients find this server by itself.
                </Notice>
            )}

            {/* Android’s Private DNS takes a bare host name and dials 853
                itself, so it can reach a standard listener and no other. */}
            {standardDot && (
                <p className="hint">
                    Android’s Private DNS field takes the host name on its own: <code className="mono">{host}</code>.
                </p>
            )}

            {(s.port_https > 0 || standardDot) && (
                <>
                    <h3 style={{ marginTop: 16 }}>Apple devices</h3>
                    <p className="muted">
                        Install one of these profiles and the device uses encrypted DNS everywhere, on Wi-Fi and on
                        mobile data alike.
                    </p>
                    <div className="btn-row" style={{ marginTop: 8 }}>
                        {s.port_https > 0 && (
                            <a className="btn" href={profile('doh', host)} download>
                                <IconDownload size={15} /> DNS-over-HTTPS profile
                            </a>
                        )}
                        {/* Apple’s TLS profile names a host and no port, so it
                            can only describe a listener left on 853. */}
                        {standardDot && (
                            <a className="btn" href={profile('dot', host)} download>
                                <IconDownload size={15} /> DNS-over-TLS profile
                            </a>
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
                    type in.
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
