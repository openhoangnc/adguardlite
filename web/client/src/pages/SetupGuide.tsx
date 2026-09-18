import { useState } from 'react';

import * as api from '../api';
import { useServer } from '../app/context';
import { Card, Notice } from '../components/ui';
import { IconDownload } from '../components/icons';
import { useAsync } from '../lib/hooks';

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

export default function SetupGuide() {
    const { status } = useServer();
    const [platform, setPlatform] = useState('router');
    const tls = useAsync(() => api.getTlsStatus());

    const current = PLATFORMS.find((p) => p.id === platform) ?? PLATFORMS[0]!;
    const encrypted = tls.data?.enabled && tls.data.server_name;

    return (
        <>
            <div className="page-head">
                <h1>Setup guide</h1>
                <p>Point your devices at Sift and it starts filtering their traffic.</p>
            </div>

            <Card title="This server answers on">
                <ul className="mono" style={{ margin: 0, paddingLeft: 18 }}>
                    {status.dns_addresses.map((a) => (
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
                {!encrypted ? (
                    <Notice kind="info">
                        Set a server name and a certificate under Encryption, and the addresses for DNS-over-TLS,
                        DNS-over-HTTPS and DNS-over-QUIC appear here.
                    </Notice>
                ) : (
                    <>
                        <ul style={{ paddingLeft: 18 }}>
                            {tls.data!.port_dns_over_tls > 0 && (
                                <li>
                                    <b>DNS-over-TLS</b> — <code className="mono">tls://{tls.data!.server_name}</code>
                                </li>
                            )}
                            {tls.data!.port_https > 0 && (
                                <li>
                                    <b>DNS-over-HTTPS</b> —{' '}
                                    <code className="mono">https://{tls.data!.server_name}/dns-query</code>
                                </li>
                            )}
                            {tls.data!.port_dns_over_quic > 0 && (
                                <li>
                                    <b>DNS-over-QUIC</b> — <code className="mono">quic://{tls.data!.server_name}</code>
                                </li>
                            )}
                        </ul>

                        <h3 style={{ marginTop: 16 }}>Apple devices</h3>
                        <p className="muted">
                            Install one of these profiles and the device uses encrypted DNS everywhere, on Wi-Fi and on
                            mobile data alike.
                        </p>
                        <div className="btn-row" style={{ marginTop: 8 }}>
                            <a className="btn" href="/apple/doh.mobileconfig" download>
                                <IconDownload size={15} /> DNS-over-HTTPS profile
                            </a>
                            <a className="btn" href="/apple/dot.mobileconfig" download>
                                <IconDownload size={15} /> DNS-over-TLS profile
                            </a>
                        </div>
                    </>
                )}
            </Card>
        </>
    );
}
