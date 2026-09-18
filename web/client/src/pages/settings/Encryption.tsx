import { useEffect, useState } from 'react';

import * as api from '../../api';
import type { TlsConfig, TlsStatus } from '../../api';
import { Card, Check, Field, Loading, Notice, SaveButton, useToast } from '../../components/ui';
import { formatDate } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

type Source = 'path' | 'content';

/** Strips the status-only fields, leaving the body `configure` takes. */
function settings(s: TlsStatus | TlsConfig): TlsConfig {
    return {
        enabled: s.enabled,
        server_name: s.server_name ?? '',
        force_https: s.force_https,
        port_https: s.port_https,
        port_dns_over_tls: s.port_dns_over_tls,
        port_dns_over_quic: s.port_dns_over_quic,
        certificate_chain: s.certificate_chain ?? '',
        private_key: s.private_key ?? '',
        certificate_path: s.certificate_path ?? '',
        private_key_path: s.private_key_path ?? '',
        serve_plain_dns: s.serve_plain_dns,
    };
}

export default function Encryption() {
    const toast = useToast();
    const status = useAsync(() => api.getTlsStatus());

    const [draft, setDraft] = useState<TlsConfig>();
    const [check, setCheck] = useState<TlsStatus>();
    const [certSource, setCertSource] = useState<Source>('path');
    const [keySource, setKeySource] = useState<Source>('path');

    useEffect(() => {
        if (!status.data) {
            return;
        }

        setDraft(settings(status.data));
        setCheck(status.data);
        setCertSource(status.data.certificate_chain ? 'content' : 'path');
        setKeySource(status.data.private_key ? 'content' : 'path');
    }, [status.data]);

    // The server is the only thing that can say whether a certificate and key
    // belong together, so every edit that could change the answer asks it.
    useEffect(() => {
        if (!draft || !draft.enabled) {
            return;
        }

        const id = window.setTimeout(() => {
            void api
                .validateTls(draft)
                .then(setCheck)
                .catch((e) => setCheck({ ...(check as TlsStatus), warning_validation: message(e) }));
        }, 400);

        return () => window.clearTimeout(id);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [
        draft?.certificate_chain,
        draft?.private_key,
        draft?.certificate_path,
        draft?.private_key_path,
        draft?.server_name,
        draft?.enabled,
    ]);

    if (!draft) {
        return status.error ? <Notice kind="error">{status.error}</Notice> : <Loading />;
    }

    const set = <K extends keyof TlsConfig>(k: K, v: TlsConfig[K]) => setDraft({ ...draft, [k]: v });

    const save = async () => {
        try {
            await api.configureTls(draft);
            await status.reload();
            toast.ok('Encryption settings saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>Encryption</h1>
                <p>Serves this interface over HTTPS, and DNS over TLS, HTTPS and QUIC, from one certificate.</p>
            </div>

            <Card>
                <Check
                    checked={draft.enabled}
                    label="Turn encryption on"
                    hint="Ports left at zero are not listened on, so you can enable DNS-over-TLS without moving the web interface."
                    onChange={(v) => set('enabled', v)}
                />

                <Field label="Server name" hint="The hostname on the certificate. Clients must reach Sift by this name.">
                    <input
                        value={draft.server_name}
                        placeholder="dns.example.org"
                        disabled={!draft.enabled}
                        onChange={(e) => set('server_name', e.target.value)}
                    />
                </Field>

                <Check
                    checked={draft.force_https}
                    disabled={!draft.enabled}
                    label="Send plain HTTP to HTTPS"
                    hint="Only affects this interface; a DNS-over-HTTPS client is never redirected."
                    onChange={(v) => set('force_https', v)}
                />

                <div className="grid grid-3">
                    <Field label="HTTPS port" hint="Also where DNS-over-HTTPS answers, at /dns-query.">
                        <input
                            type="number"
                            min={0}
                            max={65535}
                            disabled={!draft.enabled}
                            value={draft.port_https}
                            onChange={(e) => set('port_https', Number(e.target.value))}
                        />
                    </Field>
                    <Field label="DNS-over-TLS port" hint="853 is the registered port.">
                        <input
                            type="number"
                            min={0}
                            max={65535}
                            disabled={!draft.enabled}
                            value={draft.port_dns_over_tls}
                            onChange={(e) => set('port_dns_over_tls', Number(e.target.value))}
                        />
                    </Field>
                    <Field label="DNS-over-QUIC port" hint="853 over UDP.">
                        <input
                            type="number"
                            min={0}
                            max={65535}
                            disabled={!draft.enabled}
                            value={draft.port_dns_over_quic}
                            onChange={(e) => set('port_dns_over_quic', Number(e.target.value))}
                        />
                    </Field>
                </div>

                <Check
                    checked={draft.serve_plain_dns}
                    label="Keep answering plain DNS"
                    hint="Turn this off only once every device on the network is using an encrypted protocol — otherwise they lose name resolution."
                    onChange={(v) => set('serve_plain_dns', v)}
                />
            </Card>

            <Card
                title="Certificate"
                desc="A PEM chain for the server name above. Let's Encrypt issues one free; a path is re-read when the file changes on disk, so a renewal needs no restart.">
                <Sources
                    source={certSource}
                    onSource={(s) => {
                        setCertSource(s);
                        setDraft({ ...draft, certificate_chain: '', certificate_path: '' });
                    }}
                />
                {certSource === 'path' ? (
                    <Field label="Path to the chain">
                        <input
                            value={draft.certificate_path}
                            placeholder="/etc/ssl/certs/fullchain.pem"
                            disabled={!draft.enabled}
                            onChange={(e) => set('certificate_path', e.target.value)}
                        />
                    </Field>
                ) : (
                    <Field label="The chain itself">
                        <textarea
                            value={draft.certificate_chain}
                            placeholder="-----BEGIN CERTIFICATE-----"
                            disabled={!draft.enabled}
                            onChange={(e) => set('certificate_chain', e.target.value)}
                        />
                    </Field>
                )}
                <CertificateStatus check={check} />
            </Card>

            <Card title="Private key">
                <Sources
                    source={keySource}
                    onSource={(s) => {
                        setKeySource(s);
                        setDraft({ ...draft, private_key: '', private_key_path: '' });
                    }}
                />
                {keySource === 'path' ? (
                    <Field label="Path to the key">
                        <input
                            value={draft.private_key_path}
                            placeholder="/etc/ssl/private/privkey.pem"
                            disabled={!draft.enabled}
                            onChange={(e) => set('private_key_path', e.target.value)}
                        />
                    </Field>
                ) : (
                    <Field label="The key itself">
                        <textarea
                            value={draft.private_key}
                            placeholder="-----BEGIN PRIVATE KEY-----"
                            disabled={!draft.enabled}
                            onChange={(e) => set('private_key', e.target.value)}
                        />
                    </Field>
                )}
                {check?.valid_key && (
                    <Notice kind="ok">The key is valid{check.key_type ? ` (${check.key_type})` : ''}.</Notice>
                )}
            </Card>

            <SaveButton onClick={save} disabled={draft.enabled && check ? !check.valid_pair : false}>
                Save
            </SaveButton>
        </>
    );
}

function Sources({ source, onSource }: { source: Source; onSource: (s: Source) => void }) {
    return (
        <div className="btn-row" style={{ marginBottom: 12 }}>
            {(
                [
                    ['path', 'Read it from a file'],
                    ['content', 'Paste it here'],
                ] as [Source, string][]
            ).map(([value, label]) => (
                <button
                    key={value}
                    type="button"
                    className={`btn sm ${source === value ? 'primary' : ''}`}
                    onClick={() => onSource(value)}>
                    {label}
                </button>
            ))}
        </div>
    );
}

function CertificateStatus({ check }: { check: TlsStatus | undefined }) {
    if (!check) {
        return null;
    }

    if (check.warning_validation) {
        return <Notice kind="error">{check.warning_validation}</Notice>;
    }

    if (!check.valid_cert) {
        return null;
    }

    return (
        <Notice kind={check.valid_chain ? 'ok' : 'warn'}>
            <div>
                {check.subject && (
                    <div>
                        Issued to <span className="mono">{check.subject}</span>
                    </div>
                )}
                {check.issuer && (
                    <div>
                        Issued by <span className="mono">{check.issuer}</span>
                    </div>
                )}
                {check.dns_names && (
                    <div>
                        Valid for <span className="mono">{check.dns_names.join(', ')}</span>
                    </div>
                )}
                <div>Expires {formatDate(check.not_after)}</div>
                {!check.valid_chain && <div>The chain is incomplete, so some clients will refuse it.</div>}
            </div>
        </Notice>
    );
}
