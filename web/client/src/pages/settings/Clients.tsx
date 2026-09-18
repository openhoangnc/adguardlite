import { useState } from 'react';

import * as api from '../../api';
import type { Client, ClientsResponse } from '../../api';
import { Card, Check, Field, Loading, Modal, Notice, Table, useToast } from '../../components/ui';
import { IconEdit, IconPlus, IconTrash } from '../../components/icons';
import { lines, unlines } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

const BLANK: Client = {
    name: '',
    ids: [],
    use_global_settings: true,
    filtering_enabled: true,
    parental_enabled: false,
    safebrowsing_enabled: false,
    use_global_blocked_services: true,
    blocked_services: [],
    upstreams: [],
    tags: [],
    ignore_querylog: false,
    ignore_statistics: false,
};

export default function Clients() {
    const toast = useToast();
    const clients = useAsync(() => api.getClients());
    const [editing, setEditing] = useState<{ client: Client; original?: string }>();

    if (!clients.data) {
        return clients.error ? <Notice kind="error">{clients.error}</Notice> : <Loading />;
    }

    const remove = async (c: Client) => {
        if (!window.confirm(`Delete the client "${c.name}"? Its devices fall back to the global settings.`)) {
            return;
        }

        try {
            await api.deleteClient(c.name);
            await clients.reload();
            toast.ok(`Deleted ${c.name}`);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const save = async (c: Client, original?: string) => {
        try {
            if (original) {
                await api.updateClient(original, c);
                toast.ok(`Saved ${c.name}`);
            } else {
                await api.addClient(c);
                toast.ok(`Added ${c.name}`);
            }
            setEditing(undefined);
            await clients.reload();
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>Clients</h1>
                <p>Give a device its own filtering rules, upstreams and blocked services.</p>
            </div>

            <Card
                title="Configured clients"
                actions={
                    <button type="button" className="btn primary" onClick={() => setEditing({ client: { ...BLANK } })}>
                        <IconPlus size={15} /> Add a client
                    </button>
                }>
                <Table
                    className="rows"
                    empty="No client has its own settings yet."
                    head={
                        <>
                            <th>Name</th>
                            <th>Identifiers</th>
                            <th>Filtering</th>
                            <th>Tags</th>
                            <th className="actions" />
                        </>
                    }>
                    {(clients.data.clients ?? []).map((c) => (
                        <tr key={c.name}>
                            <td data-label="Name">{c.name}</td>
                            <td className="mono" data-label="Identifiers">
                                {c.ids.join(', ')}
                            </td>
                            <td data-label="Filtering">
                                <Summary client={c} />
                            </td>
                            <td data-label="Tags">
                                {c.tags.map((tag) => (
                                    <span className="badge grey" key={tag} style={{ marginRight: 4 }}>
                                        {tag}
                                    </span>
                                ))}
                            </td>
                            <td className="actions">
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Edit ${c.name}`}
                                    onClick={() => setEditing({ client: { ...c }, original: c.name })}>
                                    <IconEdit size={16} />
                                </button>
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Delete ${c.name}`}
                                    onClick={() => void remove(c)}>
                                    <IconTrash size={16} />
                                </button>
                            </td>
                        </tr>
                    ))}
                </Table>
            </Card>

            <Runtime data={clients.data} />

            {editing && (
                <Editor
                    client={editing.client}
                    original={editing.original}
                    tags={clients.data.supported_tags ?? []}
                    onClose={() => setEditing(undefined)}
                    onSave={save}
                />
            )}
        </>
    );
}

function Summary({ client }: { client: Client }) {
    if (client.use_global_settings) {
        return <span className="muted">Global settings</span>;
    }

    const on = [
        client.filtering_enabled && 'filters',
        client.safebrowsing_enabled && 'security',
        client.parental_enabled && 'adult content',
    ].filter(Boolean);

    return <span className="muted">{on.length ? on.join(', ') : 'nothing blocked'}</span>;
}

function Runtime({ data }: { data: ClientsResponse }) {
    const rows = data.auto_clients ?? [];

    return (
        <Card
            title="Seen on the network"
            desc="Devices Sift has learned about from reverse lookups, the hosts file and ARP. They use the global settings unless you add them above.">
            <Table
                className="rows"
                empty="No client has queried yet."
                head={
                    <>
                        <th>Address</th>
                        <th>Name</th>
                        <th>Learned from</th>
                    </>
                }>
                {rows.map((c) => (
                    <tr key={`${c.ip}-${c.source}`}>
                        <td className="mono" data-label="Address">
                            {c.ip}
                        </td>
                        <td data-label="Name">{c.name}</td>
                        <td className="muted" data-label="From">
                            {c.source}
                        </td>
                    </tr>
                ))}
            </Table>
        </Card>
    );
}

function Editor({
    client,
    original,
    tags,
    onClose,
    onSave,
}: {
    client: Client;
    original?: string;
    tags: string[];
    onClose: () => void;
    onSave: (c: Client, original?: string) => Promise<void>;
}) {
    const [d, setD] = useState(client);
    const [busy, setBusy] = useState(false);
    const catalogue = useAsync(() => api.getServiceCatalogue());
    const set = <K extends keyof Client>(k: K, v: Client[K]) => setD({ ...d, [k]: v });

    const toggleService = (id: string) =>
        set(
            'blocked_services',
            d.blocked_services.includes(id) ? d.blocked_services.filter((s) => s !== id) : [...d.blocked_services, id],
        );

    return (
        <Modal
            title={original ? `Edit ${original}` : 'New client'}
            onClose={onClose}
            wide
            footer={
                <>
                    <button type="button" className="btn" onClick={onClose}>
                        Cancel
                    </button>
                    <button
                        type="button"
                        className="btn primary"
                        disabled={busy || !d.name.trim() || d.ids.length === 0}
                        onClick={async () => {
                            setBusy(true);
                            try {
                                await onSave(d, original);
                            } finally {
                                setBusy(false);
                            }
                        }}>
                        Save
                    </button>
                </>
            }>
            <Field label="Name">
                <input
                    value={d.name}
                    autoFocus
                    placeholder="Living room TV"
                    onChange={(e) => set('name', e.target.value)}
                />
            </Field>

            <Field
                label="Identifiers"
                hint="One per line: an address, a CIDR range, a MAC address, or a ClientID that DoT, DoH and DoQ clients can send.">
                <textarea
                    value={unlines(d.ids)}
                    spellCheck={false}
                    style={{ minHeight: 76 }}
                    placeholder={'192.168.1.10\n192.168.2.0/24\nliving-room-tv'}
                    onChange={(e) => set('ids', lines(e.target.value))}
                />
            </Field>

            {tags.length > 0 && (
                <Field label="Tags" hint="Rules with a $ctag modifier apply to the clients carrying that tag.">
                    <select
                        multiple
                        size={6}
                        value={d.tags}
                        onChange={(e) => set('tags', Array.from(e.target.selectedOptions, (o) => o.value))}>
                        {tags.map((tag) => (
                            <option key={tag} value={tag}>
                                {tag}
                            </option>
                        ))}
                    </select>
                </Field>
            )}

            <Check
                checked={d.use_global_settings}
                label="Use the global filtering settings"
                onChange={(v) => set('use_global_settings', v)}
            />
            {!d.use_global_settings && (
                <>
                    <Check
                        checked={d.filtering_enabled}
                        label="Block with filter lists and rules"
                        onChange={(v) => set('filtering_enabled', v)}
                    />
                    <Check
                        checked={d.safebrowsing_enabled}
                        label="Block malware and phishing"
                        onChange={(v) => set('safebrowsing_enabled', v)}
                    />
                    <Check
                        checked={d.parental_enabled}
                        label="Block adult content"
                        onChange={(v) => set('parental_enabled', v)}
                    />
                </>
            )}

            <Check
                checked={d.use_global_blocked_services}
                label="Use the global blocked services"
                onChange={(v) => set('use_global_blocked_services', v)}
            />
            {!d.use_global_blocked_services && (
                <div style={{ maxHeight: 220, overflowY: 'auto', margin: '8px 0 14px' }}>
                    {catalogue.data ? (
                        <div
                            className="grid"
                            style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 2 }}>
                            {catalogue.data.blocked_services.map((s) => (
                                <label key={s.id} className="check" style={{ padding: '4px 0', borderTop: 'none' }}>
                                    <input
                                        type="checkbox"
                                        checked={d.blocked_services.includes(s.id)}
                                        onChange={() => toggleService(s.id)}
                                    />
                                    <span className="text">{s.name}</span>
                                </label>
                            ))}
                        </div>
                    ) : (
                        <Loading />
                    )}
                </div>
            )}

            <Field label="Upstream servers" hint="One per line. Left empty, this client uses the servers on the DNS settings page.">
                <textarea
                    value={unlines(d.upstreams)}
                    spellCheck={false}
                    style={{ minHeight: 76 }}
                    onChange={(e) => set('upstreams', lines(e.target.value))}
                />
            </Field>

            <Check
                checked={d.ignore_querylog}
                label="Keep this client out of the query log"
                onChange={(v) => set('ignore_querylog', v)}
            />
            <Check
                checked={d.ignore_statistics}
                label="Keep this client out of the statistics"
                onChange={(v) => set('ignore_statistics', v)}
            />
        </Modal>
    );
}
