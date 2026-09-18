import { useMemo, useState } from 'react';

import * as api from '../../api';
import type { CatalogueEntry, CheckHostResult, Filter } from '../../api';
import { Card, Field, Loading, Modal, Notice, Table, useToast } from '../../components/ui';
import { IconEdit, IconExternal, IconPlus, IconRefresh, IconSearch, IconTrash } from '../../components/icons';
import { flag, formatDate, num } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

/**
 * What each catalogue category is called.
 *
 * The catalogue carries identifiers only -- upstream keeps the names in its
 * translation files -- so the wording is this project's.  An unknown category
 * falls back to its own identifier rather than dropping its lists.
 */
/**
 * The tags worth noticing, and how strongly.
 *
 * Most tags are metadata -- a size, a country, what a list happens to cover --
 * and belong in the background.  These four groups answer a question the
 * reader is actually holding: where do I start, what will this break, is this
 * protecting me from something, and is it a control I am imposing.  Anything
 * not named here stays grey, which is what makes these carry.
 */
const TONES: Record<string, string> = {
    starter: 'green',
    strict: 'amber',
    huge: 'amber',
    malware: 'red',
    phishing: 'red',
    scam: 'red',
    'crypto-mining': 'red',
    security: 'blue',
    bypass: 'blue',
};

/** Toned tags lead, so the eye finds them without reading the whole row. */
const TONE_ORDER = ['green', 'red', 'amber', 'blue'];

function rank(tag: string): number {
    const i = TONE_ORDER.indexOf(TONES[tag] ?? '');

    return i === -1 ? TONE_ORDER.length : i;
}

function byImportance(a: string, b: string): number {
    return rank(a) - rank(b) || a.localeCompare(b);
}

const CATEGORIES: Record<string, { name: string; desc: string }> = {
    general: { name: 'General', desc: 'Block advertising and tracking on most devices.' },
    security: { name: 'Security', desc: 'Block malware, phishing and scam domains.' },
    regional: { name: 'Regional', desc: 'Lists aimed at one country or language.' },
    other: { name: 'Other', desc: 'Narrower lists for a particular purpose.' },
};

/**
 * The blocklist and allowlist pages, which differ only in which half of
 * `/control/filtering/status` they read and the `whitelist` flag they send.
 */
export default function FilterList({ whitelist }: { whitelist: boolean }) {
    const toast = useToast();
    const status = useAsync(() => api.getFilteringStatus());
    const [editing, setEditing] = useState<{ filter: Filter | null }>();
    const [adding, setAdding] = useState<'pick' | 'choose' | null>(null);
    const [refreshing, setRefreshing] = useState(false);

    if (!status.data) {
        return status.error ? <Notice kind="error">{status.error}</Notice> : <Loading />;
    }

    const rows = (whitelist ? status.data.whitelist_filters : status.data.filters) ?? [];
    const kind = whitelist ? 'allowlist' : 'blocklist';

    const toggle = async (f: Filter) => {
        try {
            await api.setFilter(f.url, whitelist, { name: f.name, url: f.url, enabled: !f.enabled });
            await status.reload();
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const remove = async (f: Filter) => {
        if (!window.confirm(`Remove "${f.name}"? Its rules stop applying immediately.`)) {
            return;
        }

        try {
            await api.removeFilter(f.url, whitelist);
            await status.reload();
            toast.ok(`Removed ${f.name}`);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const refresh = async () => {
        setRefreshing(true);
        try {
            const r = await api.refreshFilters(whitelist);
            await status.reload();
            toast.ok(
                r.updated > 0
                    ? `${r.updated} ${r.updated === 1 ? 'list' : 'lists'} updated`
                    : 'Every list is already current',
            );
        } catch (e) {
            toast.fail(message(e));
        } finally {
            setRefreshing(false);
        }
    };

    const save = async (name: string, url: string, existing: Filter | null) => {
        try {
            if (existing) {
                await api.setFilter(existing.url, whitelist, { name, url, enabled: existing.enabled });
                toast.ok(`Saved ${name}`);
            } else {
                await api.addFilter(name, url, whitelist);
                toast.ok(`Added ${name}`);
            }
            setEditing(undefined);
            await status.reload();
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>{whitelist ? 'Allowlists' : 'Blocklists'}</h1>
                <p>
                    {whitelist
                        ? 'A name matched by any of these lists resolves normally, whatever a blocklist says about it.'
                        : 'A name matched by any of these lists is blocked, unless an allowlist or a custom rule says otherwise.'}
                </p>
            </div>

            <Card
                actions={
                    <>
                        <button type="button" className="btn" disabled={refreshing} onClick={() => void refresh()}>
                            {refreshing ? (
                                <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2 }} />
                            ) : (
                                <IconRefresh size={15} />
                            )}
                            Update now
                        </button>
                        <button
                            type="button"
                            className="btn primary"
                            onClick={() => (whitelist ? setEditing({ filter: null }) : setAdding('pick'))}>
                            <IconPlus size={15} /> Add a {kind}
                        </button>
                    </>
                }>
                <Table
                    className="rows"
                    empty={`No ${kind} added yet.`}
                    head={
                        <>
                            <th style={{ width: 60 }}>On</th>
                            <th>List</th>
                            <th className="num">Rules</th>
                            <th>Last updated</th>
                            <th className="actions" />
                        </>
                    }>
                    {rows.map((f) => (
                        <tr key={f.url}>
                            <td data-label="Enabled">
                                <input
                                    type="checkbox"
                                    checked={f.enabled}
                                    aria-label={f.name}
                                    style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
                                    onChange={() => void toggle(f)}
                                />
                            </td>
                            <td data-label="List">
                                <div style={{ minWidth: 0 }}>
                                    <div>{f.name}</div>
                                    <a className="mono muted truncate" href={f.url} target="_blank" rel="noreferrer">
                                        {f.url}
                                    </a>
                                </div>
                            </td>
                            <td className="num" data-label="Rules">
                                {num(f.rules_count)}
                            </td>
                            <td className="muted" data-label="Updated">
                                {formatDate(f.last_updated) || 'never'}
                            </td>
                            <td className="actions">
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Edit ${f.name}`}
                                    onClick={() => setEditing({ filter: f })}>
                                    <IconEdit size={16} />
                                </button>
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Remove ${f.name}`}
                                    onClick={() => void remove(f)}>
                                    <IconTrash size={16} />
                                </button>
                            </td>
                        </tr>
                    ))}
                </Table>
            </Card>

            {!whitelist && <CheckHost />}

            {adding === 'pick' && (
                <Modal title="Add a blocklist" onClose={() => setAdding(null)}>
                    <p className="card-desc">
                        Pick from the lists Sift knows about, or point it at one of your own.
                    </p>
                    <div className="btn-row">
                        <button type="button" className="btn primary" onClick={() => setAdding('choose')}>
                            Choose from the list
                        </button>
                        <button
                            type="button"
                            className="btn"
                            onClick={() => {
                                setAdding(null);
                                setEditing({ filter: null });
                            }}>
                            Add your own
                        </button>
                    </div>
                </Modal>
            )}

            {adding === 'choose' && (
                <Chooser
                    existing={rows}
                    onClose={() => setAdding(null)}
                    onDone={async () => {
                        setAdding(null);
                        await status.reload();
                    }}
                />
            )}

            {editing && (
                <Editor filter={editing.filter} kind={kind} onClose={() => setEditing(undefined)} onSave={save} />
            )}
        </>
    );
}

/**
 * The catalogue picker.
 *
 * A list already added is shown ticked and fixed: removing one is the table's
 * job, and a checkbox that sometimes deletes is a checkbox nobody trusts.
 * Saving adds the newly ticked lists one at a time, because that is what the
 * API takes -- and reports what it managed, since a failure part way through
 * still leaves the earlier ones added.
 */
function Chooser({
    existing,
    onClose,
    onDone,
}: {
    existing: Filter[];
    onClose: () => void;
    onDone: () => Promise<void>;
}) {
    const toast = useToast();
    const catalogue = useAsync(() => api.getBlocklistCatalogue());
    const [picked, setPicked] = useState<string[]>([]);
    const [query, setQuery] = useState('');
    const [tags, setTags] = useState<string[]>([]);
    const [busy, setBusy] = useState(false);

    const added = new Set(existing.map((f) => f.url));
    const countryNames = catalogue.data?.countries ?? {};
    const toggleTag = (t: string) =>
        setTags((v) => (v.includes(t) ? v.filter((x) => x !== t) : [...v, t]));

    const groups = useMemo(() => {
        const all = catalogue.data?.filters ?? [];
        const q = query.trim().toLowerCase();
        // Tags widen, the search narrows: picking `malware` and `phishing`
        // asks for either, which is how someone shopping for a security list
        // thinks.  The text box then narrows whatever that produced.
        const matching = all.filter(
            (f) =>
                (tags.length === 0 || (f.tags ?? []).some((t) => tags.includes(t))) &&
                (!q || f.name.toLowerCase().includes(q) || (f.note ?? '').toLowerCase().includes(q)),
        );

        const order = (catalogue.data?.categories ?? []).map((c) => c.id);
        const byCategory = new Map<string, CatalogueEntry[]>();
        for (const f of matching) {
            const list = byCategory.get(f.category_id);
            if (list) {
                list.push(f);
            } else {
                byCategory.set(f.category_id, [f]);
            }
        }

        const known = order.filter((id) => byCategory.has(id));
        const rest = [...byCategory.keys()].filter((id) => !order.includes(id)).sort();

        return [...known, ...rest].map((id) => ({
            id,
            ...(CATEGORIES[id] ?? { name: id, desc: '' }),
            entries: byCategory.get(id) ?? [],
        }));
    }, [catalogue.data, query, tags]);

    const toggle = (id: string) =>
        setPicked((v) => (v.includes(id) ? v.filter((x) => x !== id) : [...v, id]));

    const save = async () => {
        const entries = (catalogue.data?.filters ?? []).filter((f) => picked.includes(f.id));
        setBusy(true);

        let ok = 0;
        const failed: string[] = [];
        for (const f of entries) {
            try {
                await api.addFilter(f.name, f.url, false);
                ok += 1;
            } catch {
                failed.push(f.name);
            }
        }
        setBusy(false);

        if (ok > 0) {
            toast.ok(`Added ${ok} ${ok === 1 ? 'list' : 'lists'}`);
        }
        if (failed.length > 0) {
            toast.fail(`Could not add ${failed.join(', ')}`);
        }

        await onDone();
    };

    return (
        <Modal
            title="Choose blocklists"
            onClose={onClose}
            wide
            footer={
                <>
                    <span className="muted" style={{ marginRight: 'auto' }}>
                        {picked.length} selected
                    </span>
                    <button type="button" className="btn" onClick={onClose}>
                        Cancel
                    </button>
                    <button
                        type="button"
                        className="btn primary"
                        disabled={busy || picked.length === 0}
                        onClick={() => void save()}>
                        {busy && <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2 }} />}
                        Add selected
                    </button>
                </>
            }>
            {catalogue.error && <Notice kind="error">{catalogue.error}</Notice>}
            {!catalogue.data ? (
                <Loading />
            ) : (
                <>
                    <div style={{ position: 'relative', marginBottom: 10 }}>
                        <IconSearch
                            size={15}
                            style={{ position: 'absolute', left: 9, top: 9, color: 'var(--text-faint)' }}
                        />
                        <input
                            type="search"
                            value={query}
                            autoFocus
                            placeholder="Find a list"
                            style={{ paddingLeft: 30 }}
                            onChange={(e) => setQuery(e.target.value)}
                        />
                    </div>

                    <div className="tag-filter">
                        {[...(catalogue.data.tags ?? [])].sort(byImportance).map((t) => (
                            <Chip key={t} tag={t} on={tags.includes(t)} onClick={() => toggleTag(t)} />
                        ))}
                    </div>

                    {/* Countries get their own row: mixed in with the rest they
                        read as noise, and a flag is easier to find in a line of
                        flags. */}
                    <div className="tag-filter countries">
                        {Object.entries(catalogue.data.countries ?? {}).map(([code, name]) => (
                            <Chip
                                key={code}
                                tag={code}
                                label={`${flag(code)} ${name}`}
                                on={tags.includes(code)}
                                onClick={() => toggleTag(code)}
                            />
                        ))}
                        {tags.length > 0 && (
                            <button type="button" className="btn ghost sm" onClick={() => setTags([])}>
                                Clear {tags.length}
                            </button>
                        )}
                    </div>

                    {groups.map((g) => (
                        <section key={g.id} className="service-group">
                            <div className="service-group-head">
                                <h3>{g.name}</h3>
                                <div className="spacer" />
                            </div>
                            {g.desc && <p className="card-desc">{g.desc}</p>}

                            {g.entries.map((f) => {
                                const have = added.has(f.url);

                                return (
                                    <label key={f.id} className="check">
                                        <input
                                            type="checkbox"
                                            checked={have || picked.includes(f.id)}
                                            disabled={have}
                                            onChange={() => toggle(f.id)}
                                        />
                                        <span className="text">
                                            <span className="catalogue-name">
                                                <b>{f.name}</b>
                                                {/* The links stop the click here: the whole row is a
                                                    label, so without it following one would tick the
                                                    box on the way out. */}
                                                {f.homepage && (
                                                    <a
                                                        href={f.homepage}
                                                        target="_blank"
                                                        rel="noreferrer"
                                                        title={`About ${f.name}`}
                                                        onClick={(e) => e.stopPropagation()}>
                                                        <IconExternal size={14} />
                                                    </a>
                                                )}
                                                {have && <span className="badge grey">added</span>}
                                            </span>
                                            {f.note && <div className="hint">{f.note}</div>}
                                            {((f.tags ?? []).length > 0 || f.rules > 0) && (
                                            <div className="catalogue-tags">
                                                {[...(f.tags ?? [])].sort(byImportance).map((t) => (
                                                    <span
                                                        key={t}
                                                        className={`tag static ${TONES[t] ? `tone-${TONES[t]}` : ''}`}>
                                                        {countryNames[t] ? `${flag(t)} ${countryNames[t]}` : t}
                                                    </span>
                                                ))}
                                                {f.rules > 0 && <span className="muted">{num(f.rules)} rules</span>}
                                            </div>
                                            )}
                                            <a
                                                className="hint mono truncate"
                                                href={f.url}
                                                target="_blank"
                                                rel="noreferrer"
                                                title={`Open ${f.url}`}
                                                onClick={(e) => e.stopPropagation()}>
                                                {f.url}
                                            </a>
                                        </span>
                                    </label>
                                );
                            })}
                        </section>
                    ))}

                    {groups.length === 0 && (
                        <div className="empty">No list matches that search and those tags.</div>
                    )}
                </>
            )}
        </Modal>
    );
}

function Chip({ tag, label, on, onClick }: { tag: string; label?: string; on: boolean; onClick: () => void }) {
    const tone = TONES[tag];

    return (
        <button
            type="button"
            className={`tag ${tone ? `tone-${tone}` : ''} ${on ? 'on' : ''}`}
            aria-pressed={on}
            onClick={onClick}>
            {label ?? tag}
        </button>
    );
}

function Editor({
    filter,
    kind,
    onClose,
    onSave,
}: {
    filter: Filter | null;
    kind: string;
    onClose: () => void;
    onSave: (name: string, url: string, existing: Filter | null) => Promise<void>;
}) {
    const [name, setName] = useState(filter?.name ?? '');
    const [url, setUrl] = useState(filter?.url ?? '');
    const [busy, setBusy] = useState(false);

    return (
        <Modal
            title={filter ? `Edit ${filter.name}` : `Add a ${kind}`}
            onClose={onClose}
            footer={
                <>
                    <button type="button" className="btn" onClick={onClose}>
                        Cancel
                    </button>
                    <button
                        type="button"
                        className="btn primary"
                        disabled={busy || !name.trim() || !url.trim()}
                        onClick={async () => {
                            setBusy(true);
                            try {
                                await onSave(name.trim(), url.trim(), filter);
                            } finally {
                                setBusy(false);
                            }
                        }}>
                        Save
                    </button>
                </>
            }>
            <Field label="Name">
                <input value={name} autoFocus placeholder="A name you will recognise" onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Address" hint="An https:// URL, or an absolute path to a file on this machine.">
                <input value={url} placeholder="https://example.org/list.txt" onChange={(e) => setUrl(e.target.value)} />
            </Field>
        </Modal>
    );
}

/** The "would this name be blocked?" tool, which is its own endpoint. */
function CheckHost() {
    const [host, setHost] = useState('');
    const [result, setResult] = useState<CheckHostResult>();
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string>();

    const run = async (e: React.FormEvent) => {
        e.preventDefault();
        setBusy(true);
        setError(undefined);
        try {
            setResult(await api.checkHost(host.trim()));
        } catch (err) {
            setError(message(err));
        } finally {
            setBusy(false);
        }
    };

    const blocked = result?.reason.startsWith('Filtered');

    return (
        <Card title="Test a name" desc="Runs a name through the filters without querying anything.">
            <form className="row" onSubmit={run}>
                <input
                    style={{ flex: 1, minWidth: 220 }}
                    value={host}
                    placeholder="example.org"
                    onChange={(e) => setHost(e.target.value)}
                />
                <button type="submit" className="btn primary" disabled={busy || !host.trim()}>
                    Check
                </button>
            </form>

            {error && <Notice kind="error">{error}</Notice>}

            {result && (
                <div className={`notice ${blocked ? 'error' : 'ok'}`} style={{ marginTop: 14 }}>
                    <div>
                        <div>{blocked ? 'Blocked' : 'Allowed'} — {result.reason}</div>
                        {result.rule && <div className="mono">Matched {result.rule}</div>}
                        {result.service_name && <div>Service: {result.service_name}</div>}
                        {result.cname && <div>Follows the alias {result.cname}</div>}
                        {result.ip_addrs && result.ip_addrs.length > 0 && (
                            <div>Would answer {result.ip_addrs.join(', ')}</div>
                        )}
                    </div>
                </div>
            )}
        </Card>
    );
}
