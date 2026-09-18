import { useState } from 'react';

import * as api from '../../api';
import type { QueryLogConfig, SafeSearchConfig, StatsConfig } from '../../api';
import { Card, Check, Field, Loading, Notice, SaveButton, useToast } from '../../components/ui';
import { DAY_MS, lines, unlines } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

/** How often lists are refreshed, in the hours the API counts them in. */
const FILTER_INTERVALS = [
    { value: 0, label: 'Never' },
    { value: 1, label: 'Every hour' },
    { value: 12, label: 'Every 12 hours' },
    { value: 24, label: 'Every day' },
    { value: 72, label: 'Every 3 days' },
    { value: 168, label: 'Every week' },
];

/** How long the log and the statistics are kept, in milliseconds. */
const RETENTION = [
    { value: 6 * 3600_000, label: '6 hours' },
    { value: DAY_MS, label: '24 hours' },
    { value: 7 * DAY_MS, label: '7 days' },
    { value: 30 * DAY_MS, label: '30 days' },
    { value: 90 * DAY_MS, label: '90 days' },
];

/** The search engines safe search can be enforced on. */
const ENGINES: { key: keyof SafeSearchConfig; label: string }[] = [
    { key: 'bing', label: 'Bing' },
    { key: 'duckduckgo', label: 'DuckDuckGo' },
    { key: 'ecosia', label: 'Ecosia' },
    { key: 'google', label: 'Google' },
    { key: 'pixabay', label: 'Pixabay' },
    { key: 'yandex', label: 'Yandex' },
    { key: 'youtube', label: 'YouTube' },
];

export default function General() {
    const toast = useToast();

    const all = useAsync(async () => {
        const [filtering, safeSearch, log, stats] = await Promise.all([
            api.getFilteringStatus(),
            api.getSafeSearch(),
            api.getQueryLogConfig(),
            api.getStatsConfig(),
        ]);

        return { filtering, safeSearch, log, stats };
    });

    if (!all.data) {
        return all.error ? <Notice kind="error">{all.error}</Notice> : <Loading />;
    }

    const d = all.data;

    const guard = async (run: () => Promise<void>, ok: string) => {
        try {
            await run();
            await all.reload();
            toast.ok(ok);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>General settings</h1>
            </div>

            <Card title="Filtering">
                <Check
                    checked={d.filtering.enabled}
                    label="Block domains with filter lists and rules"
                    hint="Every query is matched against the enabled blocklists and your own custom rules before it is sent anywhere."
                    onChange={(v) =>
                        void guard(
                            () => api.setFilteringConfig(v, d.filtering.interval),
                            v ? 'Filtering is on' : 'Filtering is off',
                        )
                    }
                />
                <Field label="Check lists for updates">
                    <select
                        value={d.filtering.interval}
                        style={{ maxWidth: 260 }}
                        onChange={(e) =>
                            void guard(
                                () => api.setFilteringConfig(d.filtering.enabled, Number(e.target.value)),
                                'Update interval saved',
                            )
                        }>
                        {FILTER_INTERVALS.map((o) => (
                            <option key={o.value} value={o.value}>
                                {o.label}
                            </option>
                        ))}
                    </select>
                </Field>
            </Card>

            <SafeSearch value={d.safeSearch} onSaved={all.reload} />
            <LogAndStats log={d.log} stats={d.stats} onSaved={all.reload} />
        </>
    );
}

function SafeSearch({ value, onSaved }: { value: SafeSearchConfig; onSaved: () => Promise<void> }) {
    const toast = useToast();
    const [draft, setDraft] = useState(value);

    const save = async (next: SafeSearchConfig) => {
        setDraft(next);
        try {
            await api.setSafeSearch(next);
            await onSaved();
            toast.ok('Safe search saved');
        } catch (e) {
            setDraft(value);
            toast.fail(message(e));
        }
    };

    return (
        <Card
            title="Safe search"
            desc="Rewrites searches to the family-safe address each engine publishes, for every client on the network.">
            <Check
                checked={draft.enabled}
                label="Enforce safe search"
                onChange={(v) => void save({ ...draft, enabled: v })}
            />
            {ENGINES.map((e) => (
                <Check
                    key={e.key}
                    checked={Boolean(draft[e.key])}
                    disabled={!draft.enabled}
                    label={e.label}
                    onChange={(v) => void save({ ...draft, [e.key]: v })}
                />
            ))}
        </Card>
    );
}

function LogAndStats({
    log,
    stats,
    onSaved,
}: {
    log: QueryLogConfig;
    stats: StatsConfig;
    onSaved: () => Promise<void>;
}) {
    const toast = useToast();
    const [l, setL] = useState(log);
    const [s, setS] = useState(stats);

    const saveLog = async () => {
        try {
            await api.updateQueryLogConfig({
                enabled: l.enabled,
                interval: l.interval,
                anonymize_client_ip: l.anonymize_client_ip,
                ignored: l.ignored ?? [],
            });
            await onSaved();
            toast.ok('Query log settings saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const saveStats = async () => {
        try {
            await api.updateStatsConfig({ enabled: s.enabled, interval: s.interval, ignored: s.ignored ?? [] });
            await onSaved();
            toast.ok('Statistics settings saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <Card title="Query log">
                <Check checked={l.enabled} label="Record every query" onChange={(v) => setL({ ...l, enabled: v })} />
                <Check
                    checked={l.anonymize_client_ip}
                    label="Anonymise client addresses"
                    hint="Drops the last part of each address before it is written to the log or the statistics."
                    onChange={(v) => setL({ ...l, anonymize_client_ip: v })}
                />
                <Field label="Keep entries for">
                    <select
                        value={l.interval}
                        style={{ maxWidth: 260 }}
                        onChange={(e) => setL({ ...l, interval: Number(e.target.value) })}>
                        {RETENTION.map((o) => (
                            <option key={o.value} value={o.value}>
                                {o.label}
                            </option>
                        ))}
                    </select>
                </Field>
                <Field
                    label="Domains to leave out"
                    hint="One per line. A query matching any of these is answered as usual but never written down.">
                    <textarea
                        value={unlines(l.ignored)}
                        spellCheck={false}
                        onChange={(e) => setL({ ...l, ignored: lines(e.target.value) })}
                    />
                </Field>
                <SaveButton onClick={saveLog}>Save</SaveButton>
            </Card>

            <Card title="Statistics">
                <Check checked={s.enabled} label="Collect statistics" onChange={(v) => setS({ ...s, enabled: v })} />
                <Field label="Keep statistics for">
                    <select
                        value={s.interval}
                        style={{ maxWidth: 260 }}
                        onChange={(e) => setS({ ...s, interval: Number(e.target.value) })}>
                        {RETENTION.map((o) => (
                            <option key={o.value} value={o.value}>
                                {o.label}
                            </option>
                        ))}
                    </select>
                </Field>
                <Field label="Domains to leave out" hint="One per line. These are counted nowhere on the dashboard.">
                    <textarea
                        value={unlines(s.ignored)}
                        spellCheck={false}
                        onChange={(e) => setS({ ...s, ignored: lines(e.target.value) })}
                    />
                </Field>
                <SaveButton onClick={saveStats}>Save</SaveButton>
            </Card>
        </>
    );
}
