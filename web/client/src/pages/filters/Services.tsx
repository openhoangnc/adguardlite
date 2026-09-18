import { useEffect, useMemo, useState } from 'react';

import * as api from '../../api';
import type { BlockedService, DayRange, Schedule, Weekday } from '../../api';
import { WEEKDAYS } from '../../api';
import { Card, Field, Loading, Notice, SaveButton, Switch, useToast } from '../../components/ui';
import { IconSearch } from '../../components/icons';
import { clock, unclock } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

/**
 * What each group of services is called.
 *
 * The catalogue carries the identifiers and no names -- upstream keeps those
 * in its translation files -- so the wording is this project's.  A group the
 * catalogue grows later falls back to its own identifier rather than
 * disappearing.
 */
const GROUP_NAMES: Record<string, string> = {
    ai: 'Artificial intelligence',
    cdn: 'Content delivery networks',
    dating: 'Dating',
    gambling: 'Gambling and betting',
    gaming: 'Games',
    hosting: 'Hosting and file sharing',
    messenger: 'Messaging',
    privacy: 'Privacy and security',
    shopping: 'Shopping',
    social_network: 'Social networks',
    software: 'Software and developer tools',
    streaming: 'Video and music',
};

const DAY_NAMES: Record<Weekday, string> = {
    sun: 'Sunday',
    mon: 'Monday',
    tue: 'Tuesday',
    wed: 'Wednesday',
    thu: 'Thursday',
    fri: 'Friday',
    sat: 'Saturday',
};

/** A day with no window: blocked around the clock. */
const NO_PAUSE: DayRange = { start: 0, end: 0 };

export default function Services() {
    const toast = useToast();
    const catalogue = useAsync(() => api.getServiceCatalogue());
    const current = useAsync(() => api.getBlockedServices());

    const [ids, setIds] = useState<string[]>([]);
    const [schedule, setSchedule] = useState<Schedule>({ time_zone: 'Local' });
    const [query, setQuery] = useState('');

    useEffect(() => {
        if (current.data) {
            setIds(current.data.ids ?? []);
            setSchedule(current.data.schedule ?? { time_zone: 'Local' });
        }
    }, [current.data]);

    /**
     * The catalogue, grouped and filtered.
     *
     * Group order follows the `groups` array the catalogue declares, with
     * anything whose group is unknown collected at the end, so a new group
     * appears rather than vanishing.
     */
    const groups = useMemo(() => {
        const all = catalogue.data?.blocked_services ?? [];
        const q = query.trim().toLowerCase();
        const matching = q ? all.filter((s) => s.name.toLowerCase().includes(q) || s.id.includes(q)) : all;

        const order = (catalogue.data?.groups ?? []).map((g) => g.id);
        const byGroup = new Map<string, BlockedService[]>();
        for (const s of matching) {
            const key = s.group_id ?? '';
            const list = byGroup.get(key);
            if (list) {
                list.push(s);
            } else {
                byGroup.set(key, [s]);
            }
        }

        const known = order.filter((id) => byGroup.has(id));
        const rest = [...byGroup.keys()].filter((id) => !order.includes(id)).sort();

        return [...known, ...rest].map((id) => ({
            id,
            name: GROUP_NAMES[id] ?? id ?? 'Other',
            services: byGroup.get(id) ?? [],
        }));
    }, [catalogue.data, query]);

    if (!catalogue.data || !current.data) {
        const err = catalogue.error ?? current.error;

        return err ? <Notice kind="error">{err}</Notice> : <Loading />;
    }

    const all = catalogue.data.blocked_services;
    const blocked = new Set(ids);

    const set = (next: Set<string>) => setIds([...next]);

    const toggle = (id: string) => {
        const next = new Set(blocked);
        if (next.has(id)) {
            next.delete(id);
        } else {
            next.add(id);
        }
        set(next);
    };

    const setMany = (services: BlockedService[], on: boolean) => {
        const next = new Set(blocked);
        for (const s of services) {
            if (on) {
                next.add(s.id);
            } else {
                next.delete(s.id);
            }
        }
        set(next);
    };

    const save = async () => {
        try {
            await api.updateBlockedServices({ ids, schedule });
            await current.reload();
            toast.ok('Blocked services saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>Blocked services</h1>
                <p>Block a whole service across every domain it uses, without hunting for the rules yourself.</p>
            </div>

            <Card
                actions={
                    <>
                        <span className="muted" style={{ marginRight: 8 }}>
                            {ids.length} of {all.length} blocked
                        </span>
                        <button type="button" className="btn sm" onClick={() => setMany(all, true)}>
                            Block all
                        </button>
                        <button type="button" className="btn sm" onClick={() => setMany(all, false)}>
                            Block none
                        </button>
                    </>
                }>
                <div style={{ position: 'relative', marginBottom: 18 }}>
                    <IconSearch
                        size={15}
                        style={{ position: 'absolute', left: 9, top: 9, color: 'var(--text-faint)' }}
                    />
                    <input
                        type="search"
                        value={query}
                        placeholder="Find a service"
                        style={{ paddingLeft: 30 }}
                        onChange={(e) => setQuery(e.target.value)}
                    />
                </div>

                {groups.map((g) => {
                    const on = g.services.filter((s) => blocked.has(s.id)).length;

                    return (
                        <section key={g.id} className="service-group">
                            <div className="service-group-head">
                                <h3>{g.name}</h3>
                                <span className="muted">
                                    {on} of {g.services.length}
                                </span>
                                <div className="spacer" />
                                <button
                                    type="button"
                                    className="btn ghost sm"
                                    onClick={() => setMany(g.services, true)}>
                                    Block all
                                </button>
                                <button
                                    type="button"
                                    className="btn ghost sm"
                                    onClick={() => setMany(g.services, false)}>
                                    Unblock all
                                </button>
                            </div>

                            <div className="service-grid">
                                {g.services.map((s) => (
                                    <ServiceTile
                                        key={s.id}
                                        service={s}
                                        checked={blocked.has(s.id)}
                                        onToggle={() => toggle(s.id)}
                                    />
                                ))}
                            </div>
                        </section>
                    );
                })}

                {groups.length === 0 && <div className="empty">No service matches.</div>}
            </Card>

            <ScheduleCard schedule={schedule} onChange={setSchedule} />

            <SaveButton onClick={save}>Save</SaveButton>
        </>
    );
}

function ServiceTile({
    service,
    checked,
    onToggle,
}: {
    service: BlockedService;
    checked: boolean;
    onToggle: () => void;
}) {
    return (
        <div className={`service ${checked ? 'on' : ''}`}>
            {service.icon_svg && (
                // Drawn as a mask rather than an <img>: the catalogue's icons
                // are `fill="currentColor"`, which inside an image resolves
                // against the image's own root and comes out black -- invisible
                // on the dark theme.  A mask paints the shape in the text
                // colour and runs nothing from the file.
                <span
                    className="service-icon"
                    style={{ ['--icon' as string]: `url("data:image/svg+xml;base64,${service.icon_svg}")` }}
                />
            )}
            <span className="truncate" title={service.name}>
                {service.name}
            </span>
            <div className="spacer" />
            <Switch checked={checked} onChange={onToggle} label={`Block ${service.name}`} />
        </div>
    );
}

/**
 * The pause schedule.
 *
 * A day's window says when the block is **lifted**, not when it applies, so a
 * day with no window is blocked around the clock.  The wording here follows
 * that rather than inverting it silently.
 */
function ScheduleCard({ schedule, onChange }: { schedule: Schedule; onChange: (s: Schedule) => void }) {
    const zones = useMemo(() => {
        try {
            return ['Local', ...Intl.supportedValuesOf('timeZone')];
        } catch {
            return ['Local', 'UTC'];
        }
    }, []);

    const setDay = (day: Weekday, range: DayRange | undefined) => {
        const next = { ...schedule };
        if (range) {
            next[day] = range;
        } else {
            delete next[day];
        }
        onChange(next);
    };

    return (
        <Card
            title="Pause the block"
            desc="Pick the hours each day when these services are reachable again. A day left unticked stays blocked around the clock.">
            <Field label="Time zone">
                <select
                    value={schedule.time_zone || 'Local'}
                    style={{ maxWidth: 340 }}
                    onChange={(e) => onChange({ ...schedule, time_zone: e.target.value })}>
                    {zones.map((z) => (
                        <option key={z} value={z}>
                            {z === 'Local' ? "Local (the server's own)" : z}
                        </option>
                    ))}
                </select>
            </Field>

            {WEEKDAYS.map((day) => {
                const range = schedule[day];

                return (
                    <div className="row" key={day} style={{ padding: '6px 0', borderTop: '1px solid var(--border)' }}>
                        <label className="row" style={{ width: 150, gap: 8 }}>
                            <input
                                type="checkbox"
                                checked={range !== undefined}
                                style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
                                onChange={(e) => setDay(day, e.target.checked ? { ...NO_PAUSE } : undefined)}
                            />
                            <b>{DAY_NAMES[day]}</b>
                        </label>
                        {range ? (
                            <>
                                <span className="muted">reachable from</span>
                                <input
                                    type="time"
                                    value={clock(range.start)}
                                    style={{ width: 'auto' }}
                                    onChange={(e) => setDay(day, { ...range, start: unclock(e.target.value) })}
                                />
                                <span className="muted">to</span>
                                <input
                                    type="time"
                                    value={clock(range.end)}
                                    style={{ width: 'auto' }}
                                    onChange={(e) => setDay(day, { ...range, end: unclock(e.target.value) })}
                                />
                            </>
                        ) : (
                            <span className="muted">blocked all day</span>
                        )}
                    </div>
                );
            })}
        </Card>
    );
}
