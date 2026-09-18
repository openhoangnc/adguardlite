import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import type { EChartsOption } from 'echarts';

import * as api from '../api';
import type { Stats, TopEntry } from '../api';
import { Chart, baseOption, cssVar, useThemeTick } from '../components/Chart';
import { Card, Loading, Notice, Table, useToast } from '../components/ui';
import { DAY_MS, millis, num, pair, percent, shortUpstream } from '../lib/format';
import { message, useAsync } from '../lib/hooks';

/** The windows the dashboard offers, as the milliseconds the API stores. */
const RANGES = [
    { ms: 6 * 3600_000, label: 'Last 6 hours' },
    { ms: DAY_MS, label: 'Last 24 hours' },
    { ms: 7 * DAY_MS, label: 'Last 7 days' },
    { ms: 30 * DAY_MS, label: 'Last 30 days' },
    { ms: 90 * DAY_MS, label: 'Last 90 days' },
];

/** The series the timeline draws, and the totals above it. */
const SERIES = [
    { key: 'dns_queries', total: 'num_dns_queries', label: 'Queries', colour: '--chart-5' },
    { key: 'blocked_filtering', total: 'num_blocked_filtering', label: 'Blocked by filters', colour: '--chart-2' },
] as const;

export default function Dashboard() {
    const toast = useToast();
    const stats = useAsync(() => api.getStats());
    const config = useAsync(() => api.getStatsConfig());

    const setRange = async (ms: number) => {
        try {
            await api.updateStatsConfig({ interval: ms, enabled: true });
            await Promise.all([config.reload(), stats.reload()]);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const reset = async () => {
        if (!window.confirm('Discard every statistic collected so far?')) {
            return;
        }

        try {
            await api.resetStats();
            await stats.reload();
            toast.ok('Statistics cleared');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    if (!stats.data || !config.data) {
        return stats.error ? <Notice kind="error">{stats.error}</Notice> : <Loading />;
    }

    const s = stats.data;

    return (
        <>
            <div className="page-head">
                <h1>Dashboard</h1>
                <div className="spacer" />
                <select
                    value={config.data.interval}
                    aria-label="Period"
                    style={{ width: 'auto' }}
                    onChange={(e) => void setRange(Number(e.target.value))}>
                    {RANGES.map((r) => (
                        <option key={r.ms} value={r.ms}>
                            {r.label}
                        </option>
                    ))}
                </select>
                <button type="button" className="btn" onClick={() => void reset()}>
                    Clear statistics
                </button>
            </div>

            {!config.data.enabled && (
                <Notice kind="warn">
                    Statistics are switched off, so this page has nothing to show. Turn them back on in{' '}
                    <Link to="/settings">General settings</Link>.
                </Notice>
            )}

            <Tiles s={s} />
            <Timeline s={s} />

            <div className="grid grid-2">
                <TopList
                    title="Most queried"
                    header="Domain"
                    rows={s.top_queried_domains}
                    total={s.num_dns_queries}
                    link
                />
                <TopList
                    title="Most blocked"
                    header="Domain"
                    rows={s.top_blocked_domains}
                    total={s.num_blocked_filtering}
                    tone="red"
                    link
                />
                <TopList title="Busiest clients" header="Client" rows={s.top_clients} total={s.num_dns_queries} link />
                <Upstreams s={s} />
            </div>
        </>
    );
}

/**
 * The series worth drawing.
 *
 * A category that has not blocked anything is left out of both the tiles and
 * the chart: a card reading zero and a line flat along the axis take up the
 * room the numbers that moved need, and say nothing the total does not.
 * Queries always stays, so the page is never empty.
 */
function active(s: Stats) {
    return SERIES.filter((x) => x.total === 'num_dns_queries' || s[x.total] > 0);
}

function Tiles({ s }: { s: Stats }) {
    const tiles = [
        ...active(s).map((x) => ({
            label: x.label,
            value: num(s[x.total]),
            sub: x.total === 'num_dns_queries' ? 'in this period' : percent(s[x.total], s.num_dns_queries),
            colour: `var(${x.colour})`,
        })),
        {
            label: 'Average response',
            value: millis(s.avg_processing_time),
            sub: 'time to answer a query',
            colour: 'var(--chart-1)',
        },
    ];

    return (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(152px, 1fr))', marginBottom: 16 }}>
            {tiles.map((x) => (
                <div className="tile" key={x.label} style={{ ['--tile-accent' as string]: x.colour }}>
                    <span className="label">{x.label}</span>
                    <span className="value">{x.value}</span>
                    <span className="sub truncate" title={x.sub}>
                        {x.sub}
                    </span>
                </div>
            ))}
        </div>
    );
}

/** The queries-over-time chart, which is the page's one picture. */
function Timeline({ s }: { s: Stats }) {
    const tick = useThemeTick();

    const option = useMemo<EChartsOption>(() => {
        const hourly = s.time_units === 'hours';
        const n = s.dns_queries.length;
        const now = Date.now();
        const step = hourly ? 3600_000 : DAY_MS;

        // The arrays run oldest first and end at the unit in progress.
        const labels = s.dns_queries.map((_, i) => {
            const at = new Date(now - (n - 1 - i) * step);

            return hourly
                ? at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
                : at.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        });

        const base = baseOption();
        const shown = active(s);

        return {
            ...base,
            // Room for two lines of legend: on a phone the names do not fit
            // across one, and ECharts does not move the plot down for a legend
            // that wrapped.
            grid: { ...base.grid, top: shown.length > 2 ? 52 : 34 },
            legend: { data: shown.map((x) => x.label), textStyle: { color: cssVar('--text-muted') }, top: 0 },
            tooltip: { ...base.tooltip, trigger: 'axis' },
            xAxis: { ...base.xAxis, type: 'category', boundaryGap: false, data: labels },
            yAxis: { ...base.yAxis, type: 'value', minInterval: 1 },
            series: shown.map((x) => {
                const colour = cssVar(x.colour);

                return {
                    name: x.label,
                    type: 'line',
                    smooth: 0.25,
                    showSymbol: false,
                    lineStyle: { width: 2, color: colour },
                    itemStyle: { color: colour },
                    areaStyle: { color: colour, opacity: 0.1 },
                    data: s[x.key],
                };
            }),
        } as EChartsOption;
    }, [s, tick]);

    return (
        <Card title="Queries over time">
            <Chart option={option} empty={s.dns_queries.length === 0 || s.num_dns_queries === 0} />
        </Card>
    );
}

/**
 * One of the four ranked lists.
 *
 * The bar is drawn as a layer behind the row's own text rather than as a cell
 * of its own, so a long name runs over it instead of being squeezed by it.
 */
function TopList({
    title,
    header,
    rows,
    total,
    tone = 'green',
    link,
}: {
    title: string;
    header: string;
    rows: TopEntry[];
    total: number;
    tone?: 'green' | 'red';
    link?: boolean;
}) {
    const max = rows.reduce((m, r) => Math.max(m, pair(r)[1]), 0);

    return (
        <Card title={title}>
            <Table
                empty="Nothing recorded in this period."
                head={
                    <>
                        <th>{header}</th>
                        <th className="num">Queries</th>
                    </>
                }>
                {rows.slice(0, 10).map((row) => {
                    const [name, count] = pair(row);

                    return (
                        <tr key={name}>
                            <td className="ranked">
                                <span
                                    className={`bar ${tone}`}
                                    aria-hidden="true"
                                    style={{ width: `${max ? (count / max) * 100 : 0}%` }}
                                />
                                <span className="name truncate" title={name}>
                                    {link ? (
                                        <Link to={`/logs?search=${encodeURIComponent(name)}`}>{name}</Link>
                                    ) : (
                                        name
                                    )}
                                </span>
                            </td>
                            <td className="num">
                                <div>{num(count)}</div>
                                <div className="muted" style={{ fontSize: 12 }}>
                                    {percent(count, total)}
                                </div>
                            </td>
                        </tr>
                    );
                })}
            </Table>
        </Card>
    );
}

/**
 * The upstream table.
 *
 * The two arrays the API returns -- answers per server and mean time per
 * server -- describe the same set, so they are joined into one row each
 * rather than shown as two lists.  A bar chart lived here and was the wrong
 * shape for a half-width card: its labels collided, and every bar needed its
 * value spelled out beside it anyway.
 */
function Upstreams({ s }: { s: Stats }) {
    const times = new Map(s.top_upstreams_avg_time.map(pair));
    const rows = s.top_upstreams_responses.map(pair);

    return (
        // Full width: an upstream's address is long, and squeezed into half a
        // row it ellipsises to the scheme.
        <Card title="Upstreams" className="span">
            <Table
                empty="No upstream has answered yet."
                head={
                    <>
                        <th>Server</th>
                        <th className="num">Answers</th>
                        <th className="num">Avg</th>
                    </>
                }>
                {rows.map(([name, count]) => {
                    const seconds = times.get(name);

                    return (
                        <tr key={name}>
                            <td className="mono clip" title={name}>
                                {shortUpstream(name)}
                            </td>
                            <td className="num">{num(count)}</td>
                            <td className="num">{seconds === undefined ? '—' : millis(seconds)}</td>
                        </tr>
                    );
                })}
            </Table>
        </Card>
    );
}
