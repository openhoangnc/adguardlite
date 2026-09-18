/**
 * The ECharts wrapper.
 *
 * Only the pieces the dashboard draws are imported, so the bundle carries one
 * line chart rather than the whole library.
 *
 * Colours come from the stylesheet's tokens rather than an ECharts theme:
 * `cssVar` reads them at paint time, and the observer below redraws when the
 * document's theme attribute changes, which is the only time they move.
 */
import { useEffect, useRef, useState } from 'react';

import { LineChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import type { EChartsOption } from 'echarts';

echarts.use([
    LineChart,
    GridComponent,
    TooltipComponent,
    LegendComponent,
    CanvasRenderer,
]);

/** Reads one of the stylesheet's colour tokens. */
export function cssVar(name: string): string {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Bumps whenever the document switches between the light and dark themes. */
export function useThemeTick(): number {
    const [tick, setTick] = useState(0);

    useEffect(() => {
        const obs = new MutationObserver(() => setTick((t) => t + 1));
        obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

        return () => obs.disconnect();
    }, []);

    return tick;
}

/** The axis, tooltip and text styling every chart here shares. */
export function baseOption(): EChartsOption {
    const text = cssVar('--text-muted');
    const line = cssVar('--border');

    return {
        textStyle: { color: text, fontFamily: 'inherit' },
        tooltip: {
            backgroundColor: cssVar('--surface'),
            borderColor: cssVar('--border'),
            textStyle: { color: cssVar('--text') },
            extraCssText: 'box-shadow: var(--shadow-lg); border-radius: 8px;',
        },
        // `outerBoundsMode: 'same'` is ECharts 6's replacement for the
        // deprecated `containLabel`: the axis labels are kept inside the rect
        // the margins below describe, rather than spilling out of the canvas.
        grid: { left: 8, right: 12, top: 28, bottom: 4, outerBoundsMode: 'same', outerBoundsContain: 'axisLabel' },
        xAxis: {
            axisLine: { lineStyle: { color: line } },
            axisTick: { show: false },
            axisLabel: { color: text },
            splitLine: { show: false },
        },
        yAxis: {
            axisLine: { show: false },
            axisTick: { show: false },
            axisLabel: { color: text },
            splitLine: { lineStyle: { color: line } },
        },
    };
}

export function Chart({
    option,
    className = 'chart',
    empty,
}: {
    option: EChartsOption;
    className?: string;
    empty?: boolean;
}) {
    const host = useRef<HTMLDivElement>(null);
    const tick = useThemeTick();

    useEffect(() => {
        if (!host.current || empty) {
            return;
        }

        const chart = echarts.init(host.current, undefined, { renderer: 'canvas' });
        chart.setOption(option, true);

        const ro = new ResizeObserver(() => chart.resize());
        ro.observe(host.current);

        return () => {
            ro.disconnect();
            chart.dispose();
        };
    }, [option, tick, empty]);

    if (empty) {
        return <div className={`${className} empty`}>No data yet.</div>;
    }

    return <div className={className} ref={host} />;
}
