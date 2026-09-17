import React, { memo } from 'react';
import cn from 'classnames';

import './logo.css';

type Props = {
    className?: string;
};

/**
 * The funnel: what a sieve does to a stream of queries.
 *
 * Drawn once here and reused for the icons, so the mark and the favicon
 * cannot drift apart.  Stroked in the lockup, where there is room for it;
 * filled in the icons, where a 2.8-unit stroke disappears at 16px.
 */
export const FUNNEL = 'M3 7h35L24.5 22v14l-8-4.6V22z';

/**
 * The Sift wordmark.
 *
 * Two parts, coloured separately: the lettering follows `currentColor` so a
 * theme only has to set `color`, and the funnel stays gold in both.
 *
 * The lettering is a `<text>` in the system UI stack rather than traced
 * outlines — it stays legible at any size, it is selectable and readable to a
 * screen reader, and changing it is editing a string.
 */
export const Logo = memo(({ className }: Props) => {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width="124"
            height="41"
            viewBox="0 0 124 41"
            role="img"
            aria-label="Sift"
            className={cn('logo', className)}>
            <path
                className="logo__mark"
                d={FUNNEL}
                fill="none"
                strokeWidth="2.8"
                strokeLinejoin="round"
                strokeLinecap="round"
            />
            <text className="logo__wordmark" x="52" y="29.5" fontSize="25" fontWeight="700" letterSpacing="2.5">
                SIFT
            </text>
        </svg>
    );
});

Logo.displayName = 'Logo';
