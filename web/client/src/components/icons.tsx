/**
 * The icon set, inline.
 *
 * Every glyph is a 24×24 stroked path from the same grid, so they line up at
 * any size and inherit `currentColor`.  Inline rather than a sprite or a font
 * because there are two dozen of them and none is worth a request.
 */
import type { SVGProps } from 'react';

type Props = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 18, children, ...rest }: Props) {
    return (
        <svg
            width={size}
            height={size}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            {...rest}>
            {children}
        </svg>
    );
}

export const IconDashboard = (p: Props) => (
    <Icon {...p}>
        <rect x="3" y="3" width="7" height="8" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="14" y="11" width="7" height="10" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
    </Icon>
);

export const IconLog = (p: Props) => (
    <Icon {...p}>
        <path d="M4 5h16M4 10h16M4 15h11M4 20h7" />
    </Icon>
);

export const IconGuide = (p: Props) => (
    <Icon {...p}>
        <path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H19v15H6.5A2.5 2.5 0 0 0 4 20.5z" />
        <path d="M4 20.5A2.5 2.5 0 0 1 6.5 18H19v3H6.5" />
    </Icon>
);

export const IconSettings = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 9 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z" />
    </Icon>
);

export const IconDns = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18" />
    </Icon>
);

export const IconLock = (p: Props) => (
    <Icon {...p}>
        <rect x="4" y="10" width="16" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </Icon>
);

export const IconClients = (p: Props) => (
    <Icon {...p}>
        <circle cx="9" cy="8" r="3.2" />
        <path d="M3 20a6 6 0 0 1 12 0" />
        <path d="M16.5 5.4a3.2 3.2 0 0 1 0 5.2M18 14.2a6 6 0 0 1 3 5.8" />
    </Icon>
);

export const IconShield = (p: Props) => (
    <Icon {...p}>
        <path d="M12 3l7.5 3v5.6c0 4.4-3 8.3-7.5 9.4-4.5-1.1-7.5-5-7.5-9.4V6z" />
    </Icon>
);

export const IconBlock = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M5.6 5.6l12.8 12.8" />
    </Icon>
);

export const IconAllow = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12.2l2.7 2.7L16 9.6" />
    </Icon>
);

export const IconRewrite = (p: Props) => (
    <Icon {...p}>
        <path d="M4 7h11l-3-3M20 17H9l3 3" />
    </Icon>
);

export const IconRules = (p: Props) => (
    <Icon {...p}>
        <path d="M9 4h9a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9" />
        <path d="M4 4h4v4H4zM9 10h7M9 15h7" />
    </Icon>
);

export const IconServices = (p: Props) => (
    <Icon {...p}>
        <rect x="3" y="3" width="7.5" height="7.5" rx="1.6" />
        <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.6" />
        <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.6" />
        <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.6" />
    </Icon>
);

export const IconPlus = (p: Props) => (
    <Icon {...p}>
        <path d="M12 5v14M5 12h14" />
    </Icon>
);

export const IconEdit = (p: Props) => (
    <Icon {...p}>
        <path d="M4 20h4l10-10a2.8 2.8 0 0 0-4-4L4 16z" />
    </Icon>
);

export const IconTrash = (p: Props) => (
    <Icon {...p}>
        <path d="M4 7h16M10 11v6M14 11v6" />
        <path d="M6 7l1 13h10l1-13M9 7V4h6v3" />
    </Icon>
);

export const IconRefresh = (p: Props) => (
    <Icon {...p}>
        <path d="M20 12a8 8 0 1 1-2.6-5.9M20 4v4h-4" />
    </Icon>
);

export const IconSearch = (p: Props) => (
    <Icon {...p}>
        <circle cx="11" cy="11" r="6.5" />
        <path d="M16 16l4.5 4.5" />
    </Icon>
);

export const IconClose = (p: Props) => (
    <Icon {...p}>
        <path d="M6 6l12 12M18 6L6 18" />
    </Icon>
);

export const IconChevron = (p: Props) => (
    <Icon {...p}>
        <path d="M6 9l6 6 6-6" />
    </Icon>
);

export const IconSun = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </Icon>
);

export const IconMoon = (p: Props) => (
    <Icon {...p}>
        <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" />
    </Icon>
);

export const IconGlobe = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M3.5 9h17M3.5 15h17M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18" />
    </Icon>
);

export const IconUser = (p: Props) => (
    <Icon {...p}>
        <circle cx="12" cy="8" r="3.5" />
        <path d="M5 20a7 7 0 0 1 14 0" />
    </Icon>
);

export const IconMenu = (p: Props) => (
    <Icon {...p}>
        <path d="M4 7h16M4 12h16M4 17h16" />
    </Icon>
);

export const IconExternal = (p: Props) => (
    <Icon {...p}>
        <path d="M14 4h6v6M20 4l-8 8" />
        <path d="M18 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
    </Icon>
);

export const IconDownload = (p: Props) => (
    <Icon {...p}>
        <path d="M12 4v11M8 11l4 4 4-4M4 20h16" />
    </Icon>
);

/** The mark in the sidebar and on the login card: a funnel, for a sift. */
export const Logo = ({ size = 22 }: { size?: number }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path
            d="M3.5 4.5h17L14 12.6V20l-4 1.5v-8.9z"
            stroke="var(--accent)"
            strokeWidth="1.8"
            strokeLinejoin="round"
        />
        <circle cx="12" cy="8" r="1.4" fill="var(--accent)" />
    </svg>
);
