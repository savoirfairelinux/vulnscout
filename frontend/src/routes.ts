// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

/**
 * Single source of truth for the app's top-level page paths.
 * Keys mirror the historical tab identifiers used before routing was
 * introduced, so callers that used to pass a tab string to `setTab`
 * can keep doing so (now resolved to a URL via this table).
 */
export const ROUTES = {
    metrics: '/',
    packages: '/sbom',
    vulnerabilities: '/vulnerabilities',
    scans: '/scans',
    review: '/review',
    ai: '/ai-context',
    exports: '/export',
    settings: '/settings',
} as const;

export type TabKey = keyof typeof ROUTES;

/** Marks a pathname no route owns, i.e. the one rendering the 404 page. */
export const UNKNOWN_ROUTE = 'unknown';

/** A tab key, or `UNKNOWN_ROUTE` when the pathname matches no route. */
export type RouteKey = TabKey | typeof UNKNOWN_ROUTE;

const PATH_TO_TAB: Record<string, TabKey> = Object.fromEntries(
    (Object.entries(ROUTES) as [TabKey, string][]).map(([tab, path]) => [path, tab]),
);

/**
 * Drop trailing slashes (keeping the root path) so lookups agree with
 * react-router, which matches '/sbom/' against the '/sbom' route.
 */
export function normalizeRoutePath(pathname: string): string {
    const trimmed = pathname.replace(/\/+$/, '');
    return trimmed === '' ? '/' : trimmed;
}

export const SETTINGS_PATHS = {
    transfer: `${ROUTES.settings}/transfer`,
    customExport: `${ROUTES.settings}/custom-export`,
} as const;

export function settingsProjectPath(projectId: string): string {
    return `${ROUTES.settings}/${encodeURIComponent(projectId)}`;
}

export function settingsVariantPath(projectId: string, variantId: string): string {
    return `${settingsProjectPath(projectId)}/${encodeURIComponent(variantId)}`;
}

export type SettingsRoute =
    | { kind: 'general' }
    | { kind: 'transfer' }
    | { kind: 'custom-export' }
    | { kind: 'project'; projectId: string }
    | { kind: 'variant'; projectId: string; variantId: string }
    | { kind: 'unknown' };

/** Map a pathname under `/settings` to the settings view it renders. */
export function parseSettingsPath(pathname: string): SettingsRoute {
    const path = normalizeRoutePath(pathname);
    if (path === ROUTES.settings) return { kind: 'general' };
    if (!path.startsWith(`${ROUTES.settings}/`)) return { kind: 'unknown' };

    let segments: string[];
    try {
        segments = path.slice(ROUTES.settings.length + 1).split('/').map(decodeURIComponent);
    } catch {
        return { kind: 'unknown' };
    }
    if (segments.some((segment) => segment === '')) return { kind: 'unknown' };

    if (segments.length === 1) {
        if (segments[0] === 'transfer') return { kind: 'transfer' };
        if (segments[0] === 'custom-export') return { kind: 'custom-export' };
        return { kind: 'project', projectId: segments[0] };
    }
    if (segments.length === 2) {
        return { kind: 'variant', projectId: segments[0], variantId: segments[1] };
    }
    return { kind: 'unknown' };
}

/**
 * Resolve a URL pathname back to its tab key, or `UNKNOWN_ROUTE` when no
 * route owns it. Any path under `/settings/` belongs to the settings tab.
 * Callers gating dashboard-only UI must check for 'metrics'
 * explicitly rather than relying on a fallback.
 */
export function tabForPath(pathname: string): RouteKey {
    const path = normalizeRoutePath(pathname);
    if (path.startsWith(`${ROUTES.settings}/`)) return 'settings';
    return PATH_TO_TAB[path] ?? UNKNOWN_ROUTE;
}
