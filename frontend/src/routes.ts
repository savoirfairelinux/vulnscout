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

/**
 * Resolve a URL pathname back to its tab key, or `UNKNOWN_ROUTE` when no
 * route owns it. Callers gating dashboard-only UI must check for 'metrics'
 * explicitly rather than relying on a fallback.
 */
export function tabForPath(pathname: string): RouteKey {
    return PATH_TO_TAB[normalizeRoutePath(pathname)] ?? UNKNOWN_ROUTE;
}
