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

const PATH_TO_TAB: Record<string, TabKey> = Object.fromEntries(
    (Object.entries(ROUTES) as [TabKey, string][]).map(([tab, path]) => [path, tab]),
);

/** Resolve a URL pathname back to its tab key, defaulting to 'metrics'. */
export function tabForPath(pathname: string): TabKey {
    return PATH_TO_TAB[pathname] ?? 'metrics';
}
