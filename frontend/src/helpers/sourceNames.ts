/** Canonical mapping from backend source keys to display names. */
export const SOURCE_DISPLAY_NAMES: Record<string, string> = {
    openvex: 'OpenVex',
    local_user_data: 'Local User Data',
    yocto: 'Yocto',
    grype: 'Grype',
    cyclonedx: 'CycloneDx',
    spdx3: 'SPDX3',
    nvd_cpe: 'NVD CPE',
    osv: 'OSV',
};

/** Reverse mapping: display name → backend key. */
export const SOURCE_KEYS: Record<string, string> = Object.fromEntries(
    Object.entries(SOURCE_DISPLAY_NAMES).map(([k, v]) => [v, k])
);

/** Convert a backend source key to its human-readable display name. */
export const formatSourceName = (source: string): string =>
    SOURCE_DISPLAY_NAMES[source] ?? source;

/** Convert a display name back to the original backend source key. */
export const getOriginalSourceName = (displayName: string): string =>
    SOURCE_KEYS[displayName] ?? displayName;
