/**
 * Parse a package ID string using the `name@version::supplier` convention.
 * Returns the name+version part and the supplier part separately.
 */
export function splitPkgId(id: string): { nameVersion: string; supplier: string } {
    const sepIdx = id.indexOf('::');
    if (sepIdx === -1) return { nameVersion: id, supplier: '' };
    return { nameVersion: id.slice(0, sepIdx), supplier: id.slice(sepIdx + 2) };
}

/**
 * Extract the display name from a supplier string, stripping the SPDX-style
 * "Organization: " / "Person: " prefix and any trailing parenthetical (e.g. email).
 */
export function extractSupplierName(supplier: string): string {
    return supplier.replace(/^[^:]+:\s*/, '').replace(/\s*\([^)]*\)$/, '');
}

/**
 * Format a package ID for display, always showing supplier name (falling back to 'unknown supplier').
 */
export function formatPkgId(id: string): string {
    const { nameVersion, supplier } = splitPkgId(id);
    const supplierName = supplier ? extractSupplierName(supplier) : '';
    return `${nameVersion} (${supplierName || 'unknown supplier'})`;
}
