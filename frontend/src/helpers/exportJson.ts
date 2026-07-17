/**
 * Sanitize a string for use in a filename: replace whitespace with underscores,
 * strip characters that are problematic in filenames.
 */
export function sanitizeFilename(name: string): string {
    return name
        .replace(/\s+/g, '_')
        .replace(/[<>:"/\\|?*]+/g, '')
        .replace(/_+/g, '_')
        .replace(/^_|_$/g, '');
}

/**
 * Format a Date (or current time) as YYYYMMDD_HHmmss for use in filenames.
 */
export function formatTimestampForFilename(date?: Date | string): string {
    const d = date ? new Date(date) : new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

/**
 * Trigger a JSON file download in the browser.
 */
export function downloadJson(data: unknown, filename: string): void {
    const json = JSON.stringify(data, null, 2);
    downloadBlob(new Blob([json], { type: 'application/json' }), filename);
}

/** Trigger a download for a response body that is already encoded. */
export function downloadBlob(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
}
