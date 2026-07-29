import {
    downloadBlob,
    downloadJson,
    formatTimestampForFilename,
    sanitizeFilename,
} from '../../src/helpers/exportJson';

describe('exportJson helpers', () => {
    const createObjectUrl = URL.createObjectURL;
    const revokeObjectUrl = URL.revokeObjectURL;

    beforeEach(() => {
        Object.defineProperty(URL, 'createObjectURL', {
            configurable: true,
            value: () => 'blob:vulnscout-export',
        });
        Object.defineProperty(URL, 'revokeObjectURL', {
            configurable: true,
            value: () => undefined,
        });
    });

    afterEach(() => {
        Object.defineProperty(URL, 'createObjectURL', {
            configurable: true,
            value: createObjectUrl,
        });
        Object.defineProperty(URL, 'revokeObjectURL', {
            configurable: true,
            value: revokeObjectUrl,
        });
    });

    test('sanitizes filenames and formats a supplied timestamp', () => {
        expect(sanitizeFilename(' Project: Alpha / report?.json ')).toBe('Project_Alpha_report.json');
        expect(formatTimestampForFilename(new Date(2026, 6, 28, 9, 5, 3))).toBe('20260728_090503');
    });

    test('downloads a pre-encoded blob with the requested filename', () => {
        let download = '';
        const captureDownload = (event: MouseEvent) => {
            event.preventDefault();
            download = (event.target as HTMLAnchorElement).download;
        };
        document.addEventListener('click', captureDownload);

        downloadBlob(new Blob(['export body'], { type: 'application/json' }), 'report.json');

        document.removeEventListener('click', captureDownload);
        expect(download).toBe('report.json');
        expect(document.querySelector('a[download="report.json"]')).toBeNull();
    });

    test('serializes JSON before initiating a download', () => {
        let download = '';
        const captureDownload = (event: MouseEvent) => {
            event.preventDefault();
            download = (event.target as HTMLAnchorElement).download;
        };
        document.addEventListener('click', captureDownload);

        downloadJson({ id: 'CVE-2026-0001' }, 'vulnerabilities.json');

        document.removeEventListener('click', captureDownload);
        expect(download).toBe('vulnerabilities.json');
    });
});