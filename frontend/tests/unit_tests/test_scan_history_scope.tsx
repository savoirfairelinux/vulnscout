import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';

import ScanHistory from '../../src/pages/ScanHistory';
import ScansHandler from '../../src/handlers/scans';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Variants from '../../src/handlers/variant';
import type { GlobalResult, Scan, ScanDiff } from '../../src/handlers/scans';
import { downloadJson } from '../../src/helpers/exportJson';
import Operations from '../../src/handlers/operations';
import { __reset, __setEventSourceFactory } from '../../src/handlers/operationStore';
import type { Operation } from '../../src/types/operation';

class TestEventSource {
    static current: TestEventSource;
    private handlers = new Map<string, (event: MessageEvent) => void>();

    constructor() { TestEventSource.current = this; }
    addEventListener(type: string, handler: EventListenerOrEventListenerObject) {
        this.handlers.set(type, handler as (event: MessageEvent) => void);
    }
    close() {}
    send(type: string, data: unknown) {
        act(() => this.handlers.get(type)?.({ data: JSON.stringify(data), lastEventId: 'epoch:1' } as MessageEvent));
    }
}

jest.mock('../../src/handlers/scans', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
        getDiff: jest.fn(),
        getGlobalResult: jest.fn(),
        setDescription: jest.fn(),
        deleteScan: jest.fn(),
        importExport: jest.fn(),
    },
}));
jest.mock('../../src/handlers/variant', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
        listAll: jest.fn(),
    },
}));
jest.mock('../../src/helpers/useDocUrl', () => ({ useDocUrl: () => '#' }));
jest.mock('../../src/helpers/exportJson', () => ({
    downloadJson: jest.fn(),
}));
jest.mock('../../src/components/RunScansWizard', () => ({
    __esModule: true,
    default: ({ isOpen, variants, onClose, onToggleVariant, onToggleScanType,
        onToggleRefreshType, onRefreshModeChange, onSelectAllVariants,
        onSelectNoVariants, onExcludeKernelChange, onExcludeNativeChange, onLaunch }: any) => (
        isOpen ? <div>
            <div data-testid="wizard-variants">{variants.map((variant: any) => variant.name).join(',')}</div>
            <button onClick={onClose}>wizard-close</button>
            <button onClick={() => onToggleVariant(variants[0]?.id)}>wizard-toggle-variant</button>
            <button onClick={() => onToggleScanType('grype')}>wizard-toggle-scan</button>
            <button onClick={() => onToggleRefreshType('nvd')}>wizard-toggle-refresh</button>
            <button onClick={() => onToggleRefreshType('invalid')}>wizard-toggle-invalid-refresh</button>
            <button onClick={() => onRefreshModeChange('custom')}>wizard-custom-refresh</button>
            <button onClick={onSelectAllVariants}>wizard-select-all</button>
            <button onClick={onSelectNoVariants}>wizard-select-none</button>
            <button onClick={() => onExcludeKernelChange(false)}>wizard-include-kernel</button>
            <button onClick={() => onExcludeNativeChange(false)}>wizard-include-native</button>
            <button onClick={onLaunch}>wizard-launch</button>
        </div> : null
    ),
}));

const mockList = ScansHandler.list as jest.MockedFunction<typeof ScansHandler.list>;
const mockVariantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const mockGetDiff = ScansHandler.getDiff as jest.MockedFunction<typeof ScansHandler.getDiff>;
const mockGetGlobalResult = ScansHandler.getGlobalResult as jest.MockedFunction<typeof ScansHandler.getGlobalResult>;
const mockSetDescription = ScansHandler.setDescription as jest.MockedFunction<typeof ScansHandler.setDescription>;
const mockDeleteScan = ScansHandler.deleteScan as jest.MockedFunction<typeof ScansHandler.deleteScan>;
const mockImportExport = ScansHandler.importExport as jest.MockedFunction<typeof ScansHandler.importExport>;
const mockDownloadJson = downloadJson as jest.MockedFunction<typeof downloadJson>;

const scan = (id: string, variantId: string): Scan => ({
    id,
    description: `${id} history`,
    scan_type: 'sbom',
    scan_source: null,
    timestamp: '2026-09-17T00:00:00Z',
    variant_id: variantId,
    variant_name: variantId.toUpperCase(),
    project_name: 'Project',
    finding_count: 0,
    package_count: 0,
    vuln_count: 0,
    is_first: true,
} as Scan);

const finding = {
    finding_id: 'finding-1', package_name: 'openssl', package_version: '3.0',
    package_supplier: 'Organization: ACME', package_id: 'package-1',
    vulnerability_id: 'CVE-2026-0001', origin: 'nvd',
};
const pkg = {
    package_id: 'package-1', package_name: 'openssl', package_version: '3.0',
    package_supplier: 'Organization: ACME',
};
const assessment = {
    vulnerability_id: 'CVE-2026-0001', status: 'affected',
    simplified_status: 'Exploitable', justification: '', impact_statement: 'impact',
    status_notes: 'note',
};
const richDiff: ScanDiff = {
    scan_id: 'scan-1', scan_type: 'sbom', previous_scan_id: 'scan-0', is_first: false,
    finding_count: 3, package_count: 4, vuln_count: 3,
    findings_added: [finding], findings_removed: [{...finding, finding_id: 'finding-2'}],
    findings_upgraded: [{
        vulnerability_id: finding.vulnerability_id, package_name: finding.package_name,
        old_version: '2.0', new_version: '3.0', package_supplier: finding.package_supplier,
        origin: 'nvd',
    }],
    findings_unchanged: [{...finding, finding_id: 'finding-3'}],
    packages_added: [pkg], packages_removed: [{...pkg, package_id: 'package-2'}],
    packages_upgraded: [{
        package_name: 'openssl', old_version: '2.0', new_version: '3.0',
        old_package_id: 'old', new_package_id: 'new', package_supplier: pkg.package_supplier,
    }],
    packages_unchanged: [{...pkg, package_id: 'package-3'}],
    vulns_added: ['CVE-2026-0001'], vulns_removed: ['CVE-2026-0002'],
    vulns_unchanged: ['CVE-2026-0003'], assessment_count: 3,
    assessments_added: [assessment], assessments_removed: [{...assessment, vulnerability_id: 'CVE-2026-0002'}],
    assessments_unchanged: [{...assessment, vulnerability_id: 'CVE-2026-0003'}],
    newly_detected_findings: 1, newly_detected_vulns: 1,
    newly_detected_findings_list: [finding], newly_detected_vulns_list: ['CVE-2026-0004'],
    newly_detected_assessments_list: [assessment], all_findings: [finding],
    all_vulns: ['CVE-2026-0001'],
};
const globalResult: GlobalResult = {
    scan_id: 'scan-1', scan_type: 'sbom', package_count: 1, finding_count: 1,
    vuln_count: 1, assessment_count: 1,
    packages: [{...pkg, sources: ['sbom']}],
    findings: [{...finding, sources: ['nvd']}],
    vulnerabilities: [{vulnerability_id: 'CVE-2026-0001', sources: ['nvd']}],
    assessments: [assessment],
};

describe('ScanHistory selected variant scope', () => {
    let restoreStream: () => void;

    beforeEach(() => {
        restoreStream = __setEventSourceFactory(() => new TestEventSource() as unknown as EventSource);
        jest.clearAllMocks();
        (global.fetch as jest.Mock | undefined)?.mockRestore?.();
        mockVariantsList.mockResolvedValue([
            {id: 'v1', name: 'V1', project_id: 'project'},
            {id: 'v2', name: 'V2', project_id: 'project'},
            {id: 'v3', name: 'V3', project_id: 'project'},
        ]);
        mockGetDiff.mockResolvedValue(richDiff);
        mockGetGlobalResult.mockResolvedValue(globalResult);
        mockSetDescription.mockResolvedValue(true);
        mockDeleteScan.mockResolvedValue({ok: true});
        mockImportExport.mockResolvedValue({
            ok: true,
            result: {
                scan_id: 'imported-scan',
                imported_count: 1,
                skipped_count: 0,
                package_count: 1,
                finding_count: 1,
                vulnerability_count: 1,
                assessment_count: 1,
                format: 'diff',
                is_first: false,
                scans: [],
            },
        });
    });

    afterEach(() => {
        __reset();
        restoreStream();
        jest.restoreAllMocks();
    });

    test('submits selected scans and deferred refreshes together and waits for the full batch', async () => {
        mockList.mockResolvedValue([]);
        const listVulnerabilities = jest.spyOn(Vulnerabilities, 'list').mockResolvedValue([]);
        const enqueue = jest.spyOn(Operations, 'enqueue').mockResolvedValue({
            ok: true, queueId: 'q-1', operations: [
                { op_id: 'scan:grype:v1' }, { op_id: 'scan:nvd:v1' }, { op_id: 'refresh:epss' },
            ] as Operation[],
        });
        const onScanComplete = jest.fn();
        render(<ScanHistory projectId="project" variantIds={['v1']} onScanComplete={onScanComplete} />);
        fireEvent.click(await screen.findByRole('button', { name: 'Run Scans' }));
        await screen.findByTestId('wizard-variants');
        fireEvent.click(screen.getByText('wizard-launch'));

        await waitFor(() => expect(enqueue).toHaveBeenCalled());
        expect(enqueue.mock.calls[0][0]).toEqual(expect.arrayContaining([
            expect.objectContaining({ kind: 'scan', source: 'grype', variant_ids: ['v1'], options: expect.objectContaining({ exclude_native: true }) }),
            expect.objectContaining({ kind: 'refresh', source: 'epss', variant_ids: ['v1'] }),
        ]));
        expect(listVulnerabilities).toHaveBeenCalled();

        const completed = (opId: string, kind: 'scan' | 'refresh') => ({
            op_id: opId, kind, queue_id: 'q-1', status: 'done',
        });
        TestEventSource.current.send('snapshot', { seq: 1, operations: [completed('scan:grype:v1', 'scan')] });
        expect(onScanComplete).not.toHaveBeenCalled();
        TestEventSource.current.send('operation', completed('scan:nvd:v1', 'scan'));
        expect(onScanComplete).not.toHaveBeenCalled();
        TestEventSource.current.send('operation', completed('refresh:epss', 'refresh'));
        await waitFor(() => expect(onScanComplete).toHaveBeenCalled());
    });

    test('switching from three variants to two drops stale history and wizard choices', async () => {
        let resolveThree!: (scans: Scan[]) => void;
        const threeVariantRequest = new Promise<Scan[]>(resolve => { resolveThree = resolve; });
        mockList.mockImplementation((_variantId, _projectId, variantIds) => {
            if (variantIds?.length === 3) return threeVariantRequest;
            return Promise.resolve([scan('v1-scan', 'v1'), scan('v2-scan', 'v2')]);
        });

        const view = render(
            <ScanHistory projectId="project" variantIds={['v1', 'v2', 'v3']} />
        );
        view.rerender(
            <ScanHistory projectId="project" variantIds={['v1', 'v2']} />
        );

        await waitFor(() => expect(screen.getByText('v1-scan history')).toBeInTheDocument());
        expect(screen.getByText('v2-scan history')).toBeInTheDocument();

        await act(async () => {
            resolveThree([
                scan('v1-scan', 'v1'),
                scan('v2-scan', 'v2'),
                scan('v3-scan', 'v3'),
            ]);
        });
        expect(screen.queryByText('v3-scan history')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', {name: 'Run Scans'}));
        await waitFor(() => expect(screen.getByTestId('wizard-variants')).toHaveTextContent('V1,V2'));
        expect(screen.getByTestId('wizard-variants')).not.toHaveTextContent('V3');
    });

    test('an old-scope completion refresh cannot restore deselected history', async () => {
        let resolveOldRefresh!: (scans: Scan[]) => void;
        const oldRefresh = new Promise<Scan[]>(resolve => { resolveOldRefresh = resolve; });
        let threeVariantCalls = 0;
        mockList.mockImplementation((_variantId, _projectId, scopedVariantIds) => {
            if (scopedVariantIds?.length === 3) {
                threeVariantCalls += 1;
                if (threeVariantCalls === 1) {
                    return Promise.resolve([scan('initial-v3', 'v3')]);
                }
                return oldRefresh;
            }
            return Promise.resolve([scan('current-v1', 'v1'), scan('current-v2', 'v2')]);
        });

        const view = render(
            <ScanHistory projectId="project" variantIds={['v1', 'v2', 'v3']} />
        );
        await screen.findByText('initial-v3 history');
        TestEventSource.current.send('snapshot', { seq: 1, operations: [
            { op_id: 'scan:grype:v1', kind: 'scan', status: 'running' },
        ] });
        TestEventSource.current.send('operation', { op_id: 'scan:grype:v1', kind: 'scan', status: 'done' });
        await waitFor(() => expect(threeVariantCalls).toBe(2));

        view.rerender(
            <ScanHistory projectId="project" variantIds={['v1', 'v2']} />
        );
        await screen.findByText('current-v1 history');

        await act(async () => {
            resolveOldRefresh([scan('stale-refresh-v3', 'v3')]);
        });
        expect(screen.queryByText('stale-refresh-v3 history')).not.toBeInTheDocument();
        expect(screen.getByText('current-v2 history')).toBeInTheDocument();
    });

    test('a completion refresh superseding the initial load clears loading', async () => {
        let resolveInitial!: (scans: Scan[]) => void;
        const initialRequest = new Promise<Scan[]>(resolve => { resolveInitial = resolve; });
        let calls = 0;
        mockList.mockImplementation(() => {
            calls += 1;
            return calls === 1
                ? initialRequest
                : Promise.resolve([scan('refreshed-v1', 'v1')]);
        });

        render(<ScanHistory projectId="project" variantIds={['v1']} />);
        expect(await screen.findByText('Loading scan history…')).toBeInTheDocument();
        TestEventSource.current.send('snapshot', { seq: 1, operations: [
            { op_id: 'scan:grype:v1', kind: 'scan', status: 'running' },
        ] });
        TestEventSource.current.send('operation', { op_id: 'scan:grype:v1', kind: 'scan', status: 'done' });

        expect(await screen.findByText('refreshed-v1 history')).toBeInTheDocument();
        expect(screen.queryByText('Loading scan history…')).not.toBeInTheDocument();

        await act(async () => resolveInitial([scan('stale-initial', 'v1')]));
        expect(screen.queryByText('stale-initial history')).not.toBeInTheDocument();
    });

    test('out-of-order variant responses cannot restore out-of-scope wizard choices', async () => {
        let resolveOldVariants!: (variants: Array<{id: string; name: string; project_id: string}>) => void;
        const oldVariants = new Promise<Array<{id: string; name: string; project_id: string}>>(
            resolve => { resolveOldVariants = resolve; }
        );
        let variantCalls = 0;
        mockVariantsList.mockImplementation(() => {
            variantCalls += 1;
            if (variantCalls === 1) return oldVariants;
            return Promise.resolve([
                {id: 'v1', name: 'V1', project_id: 'project'},
                {id: 'v2', name: 'V2', project_id: 'project'},
                {id: 'v3', name: 'V3', project_id: 'project'},
            ]);
        });
        mockList.mockResolvedValue([scan('current-v1', 'v1')]);

        const view = render(
            <ScanHistory projectId="project" variantIds={['v1', 'v2', 'v3']} />
        );
        view.rerender(
            <ScanHistory projectId="project" variantIds={['v1', 'v2']} />
        );
        await waitFor(() => expect(variantCalls).toBe(2));

        await act(async () => {
            resolveOldVariants([
                {id: 'v1', name: 'V1', project_id: 'project'},
                {id: 'v2', name: 'V2', project_id: 'project'},
                {id: 'v3', name: 'V3', project_id: 'project'},
            ]);
        });

        fireEvent.click(await screen.findByRole('button', {name: 'Run Scans'}));
        await waitFor(() => expect(screen.getByTestId('wizard-variants')).toHaveTextContent('V1,V2'));
        expect(screen.getByTestId('wizard-variants')).not.toHaveTextContent('V3');
    });

    test('scope change immediately disables and closes stale wizard choices', async () => {
        let resolveNarrowVariants!: (variants: Array<{id: string; name: string; project_id: string}>) => void;
        const narrowVariants = new Promise<Array<{id: string; name: string; project_id: string}>>(
            resolve => { resolveNarrowVariants = resolve; }
        );
        let variantCalls = 0;
        mockVariantsList.mockImplementation(() => {
            variantCalls += 1;
            if (variantCalls === 1) {
                return Promise.resolve([
                    {id: 'v1', name: 'V1', project_id: 'project'},
                    {id: 'v2', name: 'V2', project_id: 'project'},
                    {id: 'v3', name: 'V3', project_id: 'project'},
                ]);
            }
            return narrowVariants;
        });
        mockList.mockResolvedValue([scan('current-v1', 'v1')]);

        const view = render(
            <ScanHistory projectId="project" variantIds={['v1', 'v2', 'v3']} />
        );
        const runScans = await screen.findByRole('button', {name: 'Run Scans'});
        await waitFor(() => expect(runScans).toBeEnabled());
        fireEvent.click(runScans);
        expect(await screen.findByTestId('wizard-variants')).toHaveTextContent('V1,V2,V3');

        view.rerender(
            <ScanHistory projectId="project" variantIds={['v1', 'v2']} />
        );

        await waitFor(() => expect(screen.getByRole('button', {name: 'Run Scans'})).toBeDisabled());
        expect(screen.queryByTestId('wizard-variants')).not.toBeInTheDocument();

        await act(async () => {
            resolveNarrowVariants([
                {id: 'v1', name: 'V1', project_id: 'project'},
                {id: 'v2', name: 'V2', project_id: 'project'},
                {id: 'v3', name: 'V3', project_id: 'project'},
            ]);
        });

        await waitFor(() => expect(screen.getByRole('button', {name: 'Run Scans'})).toBeEnabled());
        fireEvent.click(screen.getByRole('button', {name: 'Run Scans'}));
        expect(await screen.findByTestId('wizard-variants')).toHaveTextContent('V1,V2');
        expect(screen.getByTestId('wizard-variants')).not.toHaveTextContent('V3');
    });

    test('browses and filters active scan result sections', async () => {
        mockList.mockResolvedValue([{...scan('scan-1', 'v1'), is_first: false}]);
        render(<ScanHistory projectId="project" variantIds={['v1']} />);

        const details = await screen.findAllByRole('button', {name: 'Details'});
        fireEvent.click(details[0]);
        expect(await screen.findByText('Scan Result — Active Items')).toBeInTheDocument();
        expect(screen.getByText('openssl')).toBeInTheDocument();

        const resultModal = screen.getByTestId('scan-result-modal-backdrop');
        const resultFilter = resultModal.querySelector<HTMLInputElement>('input[type="text"]');
        expect(resultFilter).not.toBeNull();
        fireEvent.change(resultFilter!, {target: {value: 'missing'}});
        expect(screen.queryByText('openssl')).not.toBeInTheDocument();
        fireEvent.change(resultFilter!, {target: {value: ''}});
        fireEvent.click(screen.getByRole('button', {name: /Findings/}));
        expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: /Vulnerabilities/}));
        expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: /Assessments/}));
        expect(screen.getByText('Exploitable')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: 'Close'}));
        expect(screen.queryByText('Scan Result — Active Items')).not.toBeInTheDocument();
    });

    test('browses every SBOM diff section and filters detail tables', async () => {
        mockList.mockResolvedValue([{...scan('scan-1', 'v1'), is_first: false}]);
        render(<ScanHistory projectId="project" variantIds={['v1']} />);

        const details = await screen.findAllByRole('button', {name: 'Details'});
        fireEvent.click(details[1]);
        expect(await screen.findByText('Scan diff details')).toBeInTheDocument();
        expect(screen.getByText('Added packages (1)')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: /Findings/}));
        expect(screen.getByText('Findings on upgraded packages (1)')).toBeInTheDocument();
        const diffModal = screen.getByTestId('scan-diff-modal-backdrop');
        const filters = diffModal.querySelectorAll<HTMLInputElement>('input[type="text"]');
        expect(filters.length).toBeGreaterThan(0);
        fireEvent.change(filters[0], {target: {value: 'does-not-match'}});
        fireEvent.change(filters[0], {target: {value: ''}});
        fireEvent.click(screen.getByRole('button', {name: /Vulnerabilities/}));
        expect(screen.getByText('Removed vulnerabilities (1)')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: /Assessments/}));
        expect(screen.getByText('Removed assessments (1)')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: 'Close'}));
    });

    test('renders tool scan and detail error branches', async () => {
        mockList.mockResolvedValue([{
            ...scan('tool-scan', 'v1'), scan_type: 'tool', scan_source: 'grype',
            is_first: true, newly_detected_findings: 1, newly_detected_vulns: 1,
        }]);
        mockGetGlobalResult.mockResolvedValueOnce(null);
        mockGetDiff.mockResolvedValueOnce({...richDiff, scan_type: 'tool'});
        render(<ScanHistory projectId="project" variantIds={['v1']} />);

        let details = await screen.findAllByRole('button', {name: 'Details'});
        fireEvent.click(details[0]);
        expect(await screen.findByText('Failed to load scan result.')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: 'Close'}));

        details = screen.getAllByRole('button', {name: 'Details'});
        fireEvent.click(details[1]);
        expect(await screen.findByText('Tool scan diff details')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: /New Discovered/}));
        expect(screen.getByText('New findings discovered (1)')).toBeInTheDocument();
    });

    test('exercises simple timeline, wizard, description, delete, and import controls', async () => {
        mockList.mockResolvedValue([
            {...scan('scan-1', 'v1'), is_first: false, description: 'before'},
            {...scan('scan-2', 'v1'), is_first: false, scan_type: 'tool', scan_source: 'osv'},
            {...scan('scan-3', 'v1'), is_first: false, scan_type: 'tool', scan_source: 'nvd'},
            {...scan('scan-4', 'v1'), is_first: false, scan_type: 'tool', scan_source: 'scc'},
        ]);
        const {container} = render(<ScanHistory projectId="project" variantIds={['v1']} />);
        await screen.findByText('before');

        for (const title of [
            'Showing all scans', 'Grype scans visible', 'OSV scans visible',
            'NVD scans visible', 'sbom-cve-check scans visible',
        ]) fireEvent.click(screen.getByTitle(title));
        fireEvent.click(screen.getByTitle('Showing only scans with changes'));

        fireEvent.click(screen.getByRole('button', {name: 'Run Scans'}));
        for (const label of [
            'wizard-toggle-variant', 'wizard-toggle-scan', 'wizard-toggle-refresh',
            'wizard-toggle-invalid-refresh', 'wizard-custom-refresh', 'wizard-select-none',
            'wizard-select-all', 'wizard-include-kernel', 'wizard-include-native',
        ]) fireEvent.click(screen.getByText(label));
        fireEvent.click(screen.getByText('wizard-close'));
        fireEvent.click(screen.getByRole('button', {name: 'Run Scans'}));
        fireEvent.click(screen.getByText('wizard-close'));

        fireEvent.click(screen.getAllByTitle('Edit description')[0]);
        let descriptionInput = container.querySelector<HTMLInputElement>('input[placeholder="Add a description…"]');
        expect(descriptionInput).not.toBeNull();
        fireEvent.change(descriptionInput!, {target: {value: 'after'}});
        fireEvent.keyDown(descriptionInput!, {key: 'Escape'});
        fireEvent.click(screen.getAllByTitle('Edit description')[0]);
        descriptionInput = container.querySelector<HTMLInputElement>('input[placeholder="Add a description…"]');
        fireEvent.change(descriptionInput!, {target: {value: 'after'}});
        fireEvent.keyDown(descriptionInput!, {key: 'Enter'});
        await waitFor(() => expect(mockSetDescription).toHaveBeenCalledWith('scan-1', 'after'));

        fireEvent.click(screen.getAllByTitle('Delete scan')[0]);
        fireEvent.click(await screen.findByRole('button', {name: 'Cancel'}));
        fireEvent.click(screen.getAllByTitle('Delete scan')[0]);
        fireEvent.click(await screen.findByRole('button', {name: 'Yes, delete'}));
        await waitFor(() => expect(mockDeleteScan).toHaveBeenCalled());

        const importFile = new File(['{}'], 'scan.json', {type: 'application/json'});
        Object.defineProperty(importFile, 'text', {value: jest.fn().mockResolvedValue('{}')});
        fireEvent.change(screen.getByLabelText('Choose exported scan data'), {
            target: {files: [importFile]},
        });
        await waitFor(() => expect(mockImportExport).toHaveBeenCalled());
        expect(await screen.findByText(/Imported 1 scan diff/)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: 'Dismiss'}));
        expect(screen.queryByText(/Imported 1 scan diff/)).not.toBeInTheDocument();
    });

    test('exports per-scan results and all diffs and dismisses export menus', async () => {
        mockList.mockResolvedValue([{...scan('scan-1', 'v1'), is_first: false}]);
        const fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            headers: new Headers({'Content-Disposition': 'attachment; filename="export.json"'}),
            json: async () => ({exported: true}),
        } as Response);
        render(<ScanHistory projectId="project" variantIds={['v1']} />);
        await screen.findByText('scan-1 history');

        const exportScan = screen.getByTitle('Export scan');
        fireEvent.click(exportScan);
        expect(screen.getByText('Export Diff')).toBeInTheDocument();
        fireEvent.mouseDown(document.body);
        expect(screen.queryByText('Export Diff')).not.toBeInTheDocument();

        fireEvent.click(exportScan);
        fireEvent.click(screen.getByText('Export Diff'));
        await waitFor(() => expect(mockDownloadJson).toHaveBeenCalledWith({exported: true}, 'export.json'));

        fireEvent.click(exportScan);
        fireEvent.click(screen.getByText('Export Scan Result'));
        await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/scan-1/export-result'),
            expect.objectContaining({mode: 'cors'}),
        ));

        fireEvent.click(screen.getByTitle('Export all scan diffs'));
        await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/export?type=diff&project_id=project'),
            expect.objectContaining({mode: 'cors'}),
        ));
        fetchSpy.mockRestore();
    });

    describe('scan runs', () => {
        const run = {
            id: 'q-run', scan_ids: ['grype-step', 'nvd-step'], sources: ['grype', 'nvd'],
            vuln_count: 21, finding_count: 22, assessment_count: 23,
            newly_detected_vulns: 17, newly_detected_findings: 18, newly_detected_assessments: 19,
        };
        const step = (id: string, source: string, overrides: Partial<Scan> = {}): Scan => ({
            ...scan(id, 'v1'), scan_type: 'tool', scan_source: source, is_first: false,
            run_id: 'q-run', run, newly_detected_vulns: 0, ...overrides,
        } as Scan);
        const history = (): Scan[] => [
            {...scan('sbom-scan', 'v1'), is_first: true},
            step('grype-step', 'grype', {timestamp: '2026-09-17T01:00:00Z', newly_detected_vulns: 3}),
            step('nvd-step', 'nvd', {timestamp: '2026-09-17T01:05:00Z', global_vuln_count: 99}),
            {
                ...scan('osv-solo', 'v1'), scan_type: 'tool', scan_source: 'osv', is_first: false,
                run_id: 'q-solo', run: null, newly_detected_vulns: 1,
            } as Scan,
        ];

        test('shows every step of a run as one card with per-scanner details', async () => {
            mockList.mockResolvedValue(history());
            render(<ScanHistory projectId="project" variantIds={['v1']} />);

            expect(await screen.findByText(/Scan run · 2 scanners/)).toBeInTheDocument();
            expect(screen.getAllByText(/Scan run · /)).toHaveLength(1);
            expect(screen.getByText('OSV Scan')).toBeInTheDocument();
            expect(screen.queryByText('Grype Scan')).not.toBeInTheDocument();
            ['99', '21', '17', '22', '18', '23', '19'].forEach(count =>
                expect(screen.getByText(count)).toBeInTheDocument());
            expect(screen.getByTitle('Show Grype changes')).toHaveTextContent('+3 new');

            fireEvent.click(screen.getByTitle('Show NVD CPE changes'));
            await waitFor(() => expect(mockGetDiff).toHaveBeenCalledWith('nvd-step'));
            fireEvent.click(await screen.findByRole('button', {name: 'Close'}));

            const runCard = screen.getByText(/Scan run · 2 scanners/).closest('.group\\/card') as HTMLElement;
            fireEvent.click(within(runCard).getByRole('button', {name: 'Details'}));
            await waitFor(() => expect(mockGetGlobalResult).toHaveBeenCalledWith('nvd-step'));
        });

        test('keeps a run while one of its scanners is visible', async () => {
            mockList.mockResolvedValue(history());
            render(<ScanHistory projectId="project" variantIds={['v1']} />);
            await screen.findByText(/Scan run · 2 scanners/);

            fireEvent.click(screen.getByTitle('Grype scans visible'));
            expect(screen.queryByTitle('Show Grype changes')).not.toBeInTheDocument();
            expect(screen.getByTitle('Show NVD CPE changes')).toBeInTheDocument();

            fireEvent.click(screen.getByTitle('NVD scans visible'));
            expect(screen.queryByText(/Scan run · /)).not.toBeInTheDocument();
        });

        test('hides a run without changes only when every step is empty', async () => {
            const quiet = history().map(entry => entry.run ? {...entry, newly_detected_vulns: 0} : entry);
            mockList.mockResolvedValue(quiet);
            render(<ScanHistory projectId="project" variantIds={['v1']} />);
            await screen.findByText(/Scan run · 2 scanners/);

            fireEvent.click(screen.getByTitle('Showing all scans'));

            expect(screen.queryByText(/Scan run · /)).not.toBeInTheDocument();
            expect(screen.getByText('OSV Scan')).toBeInTheDocument();
        });

        test('deletes every scan of a run after confirmation', async () => {
            mockList.mockResolvedValue(history());
            const onScanComplete = jest.fn();
            render(<ScanHistory projectId="project" variantIds={['v1']} onScanComplete={onScanComplete} />);
            await screen.findByText(/Scan run · 2 scanners/);

            fireEvent.click(screen.getByTitle('Delete scan run'));
            expect(await screen.findByText('Delete Scan Run')).toBeInTheDocument();
            expect(screen.getByText(/Its 2 scans/)).toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', {name: 'Yes, delete'}));

            await waitFor(() => expect(onScanComplete).toHaveBeenCalled());
            expect(mockDeleteScan.mock.calls.map(([scanId]) => scanId)).toEqual(['grype-step', 'nvd-step']);
            await waitFor(() => expect(screen.queryByText('Delete Scan Run')).not.toBeInTheDocument());
        });

        test('keeps the confirmation open when part of a run cannot be deleted', async () => {
            mockList.mockResolvedValue(history());
            mockDeleteScan.mockResolvedValueOnce({ok: true}).mockResolvedValueOnce({ok: false, error: 'locked'});
            const onScanComplete = jest.fn();
            render(<ScanHistory projectId="project" variantIds={['v1']} onScanComplete={onScanComplete} />);
            await screen.findByText(/Scan run · 2 scanners/);

            fireEvent.click(screen.getByTitle('Delete scan run'));
            fireEvent.click(await screen.findByRole('button', {name: 'Yes, delete'}));

            await waitFor(() => expect(onScanComplete).toHaveBeenCalled());
            expect(screen.getByText('Delete Scan Run')).toBeInTheDocument();
        });

        test('exports the run result and each scanner diff', async () => {
            mockList.mockResolvedValue(history());
            const fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                headers: new Headers(),
                json: async () => ({exported: true}),
            } as Response);
            render(<ScanHistory projectId="project" variantIds={['v1']} />);
            await screen.findByText(/Scan run · 2 scanners/);

            fireEvent.click(screen.getByTitle('Export scan run'));
            fireEvent.click(screen.getByText('Export Grype Diff'));
            await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
                expect.stringContaining('/api/scans/grype-step/export-diff'),
                expect.objectContaining({mode: 'cors'}),
            ));
            await waitFor(() => expect(screen.queryByText('Exporting…')).not.toBeInTheDocument());

            fireEvent.click(screen.getByTitle('Export scan run'));
            fireEvent.click(screen.getByText('Export Scan Result'));
            await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
                expect.stringContaining('/api/scans/nvd-step/export-result'),
                expect.objectContaining({mode: 'cors'}),
            ));
            fetchSpy.mockRestore();
        });
    });
});
