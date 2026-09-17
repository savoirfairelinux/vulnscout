import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

import ScanHistory from '../../src/pages/ScanHistory';
import ScansHandler from '../../src/handlers/scans';
import Variants from '../../src/handlers/variant';
import type { Scan } from '../../src/handlers/scans';
import { setOnDone } from '../../src/handlers/grypeScanState';

const mockEmptySnapshot: readonly never[] = [];
function mockManager() {
    return {
        subscribe: () => () => {},
        getSnapshot: () => mockEmptySnapshot,
        setOnDone: jest.fn(),
        queueScan: jest.fn(),
        startQueuedScan: jest.fn(),
        waitForCompletion: jest.fn(),
    };
}

jest.mock('../../src/handlers/grypeScanState', () => mockManager());
jest.mock('../../src/handlers/nvdScanState', () => mockManager());
jest.mock('../../src/handlers/osvScanState', () => mockManager());
jest.mock('../../src/handlers/sccScanState', () => mockManager());
jest.mock('../../src/handlers/activeScanQueue', () => ({
    hasActiveRefreshes: jest.fn(() => false),
    queueVulnerabilityRefresh: jest.fn(() => true),
    restoreActiveRefreshes: jest.fn(),
    waitForActiveScans: jest.fn(() => Promise.resolve()),
    waitForRefreshCompletion: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../src/handlers/scans', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
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
jest.mock('../../src/components/RunScansWizard', () => ({
    __esModule: true,
    default: ({ isOpen, variants }: { isOpen: boolean; variants: Array<{name: string}> }) => (
        isOpen ? <div data-testid="wizard-variants">{variants.map(variant => variant.name).join(',')}</div> : null
    ),
}));

const mockList = ScansHandler.list as jest.MockedFunction<typeof ScansHandler.list>;
const mockVariantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const mockSetOnDone = setOnDone as jest.MockedFunction<typeof setOnDone>;

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

describe('ScanHistory selected variant scope', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockVariantsList.mockResolvedValue([
            {id: 'v1', name: 'V1', project_id: 'project'},
            {id: 'v2', name: 'V2', project_id: 'project'},
            {id: 'v3', name: 'V3', project_id: 'project'},
        ]);
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
        const onDone = [...mockSetOnDone.mock.calls]
            .reverse()
            .map(call => call[0])
            .find((callback): callback is () => void => typeof callback === 'function');
        expect(onDone).toBeDefined();
        act(() => onDone?.());
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
        const onDone = [...mockSetOnDone.mock.calls]
            .reverse()
            .map(call => call[0])
            .find((callback): callback is () => void => typeof callback === 'function');
        expect(onDone).toBeDefined();
        act(() => onDone?.());

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
});
