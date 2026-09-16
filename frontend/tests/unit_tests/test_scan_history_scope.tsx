import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

import ScanHistory from '../../src/pages/ScanHistory';
import ScansHandler from '../../src/handlers/scans';
import Variants from '../../src/handlers/variant';
import type { Scan } from '../../src/handlers/scans';

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
});
