import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';

import Explorer from '../../src/pages/Explorer';
import Config from '../../src/handlers/config';
import Projects from '../../src/handlers/project';
import Variants from '../../src/handlers/variant';
import Packages from '../../src/handlers/packages';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Assessments from '../../src/handlers/assessments';
import ScansHandler from '../../src/handlers/scans';
import { restoreFromStatus as grypeRestore } from '../../src/handlers/grypeScanState';
import { restoreActiveRefreshes } from '../../src/handlers/activeScanQueue';

jest.mock('../../src/handlers/config', () => ({
    __esModule: true,
    default: {
        get: jest.fn(),
        getFrontendScope: jest.fn(),
        clearFrontendScope: jest.fn(),
        setFrontendScope: jest.fn(),
        isFrontendScopeAvailable: jest.fn((scope, projectIds, variantIds) =>
            projectIds.includes(scope.project_id) && scope.variant_ids.every((variantId: string) => variantIds.includes(variantId)),
        ),
    },
}));

jest.mock('../../src/handlers/project', () => ({
    __esModule: true,
    default: { list: jest.fn() },
}));

jest.mock('../../src/handlers/variant', () => ({
    __esModule: true,
    default: { list: jest.fn(), listAll: jest.fn() },
}));

jest.mock('../../src/handlers/scans', () => ({
    __esModule: true,
    default: { getRunningScans: jest.fn() },
}));

jest.mock('../../src/handlers/grypeScanState', () => {
    const snapshot: never[] = [];
    return { subscribe: () => () => undefined, getSnapshot: () => snapshot, restoreFromStatus: jest.fn() };
});
jest.mock('../../src/handlers/nvdScanState', () => {
    const snapshot: never[] = [];
    return { subscribe: () => () => undefined, getSnapshot: () => snapshot, restoreFromStatus: jest.fn() };
});
jest.mock('../../src/handlers/osvScanState', () => {
    const snapshot: never[] = [];
    return { subscribe: () => () => undefined, getSnapshot: () => snapshot, restoreFromStatus: jest.fn() };
});
jest.mock('../../src/handlers/sccScanState', () => {
    const snapshot: never[] = [];
    return { subscribe: () => () => undefined, getSnapshot: () => snapshot, restoreFromStatus: jest.fn() };
});
jest.mock('../../src/handlers/activeScanQueue', () => {
    const snapshot: never[] = [];
    return {
        subscribeToRefreshQueue: () => () => undefined,
        getRefreshQueueSnapshot: () => snapshot,
        restoreActiveRefreshes: jest.fn(() => Promise.resolve()),
    };
});

jest.mock('../../src/handlers/packages', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
        enrich_with_vulns: jest.fn(() => []),
    },
}));

jest.mock('../../src/handlers/vulnerabilities', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
        enrich_with_assessments: jest.fn(() => []),
        calculate_cvss_from_vector: jest.fn(() => ({ score: 7.5 })),
        append_assessment: jest.fn((vulnerabilities) => vulnerabilities),
        append_cvss: jest.fn((vulnerabilities) => vulnerabilities),
    },
}));

jest.mock('../../src/handlers/assessments', () => ({
    __esModule: true,
    default: { list: jest.fn() },
    removeDuplicateAssessments: jest.fn((lists: unknown[][]) => lists.flat()),
    STATUS_VEX_TO_GRAPH: {},
}));

jest.mock('../../src/components/NavigationBar', () => ({
    __esModule: true,
    default: ({ defaultProject, defaultScope, changeTab, onOpenScanProgress }: {
        defaultProject?: { id: string } | null;
        defaultScope?: { project_id: string } | null;
        changeTab: (tab: string) => void;
        onOpenScanProgress: () => void;
    }) => (
        <div>
            <span data-testid="default-project">{defaultProject?.id ?? ''}</span>
            <span data-testid="frontend-scope">{defaultScope?.project_id ?? ''}</span>
            {['metrics', 'packages', 'vulnerabilities', 'scans', 'review', 'settings'].map(tab => (
                <button key={tab} onClick={() => changeTab(tab)}>{tab}</button>
            ))}
            <button onClick={onOpenScanProgress}>progress</button>
        </div>
    ),
}));

jest.mock('../../src/components/MessageBanner', () => ({
    __esModule: true,
    default: ({ message, isVisible }: { message: string; isVisible: boolean }) =>
        isVisible ? <div role="alert">{message}</div> : null,
}));

jest.mock('../../src/components/VersionDisplay', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/components/ScanProgressModal', () => ({
    __esModule: true,
    default: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => isOpen ? <button onClick={onClose}>close progress</button> : null,
}));
jest.mock('../../src/pages/Metrics', () => ({
    __esModule: true,
    default: ({ goToVulnsTabWithFilter }: { goToVulnsTabWithFilter: (type: 'Severity', value: string) => void }) => (
        <button onClick={() => goToVulnsTabWithFilter('Severity', 'high')}>filter vulnerabilities</button>
    ),
}));
jest.mock('../../src/pages/TablePackages', () => ({
    __esModule: true,
    default: ({ onShowVulns }: { onShowVulns: (packageId: string, ids: string[]) => void }) => (
        <button onClick={() => onShowVulns('pkg-1', ['CVE-1'])}>show package vulnerabilities</button>
    ),
}));
jest.mock('../../src/pages/TableVulnerabilities', () => ({
    __esModule: true,
    default: ({ appendAssessment, appendCVSS, patchVuln, onRefreshComplete }: {
        appendAssessment: (assessment: { id: string }) => void;
        appendCVSS: (id: string, vector: string) => void;
        patchVuln: (id: string, vulnerability: { id: string }) => void;
        onRefreshComplete: () => void;
    }) => <div>
        <button onClick={() => appendAssessment({ id: 'assessment-1' })}>append assessment</button>
        <button onClick={() => appendCVSS('CVE-1', 'CVSS:3.1/test')}>append cvss</button>
        <button onClick={() => patchVuln('CVE-1', { id: 'CVE-1' })}>patch vulnerability</button>
        <button onClick={onRefreshComplete}>refresh complete</button>
    </div>,
}));
jest.mock('../../src/pages/ScanHistory', () => ({
    __esModule: true,
    default: ({ onScanComplete }: { onScanComplete: () => void }) => <button onClick={onScanComplete}>scan complete</button>,
}));
jest.mock('../../src/pages/Review', () => ({
    __esModule: true,
    default: ({ onAssessmentChanged }: { onAssessmentChanged: (mutation: { type: 'delete'; vulnId: string; ids: string[] }) => void }) => (
        <button onClick={() => onAssessmentChanged({ type: 'delete', vulnId: 'CVE-1', ids: [] })}>assessment changed</button>
    ),
}));
jest.mock('../../src/pages/Settings', () => ({
    __esModule: true,
    default: ({ onDataChanged, onLoadingMessage }: { onDataChanged: (message: string) => void; onLoadingMessage: (message: string) => void }) => <div>
        <button onClick={() => onDataChanged('Saving')}>settings changed</button>
        <button onClick={() => onLoadingMessage('Loading settings')}>settings loading</button>
        <button onClick={() => onLoadingMessage('')}>settings loaded</button>
    </div>,
}));
jest.mock('../../src/pages/Transfer', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Exports', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/AIContext', () => ({ __esModule: true, default: () => null }));

const mockConfigGet = Config.get as jest.MockedFunction<typeof Config.get>;
const mockGetFrontendScope = Config.getFrontendScope as jest.MockedFunction<typeof Config.getFrontendScope>;
const mockClearFrontendScope = Config.clearFrontendScope as jest.MockedFunction<typeof Config.clearFrontendScope>;
const mockProjectsList = Projects.list as jest.MockedFunction<typeof Projects.list>;
const mockVariantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const mockVariantsListAll = Variants.listAll as jest.MockedFunction<typeof Variants.listAll>;
const mockPackagesList = Packages.list as jest.MockedFunction<typeof Packages.list>;
const mockVulnerabilitiesList = Vulnerabilities.list as jest.MockedFunction<typeof Vulnerabilities.list>;
const mockAssessmentsList = Assessments.list as jest.MockedFunction<typeof Assessments.list>;
const mockGetRunningScans = ScansHandler.getRunningScans as jest.MockedFunction<typeof ScansHandler.getRunningScans>;
const mockGrypeRestore = grypeRestore as jest.MockedFunction<typeof grypeRestore>;
const mockRestoreActiveRefreshes = restoreActiveRefreshes as jest.MockedFunction<typeof restoreActiveRefreshes>;

const SERVER_CONFIG = {
    project: { id: 'default-project', name: 'Default Project' },
    variant: { id: 'default-variant', name: 'Default Variant' },
    product_name: '',
    author_name: 'vulnscout',
    client_name: '',
    contact_email: '',
    grype_memlimit: '',
};

const savedScope = (projectId: string, variantIds: string[]) => ({
    project_id: projectId,
    mode: 'select' as const,
    variant_ids: variantIds,
    compare_base_id: '',
    compare_operation: 'difference' as const,
    compare_variant_id: '',
});

describe('Explorer saved-scope validation', () => {
    beforeEach(() => {
        mockConfigGet.mockResolvedValue(SERVER_CONFIG);
        mockPackagesList.mockResolvedValue([]);
        mockVulnerabilitiesList.mockResolvedValue([]);
        mockAssessmentsList.mockResolvedValue([]);
        mockVariantsListAll.mockResolvedValue([]);
        mockGetRunningScans.mockResolvedValue({ grype: [], nvd: [], osv: [], 'sbom-cve-check': [] });
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    test('clears a stale project scope and silently falls back to the default scope', async () => {
        mockGetFrontendScope.mockReturnValue(savedScope('deleted-project', ['old-variant']));
        mockProjectsList.mockResolvedValue([{ id: 'other-project', name: 'Other Project' }]);

        render(<Explorer />);

        await waitFor(() => {
            expect(mockClearFrontendScope).toHaveBeenCalledTimes(1);
            expect(screen.getByTestId('default-project')).toHaveTextContent('default-project');
            expect(screen.getByTestId('frontend-scope')).toBeEmptyDOMElement();
        });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('clears a scope whose saved variant is no longer available', async () => {
        mockGetFrontendScope.mockReturnValue(savedScope('existing-project', ['deleted-variant']));
        mockProjectsList.mockResolvedValue([{ id: 'existing-project', name: 'Existing Project' }]);
        mockVariantsList.mockResolvedValue([{ id: 'current-variant', name: 'Current Variant', project_id: 'existing-project' }]);

        render(<Explorer />);

        await waitFor(() => {
            expect(mockClearFrontendScope).toHaveBeenCalledTimes(1);
            expect(screen.getByTestId('frontend-scope')).toBeEmptyDOMElement();
        });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('keeps a saved scope when an empty projects response cannot confirm its absence', async () => {
        const scope = savedScope('saved-project', ['saved-variant']);
        mockGetFrontendScope.mockReturnValue(scope);
        mockProjectsList.mockResolvedValue([]);

        render(<Explorer />);

        await waitFor(() => {
            expect(screen.getByTestId('default-project')).toHaveTextContent('default-project');
            expect(screen.getByTestId('frontend-scope')).toHaveTextContent('saved-project');
        });
        expect(mockClearFrontendScope).not.toHaveBeenCalled();
        expect(mockVariantsList).not.toHaveBeenCalled();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('uses the server default when scope validation fails', async () => {
        mockGetFrontendScope.mockReturnValue(savedScope('saved-project', ['saved-variant']));
        mockProjectsList.mockRejectedValue(new Error('Temporary network failure'));

        render(<Explorer />);

        await waitFor(() => {
            expect(screen.getByTestId('default-project')).toHaveTextContent('default-project');
            expect(screen.getByTestId('frontend-scope')).toBeEmptyDOMElement();
            expect(mockPackagesList).toHaveBeenCalledWith('default-variant', undefined, undefined, undefined, undefined, undefined);
        });
        expect(mockClearFrontendScope).not.toHaveBeenCalled();
    });

    test('restores backend-running scans on application mount', async () => {
        mockGetFrontendScope.mockReturnValue(null);
        mockVariantsListAll.mockResolvedValue([
            { id: 'variant-1', name: 'Variant 1', project_id: 'project-1' },
        ]);
        mockGetRunningScans.mockResolvedValue({
            grype: [{ variant_id: 'variant-1', status: 'running', progress: 'Scanning' }],
            nvd: [],
            osv: [],
            'sbom-cve-check': [],
        });

        render(<Explorer />);

        expect(mockRestoreActiveRefreshes).toHaveBeenCalledTimes(1);
        await waitFor(() => expect(mockGrypeRestore).toHaveBeenCalledWith([
            {
                variantId: 'variant-1',
                name: 'Variant 1',
                status: { variant_id: 'variant-1', status: 'running', progress: 'Scanning' },
            },
        ]));
    });

    test('restores running scans with their IDs when variant lookup fails', async () => {
        mockGetFrontendScope.mockReturnValue(null);
        mockVariantsListAll.mockRejectedValue(new Error('variants unavailable'));
        mockGetRunningScans.mockResolvedValue({
            grype: [{ variant_id: 'variant-1', status: 'running' }],
            nvd: [],
            osv: [],
            'sbom-cve-check': [],
        });

        render(<Explorer />);

        await waitFor(() => expect(mockGrypeRestore).toHaveBeenCalledWith([
            {
                variantId: 'variant-1',
                name: 'variant-1',
                status: { variant_id: 'variant-1', status: 'running' },
            },
        ]));
    });

    test('wires navigation and data update callbacks', async () => {
        mockGetFrontendScope.mockReturnValue(null);
        mockProjectsList.mockResolvedValue([]);

        render(<Explorer />);
        await waitFor(() => expect(mockPackagesList).toHaveBeenCalled());

        fireEvent.click(screen.getByRole('button', { name: 'progress' }));
        fireEvent.click(screen.getByRole('button', { name: 'close progress' }));
        fireEvent.click(screen.getByRole('button', { name: 'filter vulnerabilities' }));
        fireEvent.click(screen.getByRole('button', { name: 'append assessment' }));
        fireEvent.click(screen.getByRole('button', { name: 'append cvss' }));
        fireEvent.click(screen.getByRole('button', { name: 'patch vulnerability' }));
        fireEvent.click(screen.getByRole('button', { name: 'refresh complete' }));

        fireEvent.click(screen.getByRole('button', { name: 'packages' }));
        fireEvent.click(screen.getByRole('button', { name: 'show package vulnerabilities' }));
        fireEvent.click(screen.getByRole('button', { name: 'scans' }));
        fireEvent.click(screen.getByRole('button', { name: 'scan complete' }));
        fireEvent.click(screen.getByRole('button', { name: 'review' }));
        fireEvent.click(screen.getByRole('button', { name: 'assessment changed' }));
        fireEvent.click(screen.getByRole('button', { name: 'settings' }));
        fireEvent.click(screen.getByRole('button', { name: 'settings changed' }));
        fireEvent.click(screen.getByRole('button', { name: 'settings loading' }));
        fireEvent.click(screen.getByRole('button', { name: 'settings loaded' }));

        await waitFor(() => expect(mockConfigGet).toHaveBeenCalledTimes(2));
    });
});
