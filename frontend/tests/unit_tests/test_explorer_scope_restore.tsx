import { render, screen, waitFor } from '@testing-library/react';
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
    default: { list: jest.fn() },
}));

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
        calculate_cvss_from_vector: jest.fn(),
        append_assessment: jest.fn(),
        append_cvss: jest.fn(),
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
    default: ({ defaultProject, defaultScope }: {
        defaultProject?: { id: string } | null;
        defaultScope?: { project_id: string } | null;
    }) => (
        <div>
            <span data-testid="default-project">{defaultProject?.id ?? ''}</span>
            <span data-testid="frontend-scope">{defaultScope?.project_id ?? ''}</span>
        </div>
    ),
}));

jest.mock('../../src/components/MessageBanner', () => ({
    __esModule: true,
    default: ({ message, isVisible }: { message: string; isVisible: boolean }) =>
        isVisible ? <div role="alert">{message}</div> : null,
}));

jest.mock('../../src/components/VersionDisplay', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Metrics', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/TablePackages', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/TableVulnerabilities', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/ScanHistory', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Review', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Settings', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Transfer', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/Exports', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/pages/AIContext', () => ({ __esModule: true, default: () => null }));

const mockConfigGet = Config.get as jest.MockedFunction<typeof Config.get>;
const mockGetFrontendScope = Config.getFrontendScope as jest.MockedFunction<typeof Config.getFrontendScope>;
const mockClearFrontendScope = Config.clearFrontendScope as jest.MockedFunction<typeof Config.clearFrontendScope>;
const mockProjectsList = Projects.list as jest.MockedFunction<typeof Projects.list>;
const mockVariantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const mockPackagesList = Packages.list as jest.MockedFunction<typeof Packages.list>;
const mockVulnerabilitiesList = Vulnerabilities.list as jest.MockedFunction<typeof Vulnerabilities.list>;
const mockAssessmentsList = Assessments.list as jest.MockedFunction<typeof Assessments.list>;

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
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    test('clears a stale project scope and shows a fallback banner', async () => {
        mockGetFrontendScope.mockReturnValue(savedScope('deleted-project', ['old-variant']));
        mockProjectsList.mockResolvedValue([{ id: 'other-project', name: 'Other Project' }]);

        render(<Explorer />);

        await waitFor(() => {
            expect(mockClearFrontendScope).toHaveBeenCalledTimes(1);
            expect(screen.getByTestId('default-project')).toHaveTextContent('default-project');
            expect(screen.getByTestId('frontend-scope')).toBeEmptyDOMElement();
            expect(screen.getByRole('alert')).toHaveTextContent('Saved selection is no longer available');
        });
    });

    test('clears a scope whose saved variant is no longer available', async () => {
        mockGetFrontendScope.mockReturnValue(savedScope('existing-project', ['deleted-variant']));
        mockProjectsList.mockResolvedValue([{ id: 'existing-project', name: 'Existing Project' }]);
        mockVariantsList.mockResolvedValue([{ id: 'current-variant', name: 'Current Variant', project_id: 'existing-project' }]);

        render(<Explorer />);

        await waitFor(() => {
            expect(mockClearFrontendScope).toHaveBeenCalledTimes(1);
            expect(screen.getByTestId('frontend-scope')).toBeEmptyDOMElement();
            expect(screen.getByRole('alert')).toHaveTextContent('Saved selection is no longer available');
        });
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
});