import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import TableVulnerabilities from '../../src/pages/TableVulnerabilities';
import NvdRefreshHandler from '../../src/handlers/nvdRefresh';

jest.mock('../../src/handlers/nvdRefresh', () => ({
    __esModule: true,
    default: {
        triggerBulkRefresh: jest.fn().mockResolvedValue({ status: 'started' }),
        triggerBulkRefreshForProject: jest.fn().mockResolvedValue({ status: 'started' }),
        getBulkRefreshStatus: jest.fn().mockResolvedValue({ status: 'idle' }),
        getBulkRefreshStatusForProject: jest.fn().mockResolvedValue({ status: 'idle' }),
        triggerSingleRefresh: jest.fn().mockResolvedValue(null),
    },
}));

const minimalProps = {
    vulnerabilities: [],
    appendAssessment: jest.fn(),
    appendCVSS: jest.fn().mockReturnValue(null),
    patchVuln: jest.fn(),
    projectId: 'test-project-id',
};

beforeEach(() => {
    jest.clearAllMocks();
});

describe('TableVulnerabilities — Refresh CVEs button visibility', () => {
    it('renders the Refresh CVEs button when variantId is not provided', () => {
        render(<TableVulnerabilities {...minimalProps} />);
        expect(screen.getByTitle('Refresh CVE data from NVD')).toBeInTheDocument();
    });

    it('renders the Refresh CVEs button when variantId is an empty string', () => {
        render(<TableVulnerabilities {...minimalProps} variantId="" />);
        expect(screen.getByTitle('Refresh CVE data from NVD')).toBeInTheDocument();
    });

    it('renders the Refresh CVEs button when variantId is set', () => {
        render(<TableVulnerabilities {...minimalProps} variantId="variant-uuid" />);
        expect(screen.getByTitle('Refresh CVE data from NVD')).toBeInTheDocument();
    });
});

describe('TableVulnerabilities — Refresh CVEs handler branching', () => {
    it('calls triggerBulkRefreshForProject when no variantId', async () => {
        render(<TableVulnerabilities {...minimalProps} />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => {
            expect(NvdRefreshHandler.triggerBulkRefreshForProject).toHaveBeenCalledWith('test-project-id');
            expect(NvdRefreshHandler.triggerBulkRefresh).not.toHaveBeenCalled();
        });
    });

    it('calls triggerBulkRefresh when variantId is set', async () => {
        render(<TableVulnerabilities {...minimalProps} variantId="variant-uuid" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => {
            expect(NvdRefreshHandler.triggerBulkRefresh).toHaveBeenCalledWith('variant-uuid');
            expect(NvdRefreshHandler.triggerBulkRefreshForProject).not.toHaveBeenCalled();
        });
    });

    it('calls triggerBulkRefreshForProject with filtered ids when no variantId', async () => {
        render(<TableVulnerabilities {...minimalProps} />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('CVEs matching current filters'));
        await waitFor(() => {
            expect(NvdRefreshHandler.triggerBulkRefreshForProject).toHaveBeenCalledWith(
                'test-project-id',
                expect.any(Array),
            );
            expect(NvdRefreshHandler.triggerBulkRefresh).not.toHaveBeenCalled();
        });
    });
});
