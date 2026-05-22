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
        cancelBulkRefresh: jest.fn().mockResolvedValue(undefined),
        cancelBulkRefreshForProject: jest.fn().mockResolvedValue(undefined),
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

describe('TableVulnerabilities — Refresh poll cancellation on scope change', () => {
    it('clears the poll interval and shows cancelled status when variantId changes', async () => {
        const { rerender } = render(<TableVulnerabilities {...minimalProps} variantId="variant-a" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => expect(NvdRefreshHandler.triggerBulkRefresh).toHaveBeenCalled());

        // Simulate switching to a different variant
        rerender(<TableVulnerabilities {...minimalProps} variantId="variant-b" />);

       // Running spinner should be gone; cancelled message should appear
        await waitFor(() => {
           expect(screen.queryByText('Refreshing CVEs from NVD…')).not.toBeInTheDocument();
           expect(screen.getByText('✗ NVD refresh cancelled')).toBeInTheDocument();
       });
       // New trigger should use the new variantId
       fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
       fireEvent.click(screen.getByText('Pending Assessment CVEs'));
       await waitFor(() => {
           expect(NvdRefreshHandler.triggerBulkRefresh).toHaveBeenCalledWith('variant-b');
       });
    });

    it('cancels the backend refresh for the old variant when scope changes', async () => {
        const { rerender } = render(<TableVulnerabilities {...minimalProps} variantId="variant-a" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => expect(NvdRefreshHandler.triggerBulkRefresh).toHaveBeenCalled());

        rerender(<TableVulnerabilities {...minimalProps} variantId="variant-b" />);

        await waitFor(() => {
            expect(NvdRefreshHandler.cancelBulkRefresh).toHaveBeenCalledWith('variant-a');
        });
        expect(NvdRefreshHandler.cancelBulkRefreshForProject).not.toHaveBeenCalled();
    });

    it('cancels the backend refresh for the old project when scope changes', async () => {
        const { rerender } = render(<TableVulnerabilities {...minimalProps} projectId="project-a" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => expect(NvdRefreshHandler.triggerBulkRefreshForProject).toHaveBeenCalled());

        rerender(<TableVulnerabilities {...minimalProps} projectId="project-b" />);

        await waitFor(() => {
            expect(NvdRefreshHandler.cancelBulkRefreshForProject).toHaveBeenCalledWith('project-a');
        });
        expect(NvdRefreshHandler.cancelBulkRefresh).not.toHaveBeenCalled();
    });
});

describe('TableVulnerabilities — Cancel backend refresh on dismiss', () => {
    it('calls cancelBulkRefresh when the dismiss button is clicked during an active variant refresh', async () => {
        // Keep the refresh running so the dismiss button can cancel it
        (NvdRefreshHandler.getBulkRefreshStatus as jest.Mock).mockResolvedValue({ status: 'running', progress: '1/5 CPEs' });

        render(<TableVulnerabilities {...minimalProps} variantId="variant-uuid" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => expect(NvdRefreshHandler.triggerBulkRefresh).toHaveBeenCalled());

        const dismissBtn = await screen.findByLabelText('Dismiss');
        fireEvent.click(dismissBtn);

        await waitFor(() => {
            expect(NvdRefreshHandler.cancelBulkRefresh).toHaveBeenCalledWith('variant-uuid');
        });
    });

    it('shows cancelled notification when dismiss is clicked during a running refresh', async () => {
        (NvdRefreshHandler.getBulkRefreshStatus as jest.Mock).mockResolvedValue({ status: 'running', progress: '2/10 CPEs' });

        render(<TableVulnerabilities {...minimalProps} variantId="variant-uuid" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => screen.findByText('Refreshing CVEs from NVD…'));

        const dismissBtn = await screen.findByLabelText('Dismiss');
        fireEvent.click(dismissBtn);

        await waitFor(() => {
            expect(screen.getByText('✗ NVD refresh cancelled')).toBeInTheDocument();
        });
    });

    it('hides the toast completely when dismiss is clicked on a cancelled status', async () => {
        (NvdRefreshHandler.getBulkRefreshStatus as jest.Mock).mockResolvedValue({ status: 'running', progress: '2/10 CPEs' });

        render(<TableVulnerabilities {...minimalProps} variantId="variant-uuid" />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => screen.findByText('Refreshing CVEs from NVD…'));

        // First dismiss: shows cancelled message
        const dismissBtn = await screen.findByLabelText('Dismiss');
        fireEvent.click(dismissBtn);
        await waitFor(() => expect(screen.getByText('✗ NVD refresh cancelled')).toBeInTheDocument());

        // Second dismiss: hides the toast entirely
        fireEvent.click(screen.getByLabelText('Dismiss'));
        await waitFor(() => {
            expect(screen.queryByText('✗ NVD refresh cancelled')).not.toBeInTheDocument();
        });
    });

    it('calls cancelBulkRefreshForProject when the dismiss button is clicked during an active project refresh', async () => {
        (NvdRefreshHandler.getBulkRefreshStatusForProject as jest.Mock).mockResolvedValue({ status: 'running', progress: '1/5 CPEs' });

        render(<TableVulnerabilities {...minimalProps} />);
        fireEvent.click(screen.getByTitle('Refresh CVE data from NVD'));
        fireEvent.click(screen.getByText('Pending Assessment CVEs'));
        await waitFor(() => expect(NvdRefreshHandler.triggerBulkRefreshForProject).toHaveBeenCalled());

        const dismissBtn = await screen.findByLabelText('Dismiss');
        fireEvent.click(dismissBtn);

        await waitFor(() => {
            expect(NvdRefreshHandler.cancelBulkRefreshForProject).toHaveBeenCalledWith('test-project-id');
        });
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
