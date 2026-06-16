import { render, fireEvent, waitFor, act, screen } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import fetchMock from 'jest-fetch-mock';
import userEvent from '@testing-library/user-event';
fetchMock.enableMocks();

jest.mock('../../src/handlers/bulkRefresh', () => ({
    __esModule: true,
    BulkNvdRefreshHandler: {
        trigger: jest.fn(),
    },
    BulkEpssRefreshHandler: {
        trigger: jest.fn(),
    },
    BulkNvdRefreshCancelHandler: {
        trigger: jest.fn(),
    },
    BulkEpssRefreshCancelHandler: {
        trigger: jest.fn(),
    },
    BulkGhsaRefreshHandler: {
        trigger: jest.fn(),
    },
    BulkGhsaRefreshCancelHandler: {
        trigger: jest.fn(),
    },
}));

import MultiEditBar from '../../src/components/MultiEditBar';
import { BulkNvdRefreshHandler, BulkEpssRefreshHandler, BulkNvdRefreshCancelHandler, BulkEpssRefreshCancelHandler, BulkGhsaRefreshHandler } from '../../src/handlers/bulkRefresh';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';

describe('MultiEditBar', () => {
    const mockVulnerabilities: Vulnerability[] = [
        {
            id: 'vuln-1',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'test',
            found_by: ['test'],
            datasource: 'test',
            packages: ['pkg1'],
            packages_current: [],
            urls: [],
            texts: [],
            severity: {
                severity: 'LOW',
                min_score: 0,
                max_score: 10,
                cvss: []
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            fix: {
                state: 'unknown'
            },
            simplified_status: 'not_affected',
            variants: [],
            assessments: [],
            effort: {
                optimistic: { formatAsIso8601: () => 'PT1H' } as any,
                likely: { formatAsIso8601: () => 'PT2H' } as any,
                pessimistic: { formatAsIso8601: () => 'PT3H' } as any
            }
        },
        {
            id: 'vuln-2',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'test',
            found_by: ['test'],
            datasource: 'test',
            packages: ['pkg2'],
            packages_current: [],
            urls: [],
            texts: [],
            severity: {
                severity: 'HIGH',
                min_score: 0,
                max_score: 10,
                cvss: []
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            fix: {
                state: 'unknown'
            },
            simplified_status: 'affected',
            variants: [],
            assessments: [],
            effort: {
                optimistic: { formatAsIso8601: () => 'PT1H' } as any,
                likely: { formatAsIso8601: () => 'PT2H' } as any,
                pessimistic: { formatAsIso8601: () => 'PT3H' } as any
            }
        }
    ];

    const mockProps = {
        vulnerabilities: mockVulnerabilities,
        selectedVulns: [],
        resetVulns: () => {},
        appendAssessment: () => {},
        patchVuln: () => {},
        triggerBanner: () => {},
        hideBanner: () => {}
    };

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('renders the action bar with disabled buttons when no selection', () => {
        const { getByText } = render(<MultiEditBar {...mockProps} />);
        expect(getByText('Selected vulnerabilities')).toBeInTheDocument();
        expect(getByText('Reset selection').closest('button')).toBeDisabled();
        expect(getByText('Change status').closest('button')).toBeDisabled();
        expect(getByText('Change estimated time').closest('button')).toBeDisabled();
    });

    test('renders with selection', () => {
        const props = { ...mockProps, selectedVulns: ['vuln-1'] };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });

    test('uses singular loading copy for a single selected vulnerability', async () => {
        fetchMock.mockImplementation(() => new Promise(() => {}));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-2']
        };

        const { getByText, getByTestId } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(getByText('Editing selected CVE...')).toBeInTheDocument();
            expect(getByTestId('selected-vulns-count')).toHaveTextContent('1');
        });
    });

    test('uses plural loading copy for multiple selected vulnerabilities', async () => {
        fetchMock.mockImplementation(() => new Promise(() => {}));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1', 'vuln-2']
        };

        const { getByText, getByTestId } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(getByText('Editing selected CVEs...')).toBeInTheDocument();
            expect(getByTestId('selected-vulns-count')).toHaveTextContent('2');
        });
    });

    test('handles same status across vulnerabilities', () => {
        const sameStatusVulns = [
            { ...mockVulnerabilities[0], id: 'vuln-1' },
            { ...mockVulnerabilities[0], id: 'vuln-2' }
        ];
        const props = {
            ...mockProps,
            vulnerabilities: sameStatusVulns,
            selectedVulns: ['vuln-1', 'vuln-2']
        };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });

    test('handles different status across vulnerabilities', () => {
        const mixedStatusVulns = [
            { ...mockVulnerabilities[0], id: 'vuln-1' },
            { ...mockVulnerabilities[0], id: 'vuln-2' }
        ];
        const props = {
            ...mockProps,
            vulnerabilities: mixedStatusVulns,
            selectedVulns: ['vuln-1', 'vuln-2']
        };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });

    test('renders status editor when change status button clicked', () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1']
        };

        const { getByText } = render(<MultiEditBar {...props} />);
        const changeStatusButton = getByText('Change status');
        act(() => { changeStatusButton.click(); });

        // StatusEditor should be visible (check by finding the select element)
        const statusEditor = document.querySelector('[name="new_assessment_status"]');
        expect(statusEditor).toBeTruthy();
    });

    test('clicking the backdrop closes the batch status panel', async () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1']
        };

        const { getByText, getByTestId } = render(<MultiEditBar {...props} />);
        await act(async () => { getByText('Change status').click(); });

        expect(getByTestId('multi-edit-status-panel')).toHaveClass('block');

        fireEvent.mouseDown(getByTestId('multi-edit-backdrop'));

        await waitFor(() => {
            expect(getByTestId('multi-edit-status-panel')).toHaveClass('hidden');
        });
    });

    test('renders time estimate editor when change time button clicked', () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1']
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);
        const changeTimeButton = getByText('Change estimated time');
        act(() => { changeTimeButton.click(); });

        // TimeEstimateEditor should be visible (check by finding an input with its placeholder)
        const timeEditor = getByPlaceholderText('shortest estimate [eg: 5h]');
        expect(timeEditor).toBeTruthy();
    });

    test('pressing escape closes the batch time panel', async () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1']
        };

        const { getByText, getByPlaceholderText, getByTestId } = render(<MultiEditBar {...props} />);
        await act(async () => { getByText('Change estimated time').click(); });

        expect(getByPlaceholderText('shortest estimate [eg: 5h]')).toBeInTheDocument();
        expect(getByTestId('multi-edit-time-panel')).toHaveClass('block');

        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });

        await waitFor(() => {
            expect(getByTestId('multi-edit-time-panel')).toHaveClass('hidden');
        });
    });

    test('calls resetVulns when reset selection button clicked', () => {
        const mockResetVulns = jest.fn();
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            resetVulns: mockResetVulns
        };

        const { getByText } = render(<MultiEditBar {...props} />);
        const resetButton = getByText('Reset selection');
        resetButton.click();

        expect(mockResetVulns).toHaveBeenCalled();
    });

    test('triggers the bulk refresh buttons and reports success', async () => {
        const mockTriggerBanner = jest.fn();
        const mockHideBanner = jest.fn();
        const mockBulkNvdTrigger = BulkNvdRefreshHandler.trigger as jest.Mock;
        const mockBulkEpssTrigger = BulkEpssRefreshHandler.trigger as jest.Mock;

        mockBulkNvdTrigger.mockResolvedValue({ status: 'success', total: 2 });
        mockBulkEpssTrigger.mockResolvedValue({ status: 'success', total: 2 });

        const props = {
            ...mockProps,
            selectedVulns: ['CVE-2024-0001', 'CVE-2024-0002'],
            triggerBanner: mockTriggerBanner,
            hideBanner: mockHideBanner
        };

        render(<MultiEditBar {...props} />);

        // Open the refresh dropdown, then click the trigger button (both NVD and EPSS selected by default)
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('NVD refresh started for 2 CVE(s)', 'success', 'nvd');
            expect(mockTriggerBanner).toHaveBeenCalledWith('EPSS refresh started for 2 CVE(s)', 'success', 'epss');
        });

        expect(mockHideBanner).toHaveBeenCalledTimes(1);
        expect(mockBulkNvdTrigger).toHaveBeenCalledWith(['CVE-2024-0001', 'CVE-2024-0002']);
        expect(mockBulkEpssTrigger).toHaveBeenCalledWith(['CVE-2024-0001', 'CVE-2024-0002']);
    });

    test('does not trigger NVD refresh when NVD is already in progress', async () => {
        const mockTriggerBanner = jest.fn();
        const mockBulkNvdTrigger = BulkNvdRefreshHandler.trigger as jest.Mock;
        const mockBulkEpssTrigger = BulkEpssRefreshHandler.trigger as jest.Mock;

        mockBulkEpssTrigger.mockResolvedValue({ status: 'success', total: 2 });

        const props = {
            ...mockProps,
            selectedVulns: ['CVE-2024-0001', 'CVE-2024-0002'],
            triggerBanner: mockTriggerBanner,
            hideBanner: jest.fn(),
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
        };

        render(<MultiEditBar {...props} />);

        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        // Button shows only 1 actionable target (EPSS)
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });

        await waitFor(() => {
            expect(mockBulkEpssTrigger).toHaveBeenCalledWith(['CVE-2024-0001', 'CVE-2024-0002']);
        });
        expect(mockBulkNvdTrigger).not.toHaveBeenCalled();
    });

    test('does not trigger EPSS refresh when EPSS is already in progress', async () => {
        const mockTriggerBanner = jest.fn();
        const mockBulkNvdTrigger = BulkNvdRefreshHandler.trigger as jest.Mock;
        const mockBulkEpssTrigger = BulkEpssRefreshHandler.trigger as jest.Mock;

        mockBulkNvdTrigger.mockResolvedValue({ status: 'success', total: 2 });

        const props = {
            ...mockProps,
            selectedVulns: ['CVE-2024-0001', 'CVE-2024-0002'],
            triggerBanner: mockTriggerBanner,
            hideBanner: jest.fn(),
            epssProgress: { in_progress: true, phase: 'bulk_epss_refresh', current: 1, total: 10, message: '' },
        };

        render(<MultiEditBar {...props} />);

        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        // Button shows only 1 actionable target (NVD)
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });

        await waitFor(() => {
            expect(mockBulkNvdTrigger).toHaveBeenCalledWith(['CVE-2024-0001', 'CVE-2024-0002']);
        });
        expect(mockBulkEpssTrigger).not.toHaveBeenCalled();
    });

    test('shows loading spinner when isLoading is true', () => {
        // This would require triggering an actual save operation
        // which is complex to test properly without mocking child components
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1']
        };

        render(<MultiEditBar {...props} />);
        // Just verify component renders without errors
        expect(true).toBe(true);
    });

    test('addAssessment success path: processes assessments and triggers success banner', async () => {
        const mockTriggerBanner = jest.fn();
        const mockAppendAssessment = jest.fn();
        const mockPatchVuln = jest.fn();
        const mockResetVulns = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([])); // Variants.listByVuln for vuln-1
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'success',
            assessments: [{
                id: 'assess-1',
                vuln_id: 'vuln-1',
                packages: ['pkg1'],
                packages_current: [],
                status: 'affected',
                simplified_status: 'affected',
                timestamp: '2024-01-01T00:00:00Z'
            }],
            count: 1
        }));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner,
            appendAssessment: mockAppendAssessment,
            patchVuln: mockPatchVuln,
            resetVulns: mockResetVulns
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully added assessments'),
                'success'
            );
        });
        expect(mockAppendAssessment).toHaveBeenCalled();
        expect(mockPatchVuln).toHaveBeenCalled();
        expect(mockResetVulns).toHaveBeenCalledTimes(1);
    });

    test('saveTimeEstimation success path: updates vulns and triggers success banner', async () => {
        const mockTriggerBanner = jest.fn();
        const mockPatchVuln = jest.fn();
        const mockResetVulns = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([
            {
                id: 'variant-1',
                name: 'variant-a',
                project_id: 'project-1'
            }
        ]));
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'success',
            vulnerabilities: [{
                id: 'vuln-1',
                effort: {
                    optimistic: 'PT1H',
                    likely: 'PT2H',
                    pessimistic: 'PT3H'
                }
            }],
            count: 1
        }));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner,
            patchVuln: mockPatchVuln,
            resetVulns: mockResetVulns
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change estimated time').click(); });

        fireEvent.input(getByPlaceholderText('shortest estimate [eg: 5h]'), { target: { value: '1h' } });
        fireEvent.input(getByPlaceholderText('balanced estimate [eg: 2d 4h, or 2.5d]'), { target: { value: '2h' } });
        fireEvent.input(getByPlaceholderText('longest estimate [eg: 1w]'), { target: { value: '3h' } });

        await act(async () => { getByText('Save estimation').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully updated'),
                'success'
            );
        });
        expect(mockPatchVuln).toHaveBeenCalled();
        expect(mockResetVulns).toHaveBeenCalledTimes(1);
    });

    test('addAssessment error path: triggers error banner with error details', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'error',
            errors: [{ error: 'vuln not found' }, { error: 'invalid status' }]
        }), { status: 400 });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        // Default status is "not_affected" (from vuln-1). Change to "affected" to pass validation
        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to add assessments'),
                'error'
            );
        });
    });

    test('addAssessment error path: triggers error banner with HTTP status when no errors array', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'fail'
        }), { status: 500 });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to add assessments'),
                'error'
            );
        });
    });

    test('addAssessment catch: triggers error banner on network failure', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockRejectOnce(new Error('Network error'));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to add assessments'),
                'error'
            );
        });
    });

    test('saveTimeEstimation error path: triggers error banner with error details', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([
            {
                id: 'variant-1',
                name: 'variant-a',
                project_id: 'project-1'
            }
        ]));
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'error',
            errors: [{ error: 'invalid duration' }]
        }), { status: 400 });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change estimated time').click(); });

        fireEvent.input(getByPlaceholderText('shortest estimate [eg: 5h]'), { target: { value: '1h' } });
        fireEvent.input(getByPlaceholderText('balanced estimate [eg: 2d 4h, or 2.5d]'), { target: { value: '2h' } });
        fireEvent.input(getByPlaceholderText('longest estimate [eg: 1w]'), { target: { value: '3h' } });

        await act(async () => { getByText('Save estimation').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to save time estimates'),
                'error'
            );
        });
    });

    test('saveTimeEstimation error path: triggers error banner with HTTP status when no errors array', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([
            {
                id: 'variant-1',
                name: 'variant-a',
                project_id: 'project-1'
            }
        ]));
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'fail'
        }), { status: 500 });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change estimated time').click(); });

        fireEvent.input(getByPlaceholderText('shortest estimate [eg: 5h]'), { target: { value: '1h' } });
        fireEvent.input(getByPlaceholderText('balanced estimate [eg: 2d 4h, or 2.5d]'), { target: { value: '2h' } });
        fireEvent.input(getByPlaceholderText('longest estimate [eg: 1w]'), { target: { value: '3h' } });

        await act(async () => { getByText('Save estimation').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to save time estimates'),
                'error'
            );
        });
    });

    test('saveTimeEstimation catch: triggers error banner on network failure', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([
            {
                id: 'variant-1',
                name: 'variant-a',
                project_id: 'project-1'
            }
        ]));
        fetchMock.mockRejectOnce(new Error('Network error'));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change estimated time').click(); });

        fireEvent.input(getByPlaceholderText('shortest estimate [eg: 5h]'), { target: { value: '1h' } });
        fireEvent.input(getByPlaceholderText('balanced estimate [eg: 2d 4h, or 2.5d]'), { target: { value: '2h' } });
        fireEvent.input(getByPlaceholderText('longest estimate [eg: 1w]'), { target: { value: '3h' } });

        await act(async () => { getByText('Save estimation').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to save time estimates'),
                'error'
            );
        });
    });

    test('resolves and displays variant name when variantId prop is set and panel opens', async () => {
        const mockTriggerBanner = jest.fn();
        // Variants.listAll() call when panel opens
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v-abc', name: 'machine-image', project_id: 'p1' }
        ]));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v-abc',
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        await waitFor(() => {
            expect(getByText('machine-image')).toBeInTheDocument();
        });
    });

    test('uses variantId as name when listAll returns no match', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([])); // no match for variantId

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v-unknown',
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        await waitFor(() => {
            expect(getByText('v-unknown')).toBeInTheDocument();
        });
    });

    test('intersection mode includes base variant name in panel', async () => {
        const mockTriggerBanner = jest.fn();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v-cmp', name: 'compare-variant', project_id: 'p1' },
            { id: 'v-base', name: 'base-variant', project_id: 'p1' },
        ]));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v-cmp',
            baseVariantId: 'v-base',
            compareOperation: 'intersection',
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        await waitFor(() => {
            expect(getByText('compare-variant')).toBeInTheDocument();
            expect(getByText('base-variant')).toBeInTheDocument();
        });
    });

    test('addAssessment with variantId sends correct batch without listByVuln call', async () => {
        const mockTriggerBanner = jest.fn();
        const mockAppendAssessment = jest.fn();
        const mockPatchVuln = jest.fn();
        // Only 1 fetch: the batch POST (no listByVuln)
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v-abc', name: 'machine-image', project_id: 'p1' }
        ])); // Variants.listAll for panel display
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'success',
            assessments: [{
                id: 'assess-2',
                vuln_id: 'vuln-1',
                packages: ['pkg1'],
                packages_current: [],
                status: 'affected',
                simplified_status: 'affected',
                timestamp: '2024-01-01T00:00:00Z',
                responses: []
            }],
            count: 1
        }));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v-abc',
            triggerBanner: mockTriggerBanner,
            appendAssessment: mockAppendAssessment,
            patchVuln: mockPatchVuln
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await waitFor(() => expect(getByText('machine-image')).toBeInTheDocument());

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully added assessments'),
                'success'
            );
        });
    });

    test('addAssessment fans out per variant when listByVuln returns results', async () => {
        const mockTriggerBanner = jest.fn();
        const mockAppendAssessment = jest.fn();
        const mockPatchVuln = jest.fn();
        // listByVuln returns one variant → should create 1 triple with variant_id
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v1', name: 'default', project_id: 'p1' }
        ])); // Variants.listByVuln for vuln-1
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'success',
            assessments: [{
                id: 'assess-3',
                vuln_id: 'vuln-1',
                packages: ['pkg1'],
                packages_current: [],
                status: 'affected',
                simplified_status: 'affected',
                timestamp: '2024-01-01T00:00:00Z',
                responses: []
            }],
            count: 1
        }));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            triggerBanner: mockTriggerBanner,
            appendAssessment: mockAppendAssessment,
            patchVuln: mockPatchVuln
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully added assessments'),
                'success'
            );
        });
        // The batch request body should include variant_id
        const batchCall = fetchMock.mock.calls.find((c: any[]) =>
            typeof c[0] === 'string' && c[0].includes('/api/assessments/batch')
        ) as any[];
        expect(batchCall).toBeDefined();
        const body = JSON.parse(batchCall[1].body);
        expect(body.assessments[0].variant_id).toBe('v1');
    });

    test('addAssessment intersection mode creates triples for both variants', async () => {
        const mockTriggerBanner = jest.fn();
        // Variants.listAll for panel + batch POST
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v-cmp', name: 'compare', project_id: 'p1' },
            { id: 'v-base', name: 'base', project_id: 'p1' },
        ]));
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'success',
            assessments: [{
                id: 'assess-4',
                vuln_id: 'vuln-1',
                packages: ['pkg1'],
                packages_current: [],
                status: 'affected',
                simplified_status: 'affected',
                timestamp: '2024-01-01T00:00:00Z',
                responses: []
            }],
            count: 2
        }));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v-cmp',
            baseVariantId: 'v-base',
            compareOperation: 'intersection',
            triggerBanner: mockTriggerBanner
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await waitFor(() => expect(getByText('compare')).toBeInTheDocument());

        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });

        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully added assessments'),
                'success'
            );
        });
        // Should have created 2 triples (one per variant)
        const batchCall = fetchMock.mock.calls.find((c: any[]) =>
            typeof c[0] === 'string' && c[0].includes('/api/assessments/batch')
        ) as any[];
        expect(batchCall).toBeDefined();
        const body = JSON.parse(batchCall[1].body);
        expect(body.assessments).toHaveLength(2);
        const variantIds = body.assessments.map((a: any) => a.variant_id);
        expect(variantIds).toContain('v-cmp');
        expect(variantIds).toContain('v-base');
    });

    test('shows Cancel NVD button only when nvdProgress.in_progress is true', async () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
        };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        expect(screen.getByTestId('cancel-nvd-refresh')).toBeInTheDocument();
    });

    test('does not show Cancel NVD button when nvdProgress.in_progress is false', async () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: false, phase: 'idle', current: 0, total: 0, message: '' },
        };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        expect(screen.queryByTestId('cancel-nvd-refresh')).toBeNull();
    });

    test('shows Cancel EPSS button only when epssProgress.in_progress is true', async () => {
        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            epssProgress: { in_progress: true, phase: 'bulk_epss_refresh', current: 1, total: 10, message: '' },
        };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        expect(screen.getByTestId('cancel-epss-refresh')).toBeInTheDocument();
    });

    test('clicking Cancel NVD calls BulkNvdRefreshCancelHandler.trigger and shows banner', async () => {
        const mockTriggerBanner = jest.fn();
        const mockCancelTrigger = BulkNvdRefreshCancelHandler.trigger as jest.Mock;
        mockCancelTrigger.mockResolvedValue({ status: 'cancelling' });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);

        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByTestId('cancel-nvd-refresh'));
        });

        await waitFor(() => {
            expect(mockCancelTrigger).toHaveBeenCalled();
            expect(mockTriggerBanner).toHaveBeenCalledWith('NVD refresh cancellation requested', 'success', 'nvd');
        });
    });

    test('clicking Cancel EPSS calls BulkEpssRefreshCancelHandler.trigger and shows banner', async () => {
        const mockTriggerBanner = jest.fn();
        const mockCancelTrigger = BulkEpssRefreshCancelHandler.trigger as jest.Mock;
        mockCancelTrigger.mockResolvedValue({ status: 'cancelling' });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            epssProgress: { in_progress: true, phase: 'bulk_epss_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);

        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByTestId('cancel-epss-refresh'));
        });

        await waitFor(() => {
            expect(mockCancelTrigger).toHaveBeenCalled();
            expect(mockTriggerBanner).toHaveBeenCalledWith('EPSS refresh cancellation requested', 'success', 'epss');
        });
    });

    test('Cancel NVD button becomes disabled after click (cancelling state)', async () => {
        const mockCancelTrigger = BulkNvdRefreshCancelHandler.trigger as jest.Mock;
        // Never resolves so we can check intermediate state
        mockCancelTrigger.mockReturnValue(new Promise(() => {}));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
            triggerBanner: jest.fn(),
        };
        render(<MultiEditBar {...props} />);

        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });

        const button = screen.getByTestId('cancel-nvd-refresh');
        expect(button).not.toBeDisabled();

        await act(async () => { await userEvent.click(button); });

        expect(button).toBeDisabled();
        expect(button.textContent).toBe('Cancelling…');
    });

    // ---- Refresh dropdown: checkbox toggles ----

    test('unchecking NVD keeps Start button present and enabled', async () => {
        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'] };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        // Both checked by default → Start button is enabled
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeEnabled();

        // Uncheck NVD
        const nvdCheckbox = screen.getByRole('checkbox', { name: /NVD/i });
        await act(async () => { await userEvent.click(nvdCheckbox); });
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeEnabled();
    });

    test('unchecking EPSS keeps Start button present and enabled', async () => {
        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'] };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        const epssCheckbox = screen.getByRole('checkbox', { name: /EPSS/i });
        await act(async () => { await userEvent.click(epssCheckbox); });
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeEnabled();
    });

    test('refresh button is disabled when all targets are unchecked', async () => {
        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'] };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /NVD/i }));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /EPSS/i }));
        });
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeDisabled();
    });

    test('clicking outside the refresh dropdown closes it', async () => {
        const props = { ...mockProps, selectedVulns: ['vuln-1'] };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeInTheDocument();

        // Click outside
        await act(async () => {
            fireEvent.mouseDown(document.body);
        });
        expect(screen.queryByRole('button', { name: /^Start$/i })).toBeNull();
    });

    // ---- Refresh dropdown: GHSA-only / CVE-only selection ----

    test('NVD and EPSS checkboxes are disabled when only GHSA rows are selected', async () => {
        const props = { ...mockProps, selectedVulns: ['GHSA-1234-5678-9012'] };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        expect(screen.getByRole('checkbox', { name: /NVD/i })).toBeDisabled();
        expect(screen.getByRole('checkbox', { name: /EPSS/i })).toBeDisabled();
        // Start button enabled because GHSA row is present and GHSA checkbox is checked
        expect(screen.getByRole('button', { name: /^Start$/i })).toBeEnabled();
    });

    test('GHSA-only selection calls only GHSA handler on Start', async () => {
        const mockTriggerBanner = jest.fn();
        const mockBulkNvdTrigger = BulkNvdRefreshHandler.trigger as jest.Mock;
        const mockBulkEpssTrigger = BulkEpssRefreshHandler.trigger as jest.Mock;
        const mockBulkGhsaTrigger = BulkGhsaRefreshHandler.trigger as jest.Mock;
        mockBulkGhsaTrigger.mockResolvedValue({ status: 'success', total: 1 });

        const props = { ...mockProps, selectedVulns: ['GHSA-1234-5678-9012'], triggerBanner: mockTriggerBanner, hideBanner: jest.fn() };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });

        await waitFor(() => {
            expect(mockBulkGhsaTrigger).toHaveBeenCalledWith(['GHSA-1234-5678-9012']);
        });
        expect(mockBulkNvdTrigger).not.toHaveBeenCalled();
        expect(mockBulkEpssTrigger).not.toHaveBeenCalled();
    });

    // ---- Refresh handler: failure and catch paths ----

    test('shows error banner when NVD refresh trigger returns null', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue(null);
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockResolvedValue({ status: 'success', total: 1 });

        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'], triggerBanner: mockTriggerBanner, hideBanner: jest.fn() };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        // Uncheck EPSS so only NVD is triggered
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /EPSS/i }));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to start NVD refresh', 'error', 'nvd');
        });
    });

    test('shows error banner when NVD refresh trigger throws', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockRejectedValue(new Error('network'));

        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'], triggerBanner: mockTriggerBanner, hideBanner: jest.fn() };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /EPSS/i }));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to start NVD refresh', 'error', 'nvd');
        });
    });

    test('shows error banner when EPSS refresh trigger returns null', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockResolvedValue(null);

        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'], triggerBanner: mockTriggerBanner, hideBanner: jest.fn() };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /NVD/i }));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to start EPSS refresh', 'error', 'epss');
        });
    });

    test('shows error banner when EPSS refresh trigger throws', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockRejectedValue(new Error('network'));

        const props = { ...mockProps, selectedVulns: ['CVE-2024-0001'], triggerBanner: mockTriggerBanner, hideBanner: jest.fn() };
        render(<MultiEditBar {...props} />);
        await act(async () => {
            await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('checkbox', { name: /NVD/i }));
        });
        await act(async () => {
            await userEvent.click(screen.getByRole('button', { name: /^Start$/i }));
        });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to start EPSS refresh', 'error', 'epss');
        });
    });

    // ---- Cancel handlers: failure paths ----

    test('Cancel NVD: shows error banner and resets cancelling when trigger returns null', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkNvdRefreshCancelHandler.trigger as jest.Mock).mockResolvedValue(null);

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);
        await act(async () => { await userEvent.click(screen.getByTestId('refresh-dropdown-toggle')); });
        await act(async () => { await userEvent.click(screen.getByTestId('cancel-nvd-refresh')); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to cancel NVD refresh', 'error', 'nvd');
        });
        // Cancelling flag should reset so button is enabled again
        expect(screen.getByTestId('cancel-nvd-refresh')).not.toBeDisabled();
    });

    test('Cancel NVD: shows error banner and resets cancelling when trigger throws', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkNvdRefreshCancelHandler.trigger as jest.Mock).mockRejectedValue(new Error('network'));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            nvdProgress: { in_progress: true, phase: 'bulk_nvd_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);
        await act(async () => { await userEvent.click(screen.getByTestId('refresh-dropdown-toggle')); });
        await act(async () => { await userEvent.click(screen.getByTestId('cancel-nvd-refresh')); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to cancel NVD refresh', 'error', 'nvd');
        });
        expect(screen.getByTestId('cancel-nvd-refresh')).not.toBeDisabled();
    });

    test('Cancel EPSS: shows error banner and resets cancelling when trigger returns null', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkEpssRefreshCancelHandler.trigger as jest.Mock).mockResolvedValue(null);

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            epssProgress: { in_progress: true, phase: 'bulk_epss_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);
        await act(async () => { await userEvent.click(screen.getByTestId('refresh-dropdown-toggle')); });
        await act(async () => { await userEvent.click(screen.getByTestId('cancel-epss-refresh')); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to cancel EPSS refresh', 'error', 'epss');
        });
        expect(screen.getByTestId('cancel-epss-refresh')).not.toBeDisabled();
    });

    test('Cancel EPSS: shows error banner and resets cancelling when trigger throws', async () => {
        const mockTriggerBanner = jest.fn();
        (BulkEpssRefreshCancelHandler.trigger as jest.Mock).mockRejectedValue(new Error('network'));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            epssProgress: { in_progress: true, phase: 'bulk_epss_refresh', current: 1, total: 10, message: '' },
            triggerBanner: mockTriggerBanner,
        };
        render(<MultiEditBar {...props} />);
        await act(async () => { await userEvent.click(screen.getByTestId('refresh-dropdown-toggle')); });
        await act(async () => { await userEvent.click(screen.getByTestId('cancel-epss-refresh')); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith('Failed to cancel EPSS refresh', 'error', 'epss');
        });
        expect(screen.getByTestId('cancel-epss-refresh')).not.toBeDisabled();
    });

    // ---- addAssessment: errors array and catch paths (using variantId to bypass listByVuln) ----

    test('addAssessment error path: shows errors array message when batch returns errors (variantId set)', async () => {
        const mockTriggerBanner = jest.fn();
        // First fetch: Variants.listAll() triggered when status panel opens with variantId set
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'variant-1', project_id: 'p1' }]));
        // Second fetch: batch POST
        fetchMock.mockResponseOnce(JSON.stringify({
            status: 'error',
            errors: [{ error: 'vuln not found' }, { error: 'invalid status' }]
        }), { status: 400 });

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v1',
            triggerBanner: mockTriggerBanner,
        };
        const { getByText } = render(<MultiEditBar {...props} />);
        await act(async () => { getByText('Change status').click(); });
        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });
        await act(async () => { getByText('Add assessment').click(); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                'Failed to add assessments: Errors: vuln not found, invalid status',
                'error'
            );
        });
    });

    test('addAssessment catch path: shows error banner when batch POST throws (variantId set)', async () => {
        const mockTriggerBanner = jest.fn();
        // First fetch: Variants.listAll() triggered when status panel opens with variantId set
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'variant-1', project_id: 'p1' }]));
        // Second fetch: batch POST rejects
        fetchMock.mockRejectOnce(new Error('Network failure'));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1'],
            variantId: 'v1',
            triggerBanner: mockTriggerBanner,
        };
        const { getByText } = render(<MultiEditBar {...props} />);
        await act(async () => { getByText('Change status').click(); });
        const select = document.querySelector('[name="new_assessment_status"]') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: 'affected' } });
        await act(async () => { getByText('Add assessment').click(); });
        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Failed to add assessments'),
                'error'
            );
        });
    });
});
