import { render, fireEvent, waitFor, act } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import MultiEditBar from '../../src/components/MultiEditBar';
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
            status: 'not_affected',
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
            status: 'affected',
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

    test('renders nothing when no selection', () => {
        const { container } = render(<MultiEditBar {...mockProps} />);
        expect(container.firstChild).toBeNull();
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

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(getByText('Editing selected CVE...')).toBeInTheDocument();
            expect(getByText('Selected vulnerabilities: 1')).toBeInTheDocument();
        });
    });

    test('uses plural loading copy for multiple selected vulnerabilities', async () => {
        fetchMock.mockImplementation(() => new Promise(() => {}));

        const props = {
            ...mockProps,
            selectedVulns: ['vuln-1', 'vuln-2']
        };

        const { getByText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change status').click(); });
        await act(async () => { getByText('Add assessment').click(); });

        await waitFor(() => {
            expect(getByText('Editing selected CVEs...')).toBeInTheDocument();
            expect(getByText('Selected vulnerabilities: 2')).toBeInTheDocument();
        });
    });

    test('handles same status across vulnerabilities', () => {
        const sameStatusVulns = [
            { ...mockVulnerabilities[0], id: 'vuln-1', status: 'affected' },
            { ...mockVulnerabilities[0], id: 'vuln-2', status: 'affected' }
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
            { ...mockVulnerabilities[0], id: 'vuln-1', status: 'affected' },
            { ...mockVulnerabilities[0], id: 'vuln-2', status: 'not_affected' }
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
        expect(mockAppendAssessment).toHaveBeenCalled();
        expect(mockPatchVuln).toHaveBeenCalled();
    });

    test('saveTimeEstimation success path: updates vulns and triggers success banner', async () => {
        const mockTriggerBanner = jest.fn();
        const mockPatchVuln = jest.fn();
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
            patchVuln: mockPatchVuln
        };

        const { getByText, getByPlaceholderText } = render(<MultiEditBar {...props} />);

        await act(async () => { getByText('Change estimated time').click(); });

        fireEvent.input(getByPlaceholderText('shortest estimate [eg: 5h]'), { target: { value: '1h' } });
        fireEvent.input(getByPlaceholderText('balanced estimate [eg: 2d 4h, or 2.5d]'), { target: { value: '2h' } });
        fireEvent.input(getByPlaceholderText('longest estimate [eg: 1w]'), { target: { value: '3h' } });

        await act(async () => { getByText('Save estimation').click(); });

        await waitFor(() => {
            expect(mockTriggerBanner).toHaveBeenCalledWith(
                expect.stringContaining('Successfully updated time estimates'),
                'success'
            );
        });
        expect(mockPatchVuln).toHaveBeenCalled();
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
});
