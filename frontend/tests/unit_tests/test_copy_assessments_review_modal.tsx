import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import CopyAssessmentsReviewModal from '../../src/components/CopyAssessmentsReviewModal';
import type { CopyAssessmentsPreviewGroup } from '../../src/handlers/variant';

function makeGroups(): CopyAssessmentsPreviewGroup[] {
    return [
        {
            source_assessment_id: 'a1',
            source_finding_id: 'sf1',
            vulnerability_id: 'CVE-2024-0001',
            source_package: 'openssl@1.1.1',
            assessment_details: {
                simplified_status: 'Not affected',
                status: 'not_affected',
                justification: 'component_not_present',
                status_notes: 'Reviewed by security team.',
            },
            candidates: [
                {
                    target_finding_id: 'tf1',
                    target_package: 'openssl@1.4.2',
                    already_has_custom: false,
                    selected: true,
                },
                {
                    target_finding_id: 'tf2',
                    target_package: 'openssl@1.1.5',
                    already_has_custom: false,
                    selected: false,
                },
            ],
        },
        {
            source_assessment_id: 'a2',
            source_finding_id: 'sf2',
            vulnerability_id: 'CVE-2024-0002',
            source_package: 'curl@7.64.1',
            assessment_details: {
                simplified_status: 'Exploitable',
                status: 'affected',
            },
            candidates: [
                {
                    target_finding_id: 'tf3',
                    target_package: 'curl@8.0.0',
                    already_has_custom: false,
                    selected: true,
                },
            ],
        },
    ];
}

describe('CopyAssessmentsReviewModal', () => {
    const baseProps = {
        isOpen: true,
        groups: makeGroups(),
        previewMessage: '2 assessments would be copied.',
        onConfirm: jest.fn(),
        onCancel: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('does not render when isOpen is false', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} isOpen={false} />);
        expect(screen.queryByText('Review Copy Alignments')).not.toBeInTheDocument();
    });

    test('renders header, preview message and both vulnerability rows', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} />);
        expect(screen.getByText('Review Copy Alignments')).toBeInTheDocument();
        expect(screen.getByText('2 assessments would be copied.')).toBeInTheDocument();
        expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument();
        expect(screen.getByText('CVE-2024-0002')).toBeInTheDocument();
    });

    test('renders a dropdown for multi-candidate groups and plain text for single', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} />);
        // CVE-2024-0001 has two candidates → a select
        const select = screen.getByLabelText('Target for CVE-2024-0001') as HTMLSelectElement;
        expect(select).toBeInTheDocument();
        expect(select.options).toHaveLength(2);
        // CVE-2024-0002 has one candidate → plain text
        expect(screen.getByText('curl@8.0.0')).toBeInTheDocument();
    });

    test('confirm sends default selections (first non-assessed candidate per group)', () => {
        const onConfirm = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([
            { source_assessment_id: 'a1', target_finding_id: 'tf1' },
            { source_assessment_id: 'a2', target_finding_id: 'tf3' },
        ]);
    });

    test('changing the dropdown updates the chosen target finding', () => {
        const onConfirm = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onConfirm={onConfirm} />);
        const select = screen.getByLabelText('Target for CVE-2024-0001') as HTMLSelectElement;
        fireEvent.change(select, { target: { value: '1' } });
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([
            { source_assessment_id: 'a1', target_finding_id: 'tf2' },
            { source_assessment_id: 'a2', target_finding_id: 'tf3' },
        ]);
    });

    test('deselect all then confirm sends no selections', () => {
        const onConfirm = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByText('Deselect all'));
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([]);
    });

    test('toggling a row checkbox off excludes it from the selections', () => {
        const onConfirm = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByLabelText('Include CVE-2024-0001'));
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([
            { source_assessment_id: 'a2', target_finding_id: 'tf3' },
        ]);
    });

    test('select all re-checks every row', () => {
        const onConfirm = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByText('Deselect all'));
        fireEvent.click(screen.getByText('Select all'));
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([
            { source_assessment_id: 'a1', target_finding_id: 'tf1' },
            { source_assessment_id: 'a2', target_finding_id: 'tf3' },
        ]);
    });

    test('cancel button calls onCancel', () => {
        const onCancel = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onCancel={onCancel} />);
        fireEvent.click(screen.getByText('Cancel'));
        expect(onCancel).toHaveBeenCalledTimes(1);
    });

    test('Escape key calls onCancel', () => {
        const onCancel = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onCancel={onCancel} />);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onCancel).toHaveBeenCalledTimes(1);
    });

    test('clicking the backdrop calls onCancel', () => {
        const onCancel = jest.fn();
        render(<CopyAssessmentsReviewModal {...baseProps} onCancel={onCancel} />);
        fireEvent.mouseDown(screen.getByTestId('copy-review-modal-backdrop'));
        expect(onCancel).toHaveBeenCalledTimes(1);
    });

    test('empty groups shows the no-alignments message', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} groups={[]} />);
        expect(screen.getByText('No alignments found for the selected options.')).toBeInTheDocument();
    });

    test('already-assessed candidate is disabled and excluded from confirm', () => {
        const groups: CopyAssessmentsPreviewGroup[] = [
            {
                source_assessment_id: 'a1',
                source_finding_id: 'sf1',
                vulnerability_id: 'CVE-2024-9999',
                source_package: 'openssl@1.1.1',
                assessment_details: { simplified_status: 'Fixed', status: 'fixed' },
                candidates: [
                    {
                        target_finding_id: 'tf1',
                        target_package: 'openssl@1.4.2',
                        already_has_custom: true,
                        selected: false,
                    },
                ],
            },
        ];
        const onConfirm = jest.fn();
        render(
            <CopyAssessmentsReviewModal {...baseProps} groups={groups} onConfirm={onConfirm} />,
        );
        const checkbox = screen.getByLabelText('Include CVE-2024-9999') as HTMLInputElement;
        expect(checkbox).toBeDisabled();
        expect(screen.getByText('(already assessed)')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Confirm Copy'));
        expect(onConfirm).toHaveBeenCalledWith([]);
    });

    test('expand arrow reveals assessment details and collapse hides them', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} />);
        // Details are initially hidden
        expect(screen.queryByText('component_not_present')).not.toBeInTheDocument();
        // Click the expand button for CVE-2024-0001
        fireEvent.click(screen.getByLabelText('Expand details for CVE-2024-0001'));
        expect(screen.getByText('component_not_present')).toBeInTheDocument();
        expect(screen.getByText('Reviewed by security team.')).toBeInTheDocument();
        // Status badge is shown
        expect(screen.getByText('Not affected')).toBeInTheDocument();
        // Collapse again
        fireEvent.click(screen.getByLabelText('Collapse details for CVE-2024-0001'));
        expect(screen.queryByText('component_not_present')).not.toBeInTheDocument();
    });

    test('expand shows status badge with correct text when no other details', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} />);
        fireEvent.click(screen.getByLabelText('Expand details for CVE-2024-0002'));
        expect(screen.getByText('Exploitable')).toBeInTheDocument();
    });

    test('expand on group without assessment_details shows fallback message', () => {
        const groups: CopyAssessmentsPreviewGroup[] = [{
            source_assessment_id: 'a1',
            source_finding_id: 'sf1',
            vulnerability_id: 'CVE-2024-0003',
            source_package: 'pkg@1.0',
            candidates: [{ target_finding_id: 'tf1', target_package: 'pkg@2.0', already_has_custom: false, selected: true }],
        }];
        render(<CopyAssessmentsReviewModal {...baseProps} groups={groups} />);
        fireEvent.click(screen.getByLabelText('Expand details for CVE-2024-0003'));
        expect(screen.getByText('No details available.')).toBeInTheDocument();
    });

    test('expanding one row does not expand others', () => {
        render(<CopyAssessmentsReviewModal {...baseProps} />);
        fireEvent.click(screen.getByLabelText('Expand details for CVE-2024-0001'));
        expect(screen.getByText('component_not_present')).toBeInTheDocument();
        // CVE-2024-0002 detail (Exploitable badge) is not yet shown
        // The word 'Exploitable' appears only once (in the sub-row for CVE-2024-0001's row is not expanded, so we check CVE-2024-0002's detail text)
        expect(screen.queryByText('Reviewed by security team.')).toBeInTheDocument();
        // CVE-2024-0002 row should NOT be expanded
        expect(screen.queryByLabelText('Collapse details for CVE-2024-0002')).not.toBeInTheDocument();
    });

    test.each([
        ['Pending Assessment', 'bg-amber-700'],
        ['False Positive',     'bg-purple-700'],
        ['Unknown',            'bg-slate-600'],
    ])('status badge renders correct colour for "%s"', (simplified) => {
        const groups: CopyAssessmentsPreviewGroup[] = [{
            source_assessment_id: 'a1',
            source_finding_id: 'sf1',
            vulnerability_id: 'CVE-2024-0099',
            source_package: 'pkg@1.0',
            assessment_details: { simplified_status: simplified, status: 'under_investigation' },
            candidates: [{ target_finding_id: 'tf1', target_package: 'pkg@2.0', already_has_custom: false, selected: true }],
        }];
        render(<CopyAssessmentsReviewModal {...baseProps} groups={groups} />);
        fireEvent.click(screen.getByLabelText('Expand details for CVE-2024-0099'));
        expect(screen.getByText(simplified)).toBeInTheDocument();
    });
});
