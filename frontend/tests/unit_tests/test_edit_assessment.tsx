import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import EditAssessment from '../../src/components/EditAssessment';
import type { Assessment } from '../../src/handlers/assessments';

describe('EditAssessment Component', () => {
    const mockAssessment: Assessment = {
        id: 'test-assessment-id',
        vuln_id: 'CVE-2023-1234',
        packages: ['package@1.0.0'],
        status: 'affected',
        simplified_status: 'active',
        justification: 'test justification',
        impact_statement: 'test impact',
        status_notes: 'test notes',
        workaround: 'test workaround',
        timestamp: '2023-01-01T00:00:00Z',
        responses: []
    };

    const mockOnSave = jest.fn();
    const mockOnCancel = jest.fn();
    const mockOnFieldsChange = jest.fn();
    const mockTriggerBanner = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders component with basic elements', () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        expect(screen.getByText('Edit Assessment')).toBeInTheDocument();
        expect(screen.getByText('Save Changes')).toBeInTheDocument();
        expect(screen.getByText('Cancel')).toBeInTheDocument();
    });

    test('calls onCancel when cancel button clicked', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const cancelButton = screen.getByText('Cancel');
        
        await user.click(cancelButton);
        
        expect(mockOnCancel).toHaveBeenCalled();
    });

    test('calls saveAssessment function when save button clicked', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        expect(mockOnSave).toHaveBeenCalled();
    });

    test('shows internal banner when validation fails', async () => {
        const minimalAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'none'
        };

        render(
            <EditAssessment
                assessment={minimalAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        // Internal banner should appear
        await waitFor(() => {
            expect(screen.getByText('You must provide a justification for this status')).toBeInTheDocument();
        });
    });

    test('closes internal banner when close button clicked', async () => {
        const minimalAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'none'
        };

        render(
            <EditAssessment
                assessment={minimalAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        // Internal banner should appear
        await waitFor(() => {
            expect(screen.getByText('You must provide a justification for this status')).toBeInTheDocument();
        });

        // Find and click the close button on the banner
        const closeButton = screen.getByRole('button', { name: /dismiss/i });
        await user.click(closeButton);

        await waitFor(() => {
            expect(screen.queryByText('You must provide a justification for this status')).not.toBeInTheDocument();
        });
    });

    test('external triggerBanner function is called when provided', async () => {
        const minimalAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'none'
        };

        render(
            <EditAssessment
                assessment={minimalAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                triggerBanner={mockTriggerBanner}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        expect(mockTriggerBanner).toHaveBeenCalledWith(
            'You must provide a justification for this status',
            'error'
        );
        expect(mockOnSave).not.toHaveBeenCalled();
    });

    test('calls onFieldsChange when provided', () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                onFieldsChange={mockOnFieldsChange}
            />
        );

        // Should be called with false initially (no changes)
        expect(mockOnFieldsChange).toHaveBeenCalledWith(false);
    });

    test('resets to original values when clearFields changes', async () => {
        const { rerender } = render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={false}
            />
        );

        // Trigger clearFields
        rerender(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={true}
            />
        );

        // Should render without throwing errors
        expect(screen.getByText('Edit Assessment')).toBeInTheDocument();
    });

    test('handles minimal assessment data', () => {
        const minimalAssessment: Assessment = {
            id: 'minimal-id',
            vuln_id: 'CVE-2023-1234',
            packages: ['package@1.0.0'],
            status: 'under_investigation',
            simplified_status: 'active',
            timestamp: '2023-01-01T00:00:00Z',
            responses: []
            // Missing optional fields
        };

        render(
            <EditAssessment
                assessment={minimalAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        expect(screen.getByText('Edit Assessment')).toBeInTheDocument();
    });

    test('saves assessment for false_positive status without changing status', async () => {
        const fpAssessment: Assessment = {
            ...mockAssessment,
            status: 'false_positive'
        };

        render(
            <EditAssessment
                assessment={fpAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        await user.click(saveButton);
        
        expect(mockOnSave).toHaveBeenCalledWith({
            id: 'test-assessment-id',
            status: 'false_positive',
            justification: undefined,
            status_notes: 'test notes',
            workaround: 'test workaround',
            impact_statement: undefined
        });
    });

    test('modifies input fields and detects changes', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                onFieldsChange={mockOnFieldsChange}
            />
        );

        const user = userEvent.setup();
        
        // Should initially have no changes
        expect(mockOnFieldsChange).toHaveBeenCalledWith(false);
        
        // Modify a field
        const notesField = screen.getByPlaceholderText(/Free text notes/i);
        await user.clear(notesField);
        await user.type(notesField, 'new notes');
        
        // Should detect changes
        expect(mockOnFieldsChange).toHaveBeenCalledWith(true);
    });

    test('correctly handles assessment with all fields undefined', () => {
        const undefinedFieldsAssessment: Assessment = {
            id: 'test-id',
            vuln_id: 'CVE-2023-1234',
            packages: ['package@1.0.0'],
            status: 'affected',
            simplified_status: 'active',
            justification: undefined,
            impact_statement: undefined,
            status_notes: undefined,
            workaround: undefined,
            timestamp: '2023-01-01T00:00:00Z',
            responses: []
        };

        render(
            <EditAssessment
                assessment={undefinedFieldsAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        expect(screen.getByText('Edit Assessment')).toBeInTheDocument();
    });

    test('test resetToOriginal by triggering clearFields multiple times', async () => {
        const { rerender } = render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={false}
            />
        );

        // Trigger clearFields multiple times to test the resetToOriginal function
        rerender(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={true}
            />
        );

        rerender(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={false}
            />
        );

        rerender(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                clearFields={true}
            />
        );

        // Should render without throwing errors
        expect(screen.getByText('Edit Assessment')).toBeInTheDocument();
    });

    test('hides banner when triggerBanner prop is provided', () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                triggerBanner={mockTriggerBanner}
            />
        );

        // Internal banner should not be visible when external trigger is provided
        expect(screen.queryByRole('button', { name: /dismiss/i })).not.toBeInTheDocument();
    });

    test('changes status to not_affected and shows justification field', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const statusSelect = screen.getByDisplayValue(/Affected \/ exploitable/i);
        
        await user.selectOptions(statusSelect, 'not_affected');
        
        // Justification dropdown should appear
        await waitFor(() => {
            expect(screen.getByDisplayValue(/No justification/i)).toBeInTheDocument();
        });
    });

    test('changes status to false_positive and shows impact field', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const statusSelect = screen.getByDisplayValue(/Affected \/ exploitable/i);
        
        await user.selectOptions(statusSelect, 'false_positive');
        
        // Impact field should appear
        await waitFor(() => {
            expect(screen.getByPlaceholderText(/why this vulnerability is not exploitable/i)).toBeInTheDocument();
        });
    });

    test('changes justification field when not_affected status', async () => {
        const notAffectedAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'component_not_present'
        };

        render(
            <EditAssessment
                assessment={notAffectedAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const justificationSelect = screen.getByDisplayValue(/Component not present/i);
        
        await user.selectOptions(justificationSelect, 'code_not_reachable');
        
        await waitFor(() => {
            expect(screen.getByDisplayValue(/The vulnerable code is not invoked at runtime/i)).toBeInTheDocument();
        });
    });

    test('saves assessment with not_affected status and proper justification', async () => {
        const notAffectedAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'component_not_present'
        };

        render(
            <EditAssessment
                assessment={notAffectedAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        expect(mockOnSave).toHaveBeenCalledWith({
            id: 'test-assessment-id',
            status: 'not_affected',
            justification: 'component_not_present',
            status_notes: 'test notes',
            workaround: 'test workaround',
            impact_statement: 'test impact'
        });
    });

    test('modifies status_notes and detects changes', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                onFieldsChange={mockOnFieldsChange}
            />
        );

        const user = userEvent.setup();
        const notesField = screen.getByDisplayValue('test notes');
        
        await user.clear(notesField);
        await user.type(notesField, 'updated notes');
        
        expect(mockOnFieldsChange).toHaveBeenCalledWith(true);
    });

    test('modifies workaround and detects changes', async () => {
        render(
            <EditAssessment
                assessment={mockAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                onFieldsChange={mockOnFieldsChange}
            />
        );

        const user = userEvent.setup();
        const workaroundField = screen.getByDisplayValue('test workaround');
        
        await user.clear(workaroundField);
        await user.type(workaroundField, 'updated workaround');
        
        expect(mockOnFieldsChange).toHaveBeenCalledWith(true);
    });

    test('does not save when justification is empty and required', async () => {
        const notAffectedAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: ''
        };

        render(
            <EditAssessment
                assessment={notAffectedAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
            />
        );

        const user = userEvent.setup();
        const saveButton = screen.getByText('Save Changes');
        
        await user.click(saveButton);
        
        expect(mockOnSave).not.toHaveBeenCalled();
    });

    test('changes all justification options and saves correctly', async () => {
        const notAffectedAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'component_not_present'
        };

        const justificationOptions = [
            'vulnerable_code_not_present',
            'code_not_reachable',
            'requires_configuration',
            'requires_environment',
            'inline_mitigations_already_exist'
        ];

        for (const justOption of justificationOptions) {
            const { unmount } = render(
                <EditAssessment
                    assessment={notAffectedAssessment}
                    onSaveAssessment={mockOnSave}
                    onCancel={mockOnCancel}
                />
            );

            const user = userEvent.setup();
            const justificationSelect = document.querySelector('select[name="edit_assessment_justification"]') as HTMLSelectElement;
            
            await user.selectOptions(justificationSelect, justOption);
            
            const saveButton = screen.getByText('Save Changes');
            await user.click(saveButton);
            
            expect(mockOnSave).toHaveBeenCalledWith(
                expect.objectContaining({
                    justification: justOption
                })
            );
            
            jest.clearAllMocks();
            unmount();
        }
    });

    test('impact field is editable when status is not_affected', async () => {
        const notAffectedAssessment: Assessment = {
            ...mockAssessment,
            status: 'not_affected',
            justification: 'component_not_present',
            impact_statement: 'original impact'
        };

        render(
            <EditAssessment
                assessment={notAffectedAssessment}
                onSaveAssessment={mockOnSave}
                onCancel={mockOnCancel}
                onFieldsChange={mockOnFieldsChange}
            />
        );

        const user = userEvent.setup();
        const impactField = screen.getByDisplayValue('original impact');
        
        await user.clear(impactField);
        await user.type(impactField, 'updated impact');
        
        expect(mockOnFieldsChange).toHaveBeenCalledWith(true);
    });
});
