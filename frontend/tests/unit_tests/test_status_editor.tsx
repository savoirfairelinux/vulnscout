import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import StatusEditor from '../../src/components/StatusEditor';

// Mock MessageBanner component
jest.mock('../../src/components/MessageBanner', () => {
    return function MockMessageBanner({ type, message, isVisible, onClose }: any) {
        if (!isVisible) return null;
        return (
            <div data-testid="message-banner" data-type={type}>
                {message}
                <button onClick={onClose} data-testid="banner-close">Close</button>
            </div>
        );
    };
});

describe('StatusEditor', () => {
    const defaultProps = {
        onAddAssessment: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should render with default values', () => {
        render(<StatusEditor {...defaultProps} />);

        const statusSelect = screen.getByRole('combobox');
        expect(statusSelect).toHaveValue('under_investigation');
        expect(screen.getByRole('button', { name: 'Add assessment' })).toBeInTheDocument();
    });

    test('should render progress bar when progressBar prop is provided', () => {
        render(<StatusEditor {...defaultProps} progressBar={0.5} />);
        
        const progressBar = screen.getByRole('progressbar');
        expect(progressBar).toBeInTheDocument();
        expect(progressBar).toHaveAttribute('value', '0.5');
    });

    test('should show error when not_affected status has no justification and external triggerBanner is provided', async () => {
        const triggerBanner = jest.fn();
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} triggerBanner={triggerBanner} />);

        // Set status to not_affected with justification = none
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'not_affected');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(triggerBanner).toHaveBeenCalledWith(
            "You must provide a justification for this status",
            "error"
        );
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should show internal banner when not_affected status has no justification and no external triggerBanner', async () => {
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} />);

        // Set status to not_affected with justification = none
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'not_affected');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        // Should show internal message banner
        expect(screen.getByTestId('message-banner')).toBeInTheDocument();
        expect(screen.getByText('You must provide a justification for this status')).toBeInTheDocument();
        expect(screen.getByTestId('message-banner')).toHaveAttribute('data-type', 'error');
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should close internal banner when close button is clicked', async () => {
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} />);

        // Trigger error to show banner
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'not_affected');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        // Banner should be visible
        expect(screen.getByTestId('message-banner')).toBeInTheDocument();

        // Click close button
        const closeButton = screen.getByTestId('banner-close');
        await user.click(closeButton);

        // Banner should be hidden
        expect(screen.queryByTestId('message-banner')).not.toBeInTheDocument();
    });

    test('should not add assessment when status is empty', async () => {
        const user = userEvent.setup();
        render(<StatusEditor {...defaultProps} />);

        // Clear the status by setting it to empty
        const statusSelect = screen.getByRole('combobox');
        fireEvent.change(statusSelect, { target: { value: '' } });

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should not add assessment when justification is empty', async () => {
        const user = userEvent.setup();
        render(<StatusEditor {...defaultProps} />);

        // Set status to not_affected first to show justification dropdown
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'not_affected');
        
        // Set justification to empty
        const justificationSelect = screen.getAllByRole('combobox')[1]; // Second combobox
        fireEvent.change(justificationSelect, { target: { value: '' } });

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should call onFieldsChange when fields change from defaults', async () => {
        const onFieldsChange = jest.fn();
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} onFieldsChange={onFieldsChange} />);

        // Initially should be called with false (no changes)
        expect(onFieldsChange).toHaveBeenCalledWith(false);

        // Change status
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');

        // Should be called with true (has changes)
        await waitFor(() => {
            expect(onFieldsChange).toHaveBeenCalledWith(true);
        });
    });

    test('should clear fields when clearFields prop changes to true', async () => {
        const user = userEvent.setup();
        const { rerender } = render(<StatusEditor {...defaultProps} clearFields={false} />);

        // Change some field values
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');

        const statusNotesInput = screen.getByPlaceholderText(/Free text notes/);
        await user.type(statusNotesInput, 'Some notes');

        // Verify fields have changed
        expect(statusSelect).toHaveValue('affected');
        expect(statusNotesInput).toHaveValue('Some notes');

        // Trigger clear
        rerender(<StatusEditor {...defaultProps} clearFields={true} />);

        // Verify fields are cleared
        await waitFor(() => {
            expect(statusSelect).toHaveValue('under_investigation');
            expect(statusNotesInput).toHaveValue('');
        });
    });

    test('should successfully add assessment with valid not_affected status and justification', async () => {
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} />);

        // Set status to not_affected with valid justification
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'not_affected');

        const justificationSelect = screen.getAllByRole('combobox')[1]; // Second combobox
        await user.selectOptions(justificationSelect, 'component_not_present');

        // Add some additional fields
        const impactInput = screen.getByPlaceholderText('why this vulnerability is not exploitable ?');
        await user.type(impactInput, 'Component not in use');

        const statusNotesInput = screen.getByPlaceholderText(/Free text notes/);
        await user.type(statusNotesInput, 'Reviewed and confirmed');

        const workaroundInput = screen.getByPlaceholderText(/Describe workaround/);
        await user.type(workaroundInput, 'No workaround needed');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith({
            status: 'not_affected',
            justification: 'component_not_present',
            status_notes: 'Reviewed and confirmed',
            workaround: 'No workaround needed',
            impact_statement: 'Component not in use'
        });
    });

    test('should add assessment for non-not_affected status without justification or impact', async () => {
        const user = userEvent.setup();
        
        render(<StatusEditor {...defaultProps} />);

        // Set status to affected
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');

        const statusNotesInput = screen.getByPlaceholderText(/Free text notes/);
        await user.type(statusNotesInput, 'Confirmed vulnerability');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith({
            status: 'affected',
            justification: undefined,
            status_notes: 'Confirmed vulnerability',
            workaround: '',
            impact_statement: undefined
        });
    });

    test('should show impact input when status is false_positive', async () => {
        const user = userEvent.setup();
        render(<StatusEditor {...defaultProps} />);

        const statusSelect = screen.getByRole('combobox');
        
        // Test false_positive
        await user.selectOptions(statusSelect, 'false_positive');
        expect(screen.getByPlaceholderText('why this vulnerability is not exploitable ?')).toBeInTheDocument();
    });
});