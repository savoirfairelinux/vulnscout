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
            impact_statement: 'Component not in use',
            packages: [],
            variant_ids: undefined
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
            impact_statement: undefined,
            packages: [],
            variant_ids: undefined
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

    test('should show error when false_positive has no impact and external triggerBanner', async () => {
        const triggerBanner = jest.fn();
        const user = userEvent.setup();
        render(<StatusEditor {...defaultProps} triggerBanner={triggerBanner} />);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'false_positive');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(triggerBanner).toHaveBeenCalledWith(
            'You must provide an impact statement for false positive status',
            'error'
        );
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should show internal banner when false_positive has no impact', async () => {
        const user = userEvent.setup();
        render(<StatusEditor {...defaultProps} />);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'false_positive');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(screen.getByTestId('message-banner')).toBeInTheDocument();
        expect(screen.getByText('You must provide an impact statement for false positive status')).toBeInTheDocument();
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should render variant checkboxes when variants prop is provided', () => {
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        render(<StatusEditor {...defaultProps} variants={variants} />);

        expect(screen.getByText('Apply to variants:')).toBeInTheDocument();
        expect(screen.getByText('default')).toBeInTheDocument();
        expect(screen.getByText('release')).toBeInTheDocument();
    });

    test('should show external error when no variant selected and variants are available', async () => {
        const triggerBanner = jest.fn();
        const user = userEvent.setup();
        const variants = [{ id: 'v1', name: 'default', project_id: 'p1' }];
        render(<StatusEditor {...defaultProps} variants={variants} triggerBanner={triggerBanner} />);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(triggerBanner).toHaveBeenCalledWith('You must select at least one variant', 'error');
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should show internal error when no variant selected and variants are available', async () => {
        const user = userEvent.setup();
        const variants = [{ id: 'v1', name: 'default', project_id: 'p1' }];
        render(<StatusEditor {...defaultProps} variants={variants} />);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(screen.getByTestId('message-banner')).toBeInTheDocument();
        expect(screen.getByText('You must select at least one variant')).toBeInTheDocument();
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should submit with selected variant_ids when a variant is checked', async () => {
        const user = userEvent.setup();
        const variants = [{ id: 'v1', name: 'default', project_id: 'p1' }];
        render(<StatusEditor {...defaultProps} variants={variants} />);

        // Check the variant checkbox
        const variantCheckbox = screen.getByRole('checkbox');
        await user.click(variantCheckbox);

        // Change status away from under_investigation (to pass validation)
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith(
            expect.objectContaining({ variant_ids: ['v1'] })
        );
    });

    test('should render package checkboxes when more than one package is available', () => {
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        expect(screen.getByText('Apply to packages:')).toBeInTheDocument();
        expect(screen.getByText('pkg1@1.0.0')).toBeInTheDocument();
        expect(screen.getByText('pkg2@2.0.0')).toBeInTheDocument();
    });

    test('should show external error when no package selected', async () => {
        const triggerBanner = jest.fn();
        const user = userEvent.setup();
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} triggerBanner={triggerBanner} />);

        // Uncheck all packages
        const checkboxes = screen.getAllByRole('checkbox');
        for (const cb of checkboxes) {
            if ((cb as HTMLInputElement).checked) await user.click(cb);
        }

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(triggerBanner).toHaveBeenCalledWith('You must select at least one package', 'error');
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should show internal error when no package selected', async () => {
        const user = userEvent.setup();
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        // Uncheck all packages
        const checkboxes = screen.getAllByRole('checkbox');
        for (const cb of checkboxes) {
            if ((cb as HTMLInputElement).checked) await user.click(cb);
        }

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(screen.getByTestId('message-banner')).toBeInTheDocument();
        expect(screen.getByText('You must select at least one package')).toBeInTheDocument();
        expect(defaultProps.onAddAssessment).not.toHaveBeenCalled();
    });

    test('should toggle package checkboxes correctly', async () => {
        const user = userEvent.setup();
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        const checkboxes = screen.getAllByRole('checkbox');
        // Uncheck one package
        await user.click(checkboxes[0]);
        // Re-check it
        await user.click(checkboxes[0]);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        // Both packages checked → should include both in the call
        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith(
            expect.objectContaining({ packages: expect.arrayContaining(['pkg1@1.0.0', 'pkg2@2.0.0']) })
        );
    });
});
