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
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
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
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
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
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        render(<StatusEditor {...defaultProps} variants={variants} />);

        // Check the first variant checkbox
        const variantCheckboxes = screen.getAllByRole('checkbox');
        await user.click(variantCheckboxes[0]);

        // Change status away from under_investigation (to pass validation)
        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');

        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith(
            expect.objectContaining({ variant_ids: ['v1'] })
        );
    });

    test('should render package section even with a single package', () => {
        const packages = ['only-pkg@1.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        expect(screen.getByText('Apply to packages:')).toBeInTheDocument();
        expect(screen.getByText('only-pkg@1.0.0')).toBeInTheDocument();
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
        // With multiple packages and no incompatibility map, all start unchecked.
        await user.click(checkboxes[0]);
        await user.click(checkboxes[1]);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        // Both packages checked → should include both in the call
        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith(
            expect.objectContaining({ packages: expect.arrayContaining(['pkg1@1.0.0', 'pkg2@2.0.0']) })
        );
    });

    test('should uncheck a variant and submit with remaining variants', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        render(<StatusEditor {...defaultProps} variants={variants} />);

        const variantCheckboxes = screen.getAllByRole('checkbox');
        // Check both variants
        await user.click(variantCheckboxes[0]);
        await user.click(variantCheckboxes[1]);
        // Uncheck the first variant
        await user.click(variantCheckboxes[0]);

        const statusSelect = screen.getByRole('combobox');
        await user.selectOptions(statusSelect, 'affected');
        const addButton = screen.getByRole('button', { name: 'Add assessment' });
        await user.click(addButton);

        expect(defaultProps.onAddAssessment).toHaveBeenCalledWith(
            expect.objectContaining({ variant_ids: ['v2'] })
        );
    });

    test('should leave multiple packages unchecked by default', () => {
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        expect(checkboxes).toHaveLength(2);
        expect(checkboxes[0].checked).toBe(false);
        expect(checkboxes[1].checked).toBe(false);
    });

    test('should auto-select the package when only one is available', () => {
        const packages = ['only-pkg@1.0.0'];
        render(<StatusEditor {...defaultProps} availablePackages={packages} />);

        const checkbox = screen.getByRole('checkbox') as HTMLInputElement;
        expect(checkbox.checked).toBe(true);
    });

    test('should auto-select the package when a single defaultSelectedPackages is provided', () => {
        const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
        render(
            <StatusEditor
                {...defaultProps}
                availablePackages={packages}
                defaultSelectedPackages={['pkg2@2.0.0']}
            />
        );

        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Order matches availablePackages: pkg1, pkg2
        expect(checkboxes[0].checked).toBe(false);
        expect(checkboxes[1].checked).toBe(true);
    });

    test('should disable variants that lack the selected package', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        const variantPackageMap = {
            v1: ['pkgA@1.0.0'],
            v2: ['pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // checkbox order: v1, v2, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Select pkgA (only present in v1)
        await user.click(checkboxes[2]);

        // v2 has no selected package → disabled; v1 stays enabled
        expect(checkboxes[1].disabled).toBe(true);
        expect(checkboxes[0].disabled).toBe(false);
    });

    test('should disable packages absent from the selected variant', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        const variantPackageMap = {
            v1: ['pkgA@1.0.0'],
            v2: ['pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // checkbox order: v1, v2, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Select v1 (only contains pkgA)
        await user.click(checkboxes[0]);

        // pkgB is not in v1 → disabled; pkgA stays enabled
        expect(checkboxes[3].disabled).toBe(true);
        expect(checkboxes[2].disabled).toBe(false);
    });

    test('should disable a package that is not available in every selected variant', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        // v1 and v2 share pkgA so both variants can be selected together;
        // pkgB exists only in v2.
        const variantPackageMap = {
            v1: ['pkgA@1.0.0'],
            v2: ['pkgA@1.0.0', 'pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // checkbox order: v1, v2, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Select v2 first (reaches both packages), then v1 (shares pkgA so it
        // stays enabled). Both variants end up selected.
        await user.click(checkboxes[1]);
        await user.click(checkboxes[0]);
        expect(checkboxes[0].checked).toBe(true);
        expect(checkboxes[1].checked).toBe(true);

        // pkgB only exists in v2, so it cannot be applied while v1 is selected.
        expect(checkboxes[3].disabled).toBe(true);
        expect(checkboxes[0].checked).toBe(true);
        expect(checkboxes[1].checked).toBe(true);
    });

    test('should drop now-unreachable packages when a variant is unchecked', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        const variantPackageMap = {
            v1: ['pkgA@1.0.0'],
            v2: ['pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // checkbox order: v1, v2, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Select v1 then its package pkgA
        await user.click(checkboxes[0]);
        await user.click(checkboxes[2]);
        expect(checkboxes[2].checked).toBe(true);

        // Unchecking v1 removes pkgA since no other selected variant reaches it
        await user.click(checkboxes[0]);
        expect(checkboxes[2].checked).toBe(false);
    });

    test('should keep packages reachable from a remaining variant when another variant is unchecked', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        // v1 is a subset of v2: both share pkgA, only v2 also has pkgB.
        const variantPackageMap = {
            v1: ['pkgA@1.0.0'],
            v2: ['pkgA@1.0.0', 'pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // checkbox order: v1, v2, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Select both variants (shared pkgA keeps them compatible).
        await user.click(checkboxes[1]);
        await user.click(checkboxes[0]);
        // Check the shared package, which both variants provide.
        await user.click(checkboxes[2]);
        expect(checkboxes[2].checked).toBe(true);

        // Uncheck v2; v1 still provides pkgA, so it must remain selected.
        await user.click(checkboxes[1]);
        expect(checkboxes[1].checked).toBe(false);
        expect(checkboxes[0].checked).toBe(true);
        expect(checkboxes[2].checked).toBe(true);
    });

    test('should clear a package selection when its checkbox is unchecked', async () => {
        const user = userEvent.setup();
        const variants = [
            { id: 'v1', name: 'default', project_id: 'p1' },
        ];
        const packages = ['pkgA@1.0.0', 'pkgB@1.0.0'];
        const variantPackageMap = {
            v1: ['pkgA@1.0.0', 'pkgB@1.0.0'],
        };
        render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={packages}
                variantPackageMap={variantPackageMap}
            />
        );

        // Single variant auto-selects; checkbox order: v1, pkgA, pkgB
        const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
        // Check then uncheck pkgA.
        await user.click(checkboxes[1]);
        expect(checkboxes[1].checked).toBe(true);
        await user.click(checkboxes[1]);
        expect(checkboxes[1].checked).toBe(false);
    });

    test('includes an outdated package only after enabling the option', async () => {
        const user = userEvent.setup();
        render(
            <StatusEditor
                {...defaultProps}
                variants={[{id: 'v1', name: 'default', project_id: 'p1'}]}
                availablePackages={['pkg@2.0.0']}
                defaultSelectedPackages={['pkg@2.0.0']}
                variantPackageMap={{v1: ['pkg@2.0.0']}}
                variantFindingsMap={{v1: [
                    {pkg: 'pkg@2.0.0', outdated: false},
                    {pkg: 'pkg@1.0.0', outdated: true},
                ]}}
            />
        );

        expect(screen.queryByText('pkg@1.0.0')).not.toBeInTheDocument();
        const includeOutdated = screen.getByRole('checkbox', {name: 'Allow new assessments on outdated packages/variant'});
        await user.click(includeOutdated);
        expect(screen.getByText('default').closest('label')!.querySelector('input')).not.toBeChecked();
        expect(screen.getByText('pkg@2.0.0').closest('label')!.querySelector('input')).not.toBeChecked();
        const outdatedPackage = screen.getByText('pkg@1.0.0').closest('label')!.querySelector('input')!;
        await user.click(outdatedPackage);
        expect(screen.queryByText('Outdated')).not.toBeInTheDocument();
        await user.click(includeOutdated);
        await user.click(includeOutdated);
        expect(screen.getByText('pkg@1.0.0').closest('label')!.querySelector('input')).not.toBeChecked();
    });

    test('offers outdated findings when a package is current in another variant', () => {
        render(
            <StatusEditor
                {...defaultProps}
                variants={[
                    {id: 'v1', name: 'current', project_id: 'p1'},
                    {id: 'v2', name: 'historical', project_id: 'p1'},
                ]}
                availablePackages={['pkg@1.0.0']}
                variantPackageMap={{v1: ['pkg@1.0.0'], v2: []}}
                variantFindingsMap={{
                    v1: [{pkg: 'pkg@1.0.0', outdated: false}],
                    v2: [{pkg: 'pkg@1.0.0', outdated: true}],
                }}
            />
        );

        expect(screen.getByRole('checkbox', {name: 'Allow new assessments on outdated packages/variant'})).toBeInTheDocument();
    });

    test('requires every enabled variant to support every selected package', async () => {
        const user = userEvent.setup();
        render(
            <StatusEditor
                {...defaultProps}
                variants={[
                    {id: 'a', name: 'variant a', project_id: 'p'},
                    {id: 'b', name: 'variant b', project_id: 'p'},
                    {id: 'c', name: 'variant c', project_id: 'p'},
                    {id: 'd', name: 'variant d', project_id: 'p'},
                ]}
                availablePackages={['p1@1.0.0', 'p2@1.0.0']}
                variantPackageMap={{
                    a: ['p2@1.0.0'],
                    b: ['p1@1.0.0', 'p2@1.0.0'],
                    c: ['p2@1.0.0'],
                    d: ['p2@1.0.0'],
                }}
                variantFindingsMap={{
                    a: [
                        {pkg: 'p1@1.0.0', outdated: true},
                        {pkg: 'p2@1.0.0', outdated: false},
                    ],
                    b: [
                        {pkg: 'p1@1.0.0', outdated: false},
                        {pkg: 'p2@1.0.0', outdated: false},
                    ],
                    c: [{pkg: 'p2@1.0.0', outdated: false}],
                    d: [{pkg: 'p2@1.0.0', outdated: false}],
                }}
            />
        );

        await user.click(screen.getByRole('checkbox', {name: 'Allow new assessments on outdated packages/variant'}));
        await user.click(screen.getByText('variant a').closest('label')!.querySelector('input')!);
        await user.click(screen.getByText('p1@1.0.0').closest('label')!.querySelector('input')!);
        await user.click(screen.getByText('p2@1.0.0').closest('label')!.querySelector('input')!);

        expect(screen.getByText('variant a').closest('label')!.querySelector('input')).not.toBeDisabled();
        expect(screen.getByText('variant b').closest('label')!.querySelector('input')).not.toBeDisabled();
        expect(screen.getByText('variant c').closest('label')!.querySelector('input')).toBeDisabled();
        expect(screen.getByText('variant d').closest('label')!.querySelector('input')).toBeDisabled();
    });

    test('shows historical finding discovery while scope data loads', () => {
        render(<StatusEditor {...defaultProps} availablePackages={['pkg@2.0.0']} findingsLoading={true} />);
        expect(screen.getByText('Checking for previous package versions…')).toBeInTheDocument();
    });

    test('prunes selected packages by the intersection after scope data changes', async () => {
        const user = userEvent.setup();
        const variants = [
            {id: 'v1', name: 'first', project_id: 'p1'},
            {id: 'v2', name: 'second', project_id: 'p1'},
            {id: 'v3', name: 'third', project_id: 'p1'},
        ];
        const view = render(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={['package@1.0.0']}
                variantPackageMap={{
                    v1: ['package@1.0.0'],
                    v2: ['package@1.0.0'],
                    v3: ['package@1.0.0'],
                }}
            />
        );
        for (const name of ['first', 'second', 'third']) {
            await user.click(screen.getByText(name).closest('label')!.querySelector('input')!);
        }

        view.rerender(
            <StatusEditor
                {...defaultProps}
                variants={variants}
                availablePackages={['package@1.0.0']}
                variantPackageMap={{
                    v1: ['package@1.0.0'],
                    v2: ['package@1.0.0'],
                    v3: [],
                }}
            />
        );
        await user.click(screen.getByText('first').closest('label')!.querySelector('input')!);

        expect(screen.getByText('package@1.0.0').closest('label')!.querySelector('input')).not.toBeChecked();
    });
});
