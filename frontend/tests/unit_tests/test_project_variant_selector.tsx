import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import ProjectVariantSelector from '../../src/components/ProjectVariantSelector';

// ---------------------------------------------------------------------------
// Mock the handler modules so tests don't make real HTTP requests
// ---------------------------------------------------------------------------

jest.mock('../../src/handlers/project', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
    },
}));

jest.mock('../../src/handlers/variant', () => ({
    __esModule: true,
    default: {
        list: jest.fn(),
    },
}));

import Projects from '../../src/handlers/project';
import Variants from '../../src/handlers/variant';

const mockProjectsList = Projects.list as jest.MockedFunction<typeof Projects.list>;
const mockVariantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;

const PROJECTS = [
    { id: 'proj-1', name: 'ProjectAlpha' },
    { id: 'proj-2', name: 'ProjectBeta' },
];

const VARIANTS_PROJ1 = [
    { id: 'var-1', name: 'default', project_id: 'proj-1' },
    { id: 'var-2', name: 'release', project_id: 'proj-1' },
];


describe('ProjectVariantSelector', () => {

    beforeEach(() => {
        mockProjectsList.mockResolvedValue(PROJECTS);
        mockVariantsList.mockResolvedValue(VARIANTS_PROJ1);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    test('renders the trigger button', () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        // The button should be in the document (layer-group icon + text)
        const button = screen.getByRole('button');
        expect(button).toBeInTheDocument();
    });

    test('shows "Select Project" when no default project is provided', () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        expect(screen.getByText('Select Project')).toBeInTheDocument();
    });

    test('shows default project name when defaultProject prop is supplied', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                onApply={jest.fn()}
            />
        );
        await waitFor(() => {
            expect(screen.getByText('ProjectAlpha')).toBeInTheDocument();
        });
    });

    test('shows default variant name when both defaultProject and defaultVariant are supplied', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultVariant={{ id: 'var-1', name: 'default' }}
                onApply={jest.fn()}
            />
        );
        await waitFor(() => {
            expect(screen.getByText('default')).toBeInTheDocument();
        });
    });

    // -----------------------------------------------------------------------
    // Panel open / close
    // -----------------------------------------------------------------------

    test('dropdown panel is not visible initially', () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    test('clicking the button opens the dropdown panel', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');
        await act(async () => {
            fireEvent.click(button);
        });
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();
    });

    test('clicking the button again closes the dropdown panel', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');

        await act(async () => { fireEvent.click(button); });
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();

        await act(async () => { fireEvent.click(button); });
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    test('pressing Escape closes the dropdown panel', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');

        await act(async () => { fireEvent.click(button); });
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();

        await act(async () => {
            fireEvent.keyDown(document, { key: 'Escape' });
        });
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    // -----------------------------------------------------------------------
    // Project and variant lists in the panel
    // -----------------------------------------------------------------------

    test('loads and displays project options in the dropdown', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
            expect(screen.getByRole('option', { name: 'ProjectBeta' })).toBeInTheDocument();
        });
        expect(mockProjectsList).toHaveBeenCalledTimes(1);
    });

    test('loads variants when a project is selected', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        // Select ProjectAlpha
        const projectSelect = screen.getAllByRole('combobox')[0];
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        await waitFor(() => {
            expect(mockVariantsList).toHaveBeenCalledWith('proj-1');
            expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument();
            expect(screen.getByRole('option', { name: 'release' })).toBeInTheDocument();
        });
    });

    // -----------------------------------------------------------------------
    // Apply button behaviour
    // -----------------------------------------------------------------------

    test('Apply button is disabled when no project is selected', async () => {
        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        expect(applyButton).toBeDisabled();
    });

    test('Apply button calls onApply with selected project and variant ids', async () => {
        const onApply = jest.fn();
        render(
            <ProjectVariantSelector onApply={onApply} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        // Select project
        const [projectSelect, variantSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument();
        });

        // Select variant
        await act(async () => {
            fireEvent.change(variantSelect, { target: { value: 'var-1' } });
        });

        // Click Apply
        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', '', '');
    });

    test('Apply with no variant selected calls onApply with empty variant id', async () => {
        const onApply = jest.fn();
        render(
            <ProjectVariantSelector onApply={onApply} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        // Select project only
        const [projectSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', '', '', '');
    });

    test('Apply closes the dropdown panel', async () => {
        mockProjectsList.mockResolvedValue(PROJECTS);
        const onApply = jest.fn();
        render(
            <ProjectVariantSelector onApply={onApply} />
        );

        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    // -----------------------------------------------------------------------
    // Compare variants feature
    // -----------------------------------------------------------------------

    test('compare variants checkbox is not visible when panel is closed', () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });

    test('compare variants label is present when panel is open', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });
        expect(screen.getByText('Compare variants')).toBeInTheDocument();
    });

    test('compare section is hidden by default', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });
        expect(screen.queryByText('Compare variant (B)')).not.toBeInTheDocument();
    });

    test('checking Compare checkbox shows the compare section', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });

        expect(screen.getByText('Compare variant (B)')).toBeInTheDocument();
    });

    test('unchecking Compare hides the compare section again', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });
        expect(screen.getByText('Compare variant (B)')).toBeInTheDocument();

        await act(async () => { fireEvent.click(checkbox); });
        expect(screen.queryByText('Compare variant (B)')).not.toBeInTheDocument();
    });

    test('Apply is disabled when compare enabled but no compare variant selected', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        expect(applyButton).toBeDisabled();
    });

    test('Apply with compare calls onApply with compareVariantId and default operation', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect, variantSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument();
        });
        await act(async () => {
            fireEvent.change(variantSelect, { target: { value: 'var-1' } });
        });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });

        // Compare select is the last combobox; var-1 is filtered out, so var-2 is available
        await waitFor(() => {
            expect(screen.getAllByRole('combobox').length).toBe(3);
        });
        const compareSelect = screen.getAllByRole('combobox')[2];
        await act(async () => {
            fireEvent.change(compareSelect, { target: { value: 'var-2' } });
        });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', 'var-2', 'difference');
    });

    test('Apply with compare and intersection operation passes correct args', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect, variantSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument();
        });
        await act(async () => {
            fireEvent.change(variantSelect, { target: { value: 'var-1' } });
        });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });

        // Switch to intersection
        const intersectionRadio = screen.getByRole('radio', { name: /intersection/i });
        await act(async () => { fireEvent.click(intersectionRadio); });

        await waitFor(() => {
            expect(screen.getAllByRole('combobox').length).toBe(3);
        });
        const compareSelect = screen.getAllByRole('combobox')[2];
        await act(async () => {
            fireEvent.change(compareSelect, { target: { value: 'var-2' } });
        });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', 'var-2', 'intersection');
    });

    test('unchecking compare passes empty compareVariantId to onApply', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });
        await act(async () => { fireEvent.click(checkbox); });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', '', '', '');
    });

    test('swap button swaps variant A and compare variant B', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        const [projectSelect, variantSelect] = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(projectSelect, { target: { value: 'proj-1' } });
        });
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument();
        });
        await act(async () => {
            fireEvent.change(variantSelect, { target: { value: 'var-1' } });
        });

        const checkbox = screen.getByRole('checkbox');
        await act(async () => { fireEvent.click(checkbox); });

        await waitFor(() => {
            expect(screen.getAllByRole('combobox').length).toBe(3);
        });
        const compareSelect = screen.getAllByRole('combobox')[2];
        await act(async () => {
            fireEvent.change(compareSelect, { target: { value: 'var-2' } });
        });

        const swapButton = screen.getByTitle('Swap variants');
        await act(async () => { fireEvent.click(swapButton); });

        const applyButton = screen.getByRole('button', { name: 'Apply' });
        await act(async () => { fireEvent.click(applyButton); });

        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-2', 'var-1', 'difference');
    });

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    test('renders gracefully when Projects.list rejects', async () => {
        mockProjectsList.mockRejectedValue(new Error('Network error'));

        render(
            <ProjectVariantSelector onApply={jest.fn()} />
        );
        const button = screen.getByRole('button');
        await act(async () => { fireEvent.click(button); });

        await waitFor(() => {
            // No project options (beside the placeholder) should appear
            expect(screen.queryByRole('option', { name: 'ProjectAlpha' })).not.toBeInTheDocument();
        });
    });
});
