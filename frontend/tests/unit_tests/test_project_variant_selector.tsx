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

// Three variants so the "union of a subset" path (>= 2 but not all) is testable.
const VARIANTS_PROJ1 = [
    { id: 'var-1', name: 'default', project_id: 'proj-1' },
    { id: 'var-2', name: 'release', project_id: 'proj-1' },
    { id: 'var-3', name: 'staging', project_id: 'proj-1' },
];

const VARIANTS_PROJ2 = [
    { id: 'var-4', name: 'production', project_id: 'proj-2' },
    { id: 'var-5', name: 'candidate', project_id: 'proj-2' },
];

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

async function openPanel() {
    const button = screen.getAllByRole('button')[0];
    await act(async () => { fireEvent.click(button); });
}

async function selectProject(value: string) {
    const projectSelect = screen.getAllByRole('combobox')[0];
    await act(async () => {
        fireEvent.change(projectSelect, { target: { value } });
    });
}


describe('ProjectVariantSelector', () => {

    beforeEach(() => {
        mockProjectsList.mockResolvedValue(PROJECTS);
        mockVariantsList.mockImplementation(projectId => Promise.resolve(
            projectId === 'proj-2' ? VARIANTS_PROJ2 : VARIANTS_PROJ1,
        ));
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    test('renders the trigger button', () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        const button = screen.getByRole('button');
        expect(button).toBeInTheDocument();
    });

    test('shows "Select Project" when no default project is provided', () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
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

    test('shows "All variants" by default even when defaultVariant is supplied', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultVariant={{ id: 'var-1', name: 'default' }}
                onApply={jest.fn()}
            />
        );
        await waitFor(() => {
            expect(screen.getByText('All variants')).toBeInTheDocument();
        });
    });

    // -----------------------------------------------------------------------
    // Panel open / close
    // -----------------------------------------------------------------------

    test('dropdown panel is not visible initially', () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    test('clicking the button opens the dropdown panel', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();
    });

    test('clicking the button again closes the dropdown panel', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();
        await openPanel();
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    test('pressing Escape closes the dropdown panel', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
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
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
            expect(screen.getByRole('option', { name: 'ProjectBeta' })).toBeInTheDocument();
        });
        expect(mockProjectsList).toHaveBeenCalledTimes(1);
    });

    test('loads variants as checkboxes (all checked) when a project is selected', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(mockVariantsList).toHaveBeenCalledWith('proj-1');
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
            expect(screen.getByRole('checkbox', { name: 'release' })).toBeChecked();
            expect(screen.getByRole('checkbox', { name: 'staging' })).toBeChecked();
        });
    });

    // -----------------------------------------------------------------------
    // Mode selection
    // -----------------------------------------------------------------------

    test('Select Variants mode is the default and shows the variant checklist', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        expect(screen.getByRole('radio', { name: /select variants/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /compare variants/i })).not.toBeChecked();
        expect(screen.getByText('Variants')).toBeInTheDocument();
    });

    test('switching to Compare variants mode shows the compare section', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        expect(screen.getByText('Base variant')).toBeInTheDocument();
        expect(screen.getByText('Compare variant')).toBeInTheDocument();
    });

    test('the two modes are mutually exclusive', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        expect(screen.getByRole('radio', { name: /compare variants/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /select variants/i })).not.toBeChecked();
        // Variant checklist is hidden in compare mode
        expect(screen.queryByText('Variants')).not.toBeInTheDocument();
    });

    // -----------------------------------------------------------------------
    // Apply — Select Variants mode
    // -----------------------------------------------------------------------

    test('Apply button is disabled when no project is selected', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    });

    test('Apply with all variants selected calls onApply with project scope', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', '', '', '', [], '');
    });

    test('Apply with a single variant selected calls onApply with that variant id', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        // Clear all, then check only "default" (var-1)
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'default' }));
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', '', '', [], '');
    });

    test('Apply with a subset of variants (>= 2) calls onApply with union variantIds', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        // Clear all, then select var-1 and var-2 (subset of three)
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'default' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'release' }));
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', '', '', '', ['var-1', 'var-2'], 'union');
    });

    test('Clear all disables Apply and shows a warning', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        });
        expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
        expect(screen.getByText('Select at least one variant.')).toBeInTheDocument();
    });

    test('Apply closes the dropdown panel', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    // -----------------------------------------------------------------------
    // Apply — Compare variants mode
    // -----------------------------------------------------------------------

    test('Apply in compare mode calls onApply with base, compare and difference operation', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });

        // Base defaults to var-1, compare to var-2
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', 'var-2', 'difference', [], '');
    });

    test('Apply in compare mode with intersection operation passes correct args', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /intersection/i }));
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-1', 'var-2', 'intersection', [], '');
    });

    test('swap button swaps base and compare variants', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        await act(async () => {
            fireEvent.click(screen.getByTitle('Swap variants'));
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-2', 'var-1', 'difference', [], '');
    });

    // -----------------------------------------------------------------------
    // Reopen restores the currently-applied scope
    // -----------------------------------------------------------------------

    test('reopening restores the applied subset of variants', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        // Apply only var-1 + var-2 (drop var-3)
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'default' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'release' }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenLastCalledWith('proj-1', '', '', '', ['var-1', 'var-2'], 'union');

        // Reopen — the applied selection should be restored
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });
        expect(screen.getByRole('checkbox', { name: 'release' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'staging' })).not.toBeChecked();
    });

    test('reopening discards un-applied edits and shows the applied selection', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        // Apply all variants (project scope)
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });

        // Reopen, uncheck one variant but DON'T apply, then close
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'staging' })).toBeChecked();
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('checkbox', { name: 'staging' }));
        });
        expect(screen.getByRole('checkbox', { name: 'staging' })).not.toBeChecked();
        // Close without applying (Escape)
        await act(async () => {
            fireEvent.keyDown(document, { key: 'Escape' });
        });

        // Reopen — staging should be checked again (applied scope restored)
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'staging' })).toBeChecked();
        });
    });

    test('reopening restores compare mode and its operation', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /intersection/i }));
        });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });

        // Reopen — compare mode + intersection should be restored
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('radio', { name: /compare variants/i })).toBeChecked();
        });
        expect(screen.getByRole('radio', { name: /intersection/i })).toBeChecked();
    });

    test('all variants are checked by default even when defaultVariant is supplied', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultVariant={{ id: 'var-2', name: 'release' }}
                onApply={jest.fn()}
            />
        );
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'release' })).toBeChecked();
        });
        // All variants should be checked by default, not just the configured one
        expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'staging' })).toBeChecked();
    });

    test('restores a persisted single-variant scope', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultScope={{
                    project_id: 'proj-1',
                    mode: 'select',
                    variant_ids: ['var-2'],
                    compare_base_id: '',
                    compare_operation: 'difference',
                    compare_variant_id: '',
                }}
                onApply={jest.fn()}
            />
        );

        await waitFor(() => expect(screen.getByText('release')).toBeInTheDocument());
        await openPanel();
        await waitFor(() => expect(screen.getByRole('checkbox', { name: 'release' })).toBeChecked());
        expect(screen.getByRole('checkbox', { name: 'default' })).not.toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'staging' })).not.toBeChecked();
    });

    test('restores a persisted scope for a project different from the server default', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultScope={{
                    project_id: 'proj-2',
                    mode: 'select',
                    variant_ids: ['var-4'],
                    compare_base_id: '',
                    compare_operation: 'difference',
                    compare_variant_id: '',
                }}
                onApply={jest.fn()}
            />
        );

        await waitFor(() => {
            expect(mockVariantsList).toHaveBeenCalledWith('proj-2');
            expect(screen.getByText('ProjectBeta')).toBeInTheDocument();
            expect(screen.getByText('production')).toBeInTheDocument();
        });
        await openPanel();
        await waitFor(() => expect(screen.getByRole('checkbox', { name: 'production' })).toBeChecked());
        expect(screen.getByRole('checkbox', { name: 'candidate' })).not.toBeChecked();
    });

    test('restores a persisted compare scope', async () => {
        render(
            <ProjectVariantSelector
                defaultProject={{ id: 'proj-1', name: 'ProjectAlpha' }}
                defaultScope={{
                    project_id: 'proj-1',
                    mode: 'compare',
                    variant_ids: [],
                    compare_base_id: 'var-1',
                    compare_operation: 'intersection',
                    compare_variant_id: 'var-2',
                }}
                onApply={jest.fn()}
            />
        );

        await waitFor(() => expect(screen.getByText('default ∩ release')).toBeInTheDocument());
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('radio', { name: /compare variants/i })).toBeChecked();
        });
        expect(screen.getByRole('radio', { name: /intersection/i })).toBeChecked();
    });

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    test('renders gracefully when Projects.list rejects', async () => {
        mockProjectsList.mockRejectedValue(new Error('Network error'));
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.queryByRole('option', { name: 'ProjectAlpha' })).not.toBeInTheDocument();
        });
    });

    test('renders gracefully when Variants.list rejects after selecting a project', async () => {
        mockVariantsList.mockRejectedValue(new Error('Network error'));
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });

        await selectProject('proj-1');

        await waitFor(() => {
            expect(mockVariantsList).toHaveBeenCalledWith('proj-1');
            expect(screen.queryByRole('checkbox', { name: 'default' })).not.toBeInTheDocument();
        });
        expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    });

    // -----------------------------------------------------------------------
    // Panel interactions
    // -----------------------------------------------------------------------

    test('clicking outside the panel closes it', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        expect(screen.getByText('Project & Variant')).toBeInTheDocument();

        await act(async () => {
            fireEvent.mouseDown(document.body);
        });
        expect(screen.queryByText('Project & Variant')).not.toBeInTheDocument();
    });

    test('switching to Compare and back to Select restores the variant checklist', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });
        expect(screen.queryByText('Variants')).not.toBeInTheDocument();

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /select variants/i }));
        });
        expect(screen.getByText('Variants')).toBeInTheDocument();
    });

    test('Select all re-checks every variant after clearing', async () => {
        render(<ProjectVariantSelector onApply={jest.fn()} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        });
        expect(screen.getByRole('checkbox', { name: 'default' })).not.toBeChecked();

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Select all' }));
        });
        expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'release' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'staging' })).toBeChecked();
    });

    test('changing base and compare variant selects updates the applied scope', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('radio', { name: /compare variants/i }));
        });

        // Combobox order in compare mode: [0]=project, [1]=base, [2]=compare
        const combos = screen.getAllByRole('combobox');
        await act(async () => {
            fireEvent.change(combos[1], { target: { value: 'var-2' } });
        });
        await act(async () => {
            fireEvent.change(screen.getAllByRole('combobox')[2], { target: { value: 'var-3' } });
        });

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });
        expect(onApply).toHaveBeenCalledWith('proj-1', 'var-2', 'var-3', 'difference', [], '');
    });

    test('reopening after switching project without applying restores the applied project', async () => {
        const onApply = jest.fn();
        render(<ProjectVariantSelector onApply={onApply} />);
        await openPanel();
        await waitFor(() => {
            expect(screen.getByRole('option', { name: 'ProjectAlpha' })).toBeInTheDocument();
        });
        await selectProject('proj-1');
        await waitFor(() => {
            expect(screen.getByRole('checkbox', { name: 'default' })).toBeChecked();
        });

        // Apply proj-1 (all variants)
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        });

        // Reopen, switch the project dropdown to proj-2 but DON'T apply, then close
        await openPanel();
        await selectProject('proj-2');
        await act(async () => {
            fireEvent.keyDown(document, { key: 'Escape' });
        });

        // Reopen — the applied project (proj-1) should be restored
        await openPanel();
        await waitFor(() => {
            expect((screen.getAllByRole('combobox')[0] as HTMLSelectElement).value).toBe('proj-1');
        });
    });
});
