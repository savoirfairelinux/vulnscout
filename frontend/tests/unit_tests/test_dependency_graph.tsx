import { useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DependencyGraphView } from '../../src/pages/DependencyGraph';
import type { DependencyDocument } from '../../src/handlers/dependencies';

beforeAll(() => {
    global.ResizeObserver = class implements ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
});

const documents: DependencyDocument[] = [
    {
        id: 'doc-one', source_name: 'packages.spdx.json',
        packages: [
            { id: 'util', name: 'util', version: '1.0' },
            { id: 'app', name: 'app', version: '1.0' },
            { id: 'lib', name: 'lib', version: '1.0' },
        ],
        edges: [
            { package_id: 'app', dependency_id: 'lib' },
            { package_id: 'app', dependency_id: 'util' },
            { package_id: 'lib', dependency_id: 'util' },
        ],
    },
    {
        id: 'doc-two', source_name: 'other.spdx.json',
        packages: [
            { id: 'app', name: 'app', version: '1.0' },
            { id: 'core', name: 'core', version: '2.0' },
        ],
        edges: [{ package_id: 'app', dependency_id: 'core' }],
    },
];

test('sorts checked packages, filters sources, and shows directed edges', async () => {
    render(<DependencyGraphView documents={documents} />);
    const user = userEvent.setup();
    const selector = within(screen.getByRole('complementary', { name: 'Package selector' }));
    const checkboxes = selector.getAllByRole('checkbox') as HTMLInputElement[];

    expect(checkboxes.map(checkbox => checkbox.getAttribute('aria-label'))).toEqual([
        'Show app@1.0', 'Show lib@1.0', 'Show core@2.0', 'Show util@1.0',
    ]);
    expect(checkboxes.every(checkbox => checkbox.checked)).toBe(true);
    expect(screen.getByLabelText('Dependency diagram')).toBeTruthy();
    expect(screen.getByText('4 dependencies from 4 selected packages')).toBeTruthy();

    await user.click(selector.getByRole('checkbox', { name: 'Show app@1.0' }));
    expect(screen.getByText('1 dependencies from 3 selected packages')).toBeTruthy();
    await user.click(selector.getByRole('button', { name: 'None' }));
    expect(screen.getByText('Select packages to display their dependencies.')).toBeTruthy();
    await user.click(selector.getByRole('button', { name: 'All' }));
    expect(screen.getByText('4 dependencies from 4 selected packages')).toBeTruthy();

    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-one');
    expect(selector.getAllByRole('checkbox')).toHaveLength(3);
    expect(screen.getByText('3 dependencies from 3 selected packages')).toBeTruthy();
});

test('focuses one package, then restores the entire graph', async () => {
    function FocusedGraph() {
        const [focusedPackageId, setFocusedPackageId] = useState<string | undefined>('app');
        return <DependencyGraphView documents={documents} focusedPackageId={focusedPackageId}
            onFocusPackage={setFocusedPackageId} onClearFocus={() => setFocusedPackageId(undefined)} />;
    }

    render(<FocusedGraph />);
    const user = userEvent.setup();
    expect(screen.getByText('3 dependencies from 1 selected packages')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Show whole graph' }));
    expect(screen.getByText('4 dependencies from 4 selected packages')).toBeTruthy();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-two');
    expect(screen.getByText('1 dependencies from 2 selected packages')).toBeTruthy();
});

test('paginates large document graphs', async () => {
    const packages = Array.from({ length: 51 }, (_, index) => ({
        id: `pkg-${index}`, name: `pkg-${String(index).padStart(2, '0')}`, version: '1.0',
    }));
    render(<DependencyGraphView documents={[{ id: 'big', source_name: 'big.spdx.json', packages, edges: [] }]} />);

    const user = userEvent.setup();
    expect(screen.getByText('Page 1 of 2')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('Page 2 of 2')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Previous' }));
    expect(screen.getByText('Page 1 of 2')).toBeTruthy();
});

test('shows loading, empty, and retry states', async () => {
    function GraphStates() {
        const [error, setError] = useState('Unable to load dependencies');
        return <DependencyGraphView documents={[]} error={error} onRetry={() => setError('')} />;
    }
    const view = render(<DependencyGraphView documents={[]} loading />);
    expect(screen.getByRole('status').textContent).toContain('Loading');
    view.rerender(<GraphStates />);
    expect(screen.getByRole('alert').textContent).toContain('Unable to load');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(screen.getByText('No packages in this SBOM scope.')).toBeTruthy();
});