import { useState } from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyGraph, { DependencyGraphView } from '../../src/pages/DependencyGraph';
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

test('requests the selected comparison and refetches after data refresh', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        json: async () => ({ documents: [documents[0]] }),
    } as Response);
    try {
        const view = render(<DependencyGraph variantId="base" compareVariantId="compare"
            operation="difference" dataRevision={1} />);
        await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
        const firstUrl = new URL(fetchSpy.mock.calls[0][0] as string);
        expect(firstUrl.searchParams.get('variant_id')).toBe('base');
        expect(firstUrl.searchParams.get('compare_variant_id')).toBe('compare');
        expect(firstUrl.searchParams.get('operation')).toBe('difference');

        view.rerender(<DependencyGraph variantId="base" compareVariantId="compare"
            operation="difference" dataRevision={2} />);
        await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2));
    } finally {
        fetchSpy.mockRestore();
    }
});

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

test('clears a selected source when it disappears after a refresh', async () => {
    const view = render(<DependencyGraphView documents={documents} />);
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-two');
    view.rerender(<DependencyGraphView documents={[documents[0]]} />);

    expect((screen.getByRole('combobox', { name: 'SBOM source' }) as HTMLSelectElement).value).toBe('all');
    expect(screen.getByText('Packages (3/3)')).toBeTruthy();
});

test('requires package focus before laying out a large graph', async () => {
    const packages = Array.from({ length: 201 }, (_, index) => ({
        id: `pkg-${index}`, name: `pkg-${index}`, version: '1.0',
    }));
    function LargeGraph() {
        const [focusedPackageId, setFocusedPackageId] = useState<string>();
        return <DependencyGraphView
            documents={[{ id: 'large', source_name: 'large.spdx.json', packages, edges: [] }]}
            focusedPackageId={focusedPackageId} onFocusPackage={setFocusedPackageId}
            onClearFocus={() => setFocusedPackageId(undefined)} />;
    }
    render(<LargeGraph />);
    expect(screen.queryByLabelText('Dependency diagram')).toBeNull();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Focus pkg-0@1.0' }));
    expect(screen.getByLabelText('Dependency diagram')).toBeTruthy();
});

test('bounds the layout for a focused package with many dependencies', () => {
    const packages = Array.from({ length: 251 }, (_, index) => ({
        id: `pkg-${index}`, name: `pkg-${index}`, version: '1.0',
    }));
    const edges = packages.slice(1).map(pkg => ({ package_id: 'pkg-0', dependency_id: pkg.id }));
    render(<DependencyGraphView
        documents={[{ id: 'large', source_name: 'large.spdx.json', packages, edges }]}
        focusedPackageId="pkg-0" />);

    expect(screen.getByLabelText('Dependency diagram')).toBeTruthy();
    expect(screen.getByRole('status').textContent).toContain('Graph limited to 200 packages');
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