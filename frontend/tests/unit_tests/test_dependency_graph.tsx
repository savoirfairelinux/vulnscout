import { useState } from 'react';
import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyGraph, { DependencyGraphView } from '../../src/pages/DependencyGraph';
import { listDependencies } from '../../src/handlers/dependencies';
import type { DependencyDocument } from '../../src/handlers/dependencies';

jest.mock('../../src/handlers/dependencies', () => ({ listDependencies: jest.fn() }));
const mockListDependencies = jest.mocked(listDependencies);

beforeAll(() => {
    global.ResizeObserver = class implements ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
});

const documents: DependencyDocument[] = [
    {
        id: 'doc-one', source_name: 'packages.spdx.json', variant_id: 'v1', variant_name: 'alpha', dependencies_recorded: true,
        packages: [
            { id: 'util', name: 'util', version: '1.0' },
            { id: 'app', name: 'app', version: '1.0' },
            { id: 'lib', name: 'lib', version: '1.0' },
        ],
        edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'app', dependency_id: 'util' },
            { package_id: 'lib', dependency_id: 'util' }],
    },
    {
        id: 'doc-two', source_name: 'other.spdx.json', variant_id: 'v2', variant_name: 'beta', dependencies_recorded: true,
        packages: [{ id: 'app', name: 'app', version: '1.0' }, { id: 'core', name: 'core', version: '2.0' }],
        edges: [{ package_id: 'app', dependency_id: 'core' }],
    },
];

test('starts with a compact tree and progressively explores full transitive paths', async () => {
    render(<DependencyGraphView documents={documents} />);
    const user = userEvent.setup();
    const tree = within(screen.getByRole('tree', { name: 'alpha: Depends on' }));
    expect(tree.getAllByRole('treeitem')).toHaveLength(1);
    expect(screen.queryByLabelText('Dependency diagram')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Graph' })).toBeDisabled();
    await user.click(tree.getByRole('button', { name: 'Expand app@1.0' }));
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    expect(tree.getAllByRole('treeitem', { name: 'util@1.0' })).toHaveLength(2);
    expect(tree.getByRole('treeitem', { name: 'lib@1.0' })).toHaveAttribute('aria-level', '2');
    expect(tree.getAllByRole('treeitem', { name: 'util@1.0' })[0]).toHaveAttribute('aria-level', '3');
    await user.click(tree.getByRole('treeitem', { name: 'lib@1.0' }));
    const inspector = within(screen.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('heading', { name: 'lib@1.0' })).toBeInTheDocument();
    expect(inspector.getByRole('button', { name: /Explore dependencies/ })).toHaveTextContent('1 direct');
    expect(inspector.getByText('packages.spdx.json')).toBeInTheDocument();
    expect(inspector.queryByText('other.spdx.json')).not.toBeInTheDocument();
    expect(within(inspector.getByRole('list', { name: 'Selected dependency path' })).getAllByRole('button')).toHaveLength(2);
    await user.click(tree.getAllByRole('treeitem', { name: 'util@1.0' })[0]);
    expect(tree.getAllByRole('treeitem', { selected: true })).toHaveLength(1);
});

test('searches all packages and traces dependents without losing transitive paths', async () => {
    render(<DependencyGraphView documents={documents} />);
    const user = userEvent.setup();
    await user.type(screen.getByRole('searchbox', { name: 'Find a package' }), 'util');
    expect(screen.getByText('1 package matches')).toBeInTheDocument();
    await user.click(within(screen.getByRole('list', { name: 'Package search results' })).getByRole('button'));
    expect(screen.getByRole('searchbox')).toHaveValue('');
    const inspector = within(screen.getByRole('complementary', { name: 'Package inspector' }));
    await user.click(inspector.getByRole('button', { name: /Trace dependents/ }));
    const tree = within(screen.getByRole('tree', { name: 'alpha: Required by' }));
    expect(tree.getByRole('treeitem', { name: 'app@1.0' })).toBeInTheDocument();
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    expect(tree.getAllByRole('treeitem', { name: 'app@1.0' })).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'All packages' }));
    expect(screen.getByRole('tree', { name: 'beta: Required by' })).toBeInTheDocument();
});

test('keyboard navigation expands, selects, traverses, and collapses branches', () => {
    render(<DependencyGraphView documents={[documents[0]]} />);
    const tree = within(screen.getByRole('tree'));
    const root = tree.getByRole('treeitem', { name: 'app@1.0' });
    act(() => root.focus());
    fireEvent.keyDown(root, { key: 'ArrowRight' });
    expect(root).toHaveAttribute('aria-expanded', 'true');
    fireEvent.keyDown(root, { key: 'ArrowRight' });
    const child = tree.getByRole('treeitem', { name: 'lib@1.0' });
    expect(child).toHaveFocus();
    fireEvent.keyDown(child, { key: 'Enter' });
    expect(child).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(child, { key: 'ArrowLeft' });
    expect(root).toHaveFocus();
    fireEvent.keyDown(root, { key: 'ArrowLeft' });
    expect(tree.getAllByRole('treeitem')).toHaveLength(1);
});

test('terminates circular paths and includes unlinked packages', async () => {
    const cyclic: DependencyDocument = { ...documents[0],
        packages: [...documents[0].packages, { id: 'isolated', name: 'isolated', version: '1' }],
        edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'lib', dependency_id: 'app' }],
    };
    render(<DependencyGraphView documents={[cyclic]} focusedPackageId="app" />);
    const user = userEvent.setup();
    const tree = within(screen.getByRole('tree'));
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    expect(tree.getByText('Cycle')).toBeInTheDocument();
    expect(tree.getAllByRole('treeitem', { name: 'app@1.0' })).toHaveLength(2);
    expect(tree.getAllByRole('button', { name: 'Expand app@1.0' })[0]).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'All packages' }));
});

test('browses large branches incrementally and can find packages beyond the first page', async () => {
    const packages = Array.from({ length: 1000 }, (_, index) => ({ id: `pkg-${index}`, name: `pkg-${String(index).padStart(4, '0')}`, version: '1' }));
    render(<DependencyGraphView documents={[{ ...documents[0], packages, edges: packages.slice(1).map(pkg => ({
        package_id: 'pkg-0', dependency_id: pkg.id,
    })) }]} />);
    const user = userEvent.setup();
    const tree = within(screen.getByRole('tree'));
    await user.click(tree.getByRole('button', { name: 'Expand pkg-0000@1' }));
    expect(tree.getAllByRole('treeitem')).toHaveLength(42);
    await user.click(tree.getByRole('treeitem', { name: 'Show more packages (40 shown)' }));
    expect(tree.getAllByRole('treeitem')).toHaveLength(82);
    expect(tree.getByRole('treeitem', { name: 'pkg-0041@1' })).toHaveFocus();
    await user.type(screen.getByRole('searchbox'), 'pkg-0999');
    expect(within(screen.getByRole('list', { name: 'Package search results' })).getByRole('button')).toHaveTextContent('pkg-0999@1');
});

test('preserves bookmark focus and resets it when selecting a different source', async () => {
    function FocusedGraph() {
        const [focusedPackageId, setFocusedPackageId] = useState<string | undefined>('app');
        return <DependencyGraphView documents={documents} focusedPackageId={focusedPackageId}
            onFocusPackage={setFocusedPackageId} onClearFocus={() => setFocusedPackageId(undefined)} />;
    }
    render(<FocusedGraph />);
    expect(within(screen.getByRole('tree', { name: 'alpha: Depends on' })).getAllByRole('treeitem')).toHaveLength(3);
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-two');
    expect(screen.queryByRole('tree', { name: 'alpha: Depends on' })).not.toBeInTheDocument();
    expect(within(screen.getByRole('tree', { name: 'beta: Depends on' })).getAllByRole('treeitem')).toHaveLength(1);
});

test('shows a bounded neighborhood diagram only on request, with readable node colors', async () => {
    render(<DependencyGraphView documents={[documents[0]]} focusedPackageId="app" />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Graph' }));
    expect(screen.getByLabelText('Dependency diagram')).toBeInTheDocument();
    expect(screen.getByText('3 of 3 packages within 1 level')).toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Graph depth' }), '2');
    expect(screen.getByText('3 of 3 packages within 2 levels')).toBeInTheDocument();
    await user.type(screen.getByRole('searchbox'), 'lib');
    await user.click(screen.getByRole('button', { name: 'Back to tree' }));
    expect(screen.getByRole('tree')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Tree' })).toHaveAttribute('aria-pressed', 'true');
});

test('explicitly reports diagram limits without limiting the full tree', async () => {
    const packages = Array.from({ length: 200 }, (_, index) => ({ id: `pkg-${index}`, name: `pkg-${index}`, version: '1' }));
    render(<DependencyGraphView focusedPackageId="pkg-0" documents={[{ ...documents[0], packages,
        edges: packages.slice(1).map(pkg => ({ package_id: 'pkg-0', dependency_id: pkg.id })) }]} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Graph' }));
    expect(screen.getByRole('status')).toHaveTextContent('Diagram limited to 120 packages');
    expect(screen.getByText('120 of 200 packages within 1 level')).toBeInTheDocument();
});

test('follows a changed bookmark instead of showing the previous root inspection', async () => {
    const focus = jest.fn();
    const view = render(<DependencyGraphView documents={documents} focusedPackageId="app" onFocusPackage={focus} />);
    await userEvent.setup().click(within(screen.getByRole('tree', { name: 'alpha: Depends on' })).getByRole('treeitem', { name: 'lib@1.0' }));
    const inspector = within(screen.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('heading', { name: 'lib@1.0' })).toBeInTheDocument();
    view.rerender(<DependencyGraphView documents={documents} focusedPackageId="util" onFocusPackage={focus} />);
    expect(inspector.getByRole('heading', { name: 'util@1.0' })).toBeInTheDocument();
});

test('shows loading, empty, missing bookmark and retry states', async () => {
    const retry = jest.fn();
    const view = render(<DependencyGraphView documents={[]} loading />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading dependency tree');
    view.rerender(<DependencyGraphView documents={[]} error="Unable to load dependencies" onRetry={retry} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(retry).toHaveBeenCalledTimes(1);
    view.rerender(<DependencyGraphView documents={[]} />);
    expect(screen.getByText('No packages in this SBOM scope.')).toBeInTheDocument();
    view.rerender(<DependencyGraphView documents={documents} focusedPackageId="missing" />);
    expect(screen.getByRole('alert')).toHaveTextContent('The bookmarked package is not in this scope.');
});

test('uses staging comparison semantics and reloads after the scope or data changes', async () => {
    mockListDependencies.mockResolvedValue([]);
    const view = render(<DependencyGraph variantId="v1" projectId="p1" compareVariantId="v2" operation="difference" dataRevision={1} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'difference'));
    await screen.findByText('No packages in this SBOM scope.');
    view.rerender(<DependencyGraph variantId="v1" projectId="p1" compareVariantId="v2" operation="intersection" dataRevision={1} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'intersection'));
    view.rerender(<DependencyGraph projectId="p1" variantIds={['v1', 'v2']} operation="intersection" dataRevision={1} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith(undefined, 'p1', ['v1', 'v2'], undefined, 'intersection'));
    const calls = mockListDependencies.mock.calls.length;
    view.rerender(<DependencyGraph projectId="p1" variantIds={['v1', 'v2']} operation="intersection" dataRevision={2} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenCalledTimes(calls + 1));
});

test('surfaces request failures and retries', async () => {
    mockListDependencies.mockRejectedValueOnce(new Error('Request failed')).mockResolvedValueOnce([]);
    render(<DependencyGraph projectId="p1" />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load dependencies');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    await screen.findByText('No packages in this SBOM scope.');
    expect(mockListDependencies).toHaveBeenCalledTimes(2);
});

test('keeps variant sources distinguishable and warns about unrecorded dependencies', () => {
    render(<DependencyGraphView documents={[
        { ...documents[0], source_name: 'same.spdx.json' },
        { ...documents[1], source_name: 'same.spdx.json', dependencies_recorded: false },
    ]} />);
    expect(screen.getByRole('option', { name: 'alpha: same.spdx.json' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'beta: same.spdx.json' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Re-import them to record dependencies');
});

test('preserves release and revision evidence across source filtering', async () => {
    const revision = 'a'.repeat(40);
    const sourceDocuments: DependencyDocument[] = ['a'.repeat(40), 'b'.repeat(40)].map((source_revision, index) => ({
        ...documents[0], id: `source-${index}`, source_name: `source-${index}.spdx.json`,
        packages: [{ id: `lib@${revision}`, name: 'lib', version: revision, release_version: '1.0', source_revision }], edges: [],
    }));
    render(<DependencyGraphView documents={sourceDocuments} />);
    expect(screen.getByRole('treeitem', { name: 'lib@1.0 (conflicting revisions)' })).toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'source-0');
    expect(screen.getByRole('treeitem', { name: 'lib@1.0 (aaaaaaaaaaaa)' })).toBeInTheDocument();
});
