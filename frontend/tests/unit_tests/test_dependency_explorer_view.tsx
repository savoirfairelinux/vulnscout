import '@testing-library/jest-dom';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyExplorer from '../../src/components/DependencyExplorer';
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
    render(<DependencyExplorer documents={documents} />);
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
    render(<DependencyExplorer documents={documents} />);
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
    render(<DependencyExplorer documents={[documents[0]]} />);
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

test('changing direction clears the previously selected path rather than presenting it as a reverse path', async () => {
    render(<DependencyExplorer documents={[documents[0]]} focusedPackageId="app" />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('treeitem', { name: 'lib@1.0' }));
    expect(screen.getByRole('list', { name: 'Selected dependency path' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Required by' }));
    expect(screen.queryByRole('list', { name: 'Selected dependency path' })).not.toBeInTheDocument();
    expect(within(screen.getByRole('complementary')).getByRole('heading', { name: 'lib@1.0' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Trace dependents/ })).toHaveTextContent('1 direct');
});

test('terminates circular paths and includes unlinked packages', async () => {
    const cyclic: DependencyDocument = { ...documents[0],
        packages: [...documents[0].packages, { id: 'isolated', name: 'isolated', version: '1' }],
        edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'lib', dependency_id: 'app' }],
    };
    render(<DependencyExplorer documents={[cyclic]} focusedPackageId="app" />);
    const user = userEvent.setup();
    const tree = within(screen.getByRole('tree'));
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    expect(tree.getByText('Cycle')).toBeInTheDocument();
    expect(tree.getAllByRole('treeitem', { name: 'app@1.0' })).toHaveLength(2);
    expect(tree.getAllByRole('button', { name: 'Expand app@1.0' })[0]).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'All packages' }));
    expect(screen.getByRole('treeitem', { name: 'isolated@1' })).toBeInTheDocument();
});

test('browses large branches incrementally and can find packages beyond the first page', async () => {
    const packages = Array.from({ length: 1000 }, (_, index) => ({ id: `pkg-${index}`, name: `pkg-${String(index).padStart(4, '0')}`, version: '1' }));
    render(<DependencyExplorer documents={[{ ...documents[0], packages, edges: packages.slice(1).map(pkg => ({
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

test('starts at the clicked package and resets focus when selecting a different source', async () => {
    render(<DependencyExplorer documents={documents} focusedPackageId="app" />);
    expect(within(screen.getByRole('tree', { name: 'alpha: Depends on' })).getAllByRole('treeitem')).toHaveLength(3);
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-two');
    expect(screen.queryByRole('tree', { name: 'alpha: Depends on' })).not.toBeInTheDocument();
    expect(within(screen.getByRole('tree', { name: 'beta: Depends on' })).getAllByRole('treeitem')).toHaveLength(1);
});

test('shows a bounded neighborhood diagram only on request, with readable node colors', async () => {
    render(<DependencyExplorer documents={[documents[0]]} focusedPackageId="app" />);
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
    render(<DependencyExplorer focusedPackageId="pkg-0" documents={[{ ...documents[0], packages,
        edges: packages.slice(1).map(pkg => ({ package_id: 'pkg-0', dependency_id: pkg.id })) }]} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Graph' }));
    expect(screen.getByRole('status')).toHaveTextContent('Diagram limited to 120 packages');
    expect(screen.getByText('120 of 200 packages within 1 level')).toBeInTheDocument();
});

test('follows a changed package instead of showing the previous root inspection', async () => {
    const view = render(<DependencyExplorer documents={documents} focusedPackageId="app" />);
    await userEvent.setup().click(within(screen.getByRole('tree', { name: 'alpha: Depends on' })).getByRole('treeitem', { name: 'lib@1.0' }));
    const inspector = within(screen.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('heading', { name: 'lib@1.0' })).toBeInTheDocument();
    view.rerender(<DependencyExplorer documents={documents} focusedPackageId="util" />);
    expect(inspector.getByRole('heading', { name: 'util@1.0' })).toBeInTheDocument();
});

test('shows loading, empty, missing package and retry states', async () => {
    const retry = jest.fn();
    const view = render(<DependencyExplorer documents={[]} loading />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading dependency tree');
    view.rerender(<DependencyExplorer documents={[]} error="Unable to load dependencies" onRetry={retry} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(retry).toHaveBeenCalledTimes(1);
    view.rerender(<DependencyExplorer documents={[]} />);
    expect(screen.getByText('No packages in this SBOM scope.')).toBeInTheDocument();
    view.rerender(<DependencyExplorer documents={[{ ...documents[0], packages: [], edges: [] }]} />);
    expect(screen.getByText('No packages in this SBOM scope.')).toBeInTheDocument();
    view.rerender(<DependencyExplorer documents={documents} focusedPackageId="missing" />);
    expect(screen.getByRole('alert')).toHaveTextContent('This package is not in the selected scope.');
});

test('keeps variant sources distinguishable and warns about unrecorded dependencies', () => {
    render(<DependencyExplorer documents={[
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
    render(<DependencyExplorer documents={sourceDocuments} />);
    expect(screen.getByRole('treeitem', { name: 'lib@1.0 (conflicting revisions)' })).toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'source-0');
    expect(screen.getByRole('treeitem', { name: 'lib@1.0 (aaaaaaaaaaaa)' })).toBeInTheDocument();
});

test('preserves commit-based identity when exploring a release-labeled package', async () => {
    const revision = 'a'.repeat(40);
    const id = `lib@${revision}`;
    render(<DependencyExplorer focusedPackageId="app" documents={[{ ...documents[0], packages: [
        { id: 'app', name: 'app', version: '1.0' },
        { id, name: 'lib', version: revision, release_version: '4.1.1', source_revision: revision,
            version_evidence: [{ source: 'purl', version: 'v4.1.1', identifier: 'pkg:generic/lib@v4.1.1' }] },
    ], edges: [{ package_id: 'app', dependency_id: id }] }]} />);
    const user = userEvent.setup();
    const row = screen.getByRole('treeitem', { name: 'lib@4.1.1 (aaaaaaaaaaaa)' });
    expect(within(row).getByText('lib@4.1.1 (aaaaaaaaaaaa)')).toHaveAttribute('title', expect.stringContaining('pkg:generic/lib@v4.1.1'));
    await user.click(row);
    await user.click(screen.getByRole('button', { name: /Explore dependencies/ }));
    expect(screen.getAllByRole('treeitem')).toHaveLength(1);
    expect(screen.getByRole('treeitem', { name: 'lib@4.1.1 (aaaaaaaaaaaa)' })).toBeInTheDocument();
});

test('keeps variant evidence and paths separate and allows hiding every variant', async () => {
    const revisions = ['a'.repeat(40), 'b'.repeat(40)];
    render(<DependencyExplorer focusedPackageId="lib" documents={revisions.map((source_revision, index) => ({
        ...documents[index],
        packages: [{ id: 'lib', name: 'lib', version: '1.0', source_revision },
            { id: `child-${index}`, name: `child-${index}`, version: '1' }],
        edges: [{ package_id: 'lib', dependency_id: `child-${index}` }],
    }))} />);
    const user = userEvent.setup();
    const alpha = within(screen.getByRole('tree', { name: 'alpha: Depends on' }));
    const beta = within(screen.getByRole('tree', { name: 'beta: Depends on' }));
    expect(alpha.getByRole('treeitem', { name: 'lib@1.0 (aaaaaaaaaaaa)' })).toBeInTheDocument();
    expect(alpha.queryByRole('treeitem', { name: 'child-1@1' })).not.toBeInTheDocument();
    expect(beta.getByRole('treeitem', { name: 'lib@1.0 (bbbbbbbbbbbb)' })).toBeInTheDocument();
    expect(beta.queryByRole('treeitem', { name: 'child-0@1' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /beta/ }));
    expect(screen.queryByRole('tree', { name: 'beta: Depends on' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Graph' }));
    expect(within(screen.getByLabelText('Dependency diagram')).queryByText(/bbbbbbbbbbbb/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /alpha/ }));
    expect(screen.queryByLabelText('Dependency diagram')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('No variants selected');
    await user.click(screen.getByRole('checkbox', { name: /beta/ }));
    expect(screen.getByText('Variant: beta', { selector: 'span' })).toBeInTheDocument();
});

test.each([false, true])('selected-source metadata wins while companion endpoints remain available (reversed=%s)', async reversed => {
    const sources: DependencyDocument[] = [
        { ...documents[0], id: 'selected', source_name: 'selected.spdx.json',
            packages: [{ id: 'lib', name: 'lib', version: '1.0', source_revision: null }],
            edges: [{ package_id: 'lib', dependency_id: 'util' }] },
        { ...documents[0], id: 'companion', source_name: 'companion.spdx.json',
            packages: [{ id: 'lib', name: 'lib', version: '1.0', source_revision: 'a'.repeat(40) },
                { id: 'util', name: 'util', version: '2.0', source_revision: 'c'.repeat(40) }], edges: [] },
        { ...documents[1], packages: [{ id: 'util', name: 'util', version: '2.0', source_revision: 'b'.repeat(40) }], edges: [] },
    ];
    render(<DependencyExplorer documents={reversed ? [...sources].reverse() : sources} focusedPackageId="lib" />);
    const user = userEvent.setup();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'selected');
    const tree = within(screen.getByRole('tree'));
    expect(tree.getByRole('treeitem', { name: 'lib@1.0' })).toBeInTheDocument();
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    expect(tree.getByRole('treeitem', { name: 'util@2.0 (cccccccccccc)' })).toBeInTheDocument();
    await user.click(tree.getByRole('treeitem', { name: 'lib@1.0' }));
    await user.click(screen.getByRole('button', { name: 'Graph' }));
    const diagram = within(screen.getByLabelText('Dependency diagram'));
    expect(diagram.getByText('lib@1.0')).toBeInTheDocument();
    expect(diagram.getByText('util@2.0 (cccccccccccc)')).toBeInTheDocument();
    expect(diagram.queryByText(/aaaaaaaaaaaa|bbbbbbbbbbbb/)).not.toBeInTheDocument();
});
