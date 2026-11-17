import '@testing-library/jest-dom';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyModal from '../../src/components/DependencyModal';
import DependencyExplorer from '../../src/components/DependencyExplorer';
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

beforeEach(() => mockListDependencies.mockReset());

const documents: DependencyDocument[] = [{
    id: 'doc-one', source_name: 'packages.spdx.json', variant_id: 'v1', variant_name: 'alpha', dependencies_recorded: true,
    packages: [
        { id: 'app', name: 'app', version: '1.0' },
        { id: 'lib', name: 'lib', version: '1.0' },
        { id: 'util', name: 'util', version: '1.0' },
    ],
    edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'lib', dependency_id: 'util' }],
}];

test('inspects each imported declaration without multiplying graph links or counts', async () => {
    const declared: DependencyDocument[] = [{ ...documents[0], edges: [{
        package_id: 'app', dependency_id: 'lib',
        declarations: [
            { relationship_type: 'dependsOn', lifecycle_scope: 'runtime',
                source_document_id: 'doc-one', source_name: 'packages.spdx.json' },
            { relationship_type: 'dependsOn', lifecycle_scope: 'build',
                source_document_id: 'doc-one', source_name: 'packages.spdx.json' },
            { relationship_type: 'hasPrerequisite', lifecycle_scope: '',
                source_document_id: 'doc-two', source_name: 'companion.spdx.json' },
        ],
    }] }];
    render(<DependencyExplorer documents={declared} focusedPackageId="app" />);
    expect(screen.getAllByText('Deps: 1 / Req by: 0')).toHaveLength(1);
    expect(screen.getByRole('list', { name: 'Relationship counts' })).toHaveTextContent('Depends on1 direct');
    const user = userEvent.setup();
    await user.click(screen.getByText('Inspect dependency links'));
    await user.click(screen.getByRole('button', { name: 'Inspect app depends on lib' }));
    const details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getAllByText('Relationship: dependsOn')).toHaveLength(2);
    for (const value of ['Lifecycle scope: Runtime', 'Lifecycle scope: Build', 'Lifecycle scope: Unspecified',
        'Relationship: hasPrerequisite', 'Source: companion.spdx.json']) {
        expect(details.getByText(value)).toBeTruthy();
    }
    expect(details.getByText(/not proof that a vulnerable function is reachable/)).toBeTruthy();
    await user.click(details.getByRole('button', { name: 'Close link details' }));
    expect(screen.queryByRole('dialog')).toBeNull();
});

test('legacy edges show unspecified metadata and the SBOM source', async () => {
    render(<DependencyExplorer documents={documents} focusedPackageId="app" />);
    const user = userEvent.setup();
    await user.click(screen.getByText('Inspect dependency links'));
    await user.click(screen.getByRole('button', { name: 'Inspect app depends on lib' }));
    const details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('Relationship: Unspecified')).toBeTruthy();
    expect(details.getByText('Lifecycle scope: Unspecified')).toBeTruthy();
    expect(details.getByText('Source: packages.spdx.json')).toBeTruthy();
});

test('shows release/revision metadata while navigation keeps commit-based package identity', async () => {
    const revision = 'a'.repeat(40);
    const id = `lib@${revision}`;
    const metadataDocuments: DependencyDocument[] = [{...documents[0], packages: [
        {id: 'app', name: 'app', version: '1.0'},
        {id, name: 'lib', version: revision, release_version: '4.1.1', source_revision: revision,
            version_evidence: [{source: 'purl', version: 'v4.1.1', identifier: 'pkg:generic/lib@v4.1.1'}]},
    ], edges: [{package_id: 'app', dependency_id: id}]}];
    render(<DependencyExplorer documents={metadataDocuments} focusedPackageId="app" />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Tree' }));
    const tree = within(screen.getByRole('tree', {name: 'alpha: Depends on'}));
    const row = tree.getByRole('treeitem', {name: 'lib@4.1.1 (aaaaaaaaaaaa)'});
    expect(within(row).getByTitle(/pkg:generic\/lib@v4.1.1/)).toBeTruthy();
    await user.click(row);
    const inspector = within(screen.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('heading', { name: 'lib@4.1.1 (aaaaaaaaaaaa)' })).toBeTruthy();
    await user.click(inspector.getByText('Inspect dependency links'));
    expect(inspector.getByRole('button', { name: `Inspect app depends on ${id}` })).toBeTruthy();
});

test('opens at the SBOM package and explores paths, reverse relationships and the graph inside the popup', async () => {
    mockListDependencies.mockResolvedValue(documents);
    const close = jest.fn();
    render(<DependencyModal variantId="popup-flow" packageId="app" onClose={close} />);
    const dialog = within(screen.getByRole('dialog', { name: 'Package dependencies' }));
    expect(await dialog.findByLabelText('Dependency diagram')).toBeInTheDocument();
    expect(dialog.getByRole('button', { name: 'Graph' })).toHaveAttribute('aria-pressed', 'true');
    expect(dialog.getByRole('combobox', { name: 'Graph depth' })).toHaveValue('1');
    expect(dialog.queryByText(/Explore SBOM relationships|without leaving the SBOM/)).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(dialog.getByRole('button', { name: 'Tree' }));
    const tree = within(dialog.getByRole('tree', { name: 'alpha: Depends on' }));
    expect(tree.getByRole('treeitem', { name: 'app@1.0' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.queryByLabelText('Dependency diagram')).not.toBeInTheDocument();
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    await user.click(tree.getByRole('treeitem', { name: 'util@1.0' }));
    const inspector = within(dialog.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('list', { name: 'Selected dependency path' })).toHaveTextContent('app@1.0lib@1.0util@1.0');
    await user.click(dialog.getByRole('button', { name: 'Required by' }));
    expect(dialog.getByRole('tree', { name: 'alpha: Required by' })).toBeInTheDocument();
    expect(inspector.getByRole('list', { name: 'Relationship counts' })).toHaveTextContent('Required by1 direct · 1 transitive only');
    await user.click(dialog.getByRole('button', { name: 'Graph' }));
    expect(dialog.getByLabelText('Dependency diagram')).toBeInTheDocument();
    await user.click(dialog.getByRole('button', { name: 'All packages' }));
    expect(dialog.getByRole('tree')).toBeVisible();
    expect(mockListDependencies).toHaveBeenCalledTimes(1);
    await user.click(dialog.getByRole('button', { name: 'Close modal' }));
    expect(close).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(close).toHaveBeenCalledTimes(2);
});

test('reuses the scope graph across package openings until the data revision changes', async () => {
    mockListDependencies.mockResolvedValue(documents);
    const first = render(<DependencyModal variantId="cache-scope" dataRevision={1} packageId="app" onClose={() => {}} />);
    expect(within(await screen.findByLabelText('Dependency diagram')).getByText('app@1.0')).toBeInTheDocument();
    first.unmount();
    const second = render(<DependencyModal variantId="cache-scope" dataRevision={1} packageId="lib" onClose={() => {}} />);
    const diagram = within(await screen.findByLabelText('Dependency diagram'));
    expect(diagram.getByText('util@1.0')).toBeInTheDocument();
    expect(diagram.queryByText('app@1.0')).not.toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(1);
    second.rerender(<DependencyModal variantId="cache-scope" dataRevision={2} packageId="lib" onClose={() => {}} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenCalledTimes(2));
    expect(within(await screen.findByLabelText('Dependency diagram')).getByText('util@1.0')).toBeInTheDocument();
});

test('uses comparison semantics and resets exploration when the scope or selected package changes', async () => {
    mockListDependencies.mockResolvedValue(documents);
    const close = () => {};
    const view = render(<DependencyModal variantId="v1" projectId="p1" compareVariantId="v2"
        operation="difference" dataRevision={1} packageId="app" onClose={close} />);
    await screen.findByLabelText('Dependency diagram');
    expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'difference');
    await userEvent.setup().type(screen.getByRole('searchbox'), 'util');
    view.rerender(<DependencyModal variantId="v1" projectId="p1" compareVariantId="v2"
        operation="intersection" dataRevision={1} packageId="app" onClose={close} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'intersection'));
    expect(await screen.findByRole('searchbox')).toHaveValue('');
    view.rerender(<DependencyModal projectId="p1" variantIds={['v1', 'v2']} operation="intersection"
        dataRevision={1} packageId="lib" onClose={close} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith(undefined, 'p1', ['v1', 'v2'], undefined, 'intersection'));
    expect(within(await screen.findByLabelText('Dependency diagram')).getByText('util@1.0')).toBeInTheDocument();
    view.rerender(<DependencyModal projectId="p1" variantIds={['v1', 'v2']} operation="intersection"
        dataRevision={1} packageId="util" onClose={close} />);
    const diagram = within(screen.getByLabelText('Dependency diagram'));
    expect(diagram.getByText('util@1.0')).toBeInTheDocument();
    expect(diagram.queryByText('lib@1.0')).not.toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(3);
});

test('surfaces request failures and evicts failed requests so retry can succeed', async () => {
    mockListDependencies.mockRejectedValueOnce(new Error('Request failed')).mockResolvedValueOnce(documents);
    render(<DependencyModal projectId="retry-scope" packageId="app" onClose={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load dependencies');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(within(await screen.findByLabelText('Dependency diagram')).getByText('app@1.0')).toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(2);
});
