import '@testing-library/jest-dom';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyModal from '../../src/components/DependencyModal';
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

test('opens at the SBOM package and explores paths, reverse relationships and the graph inside the popup', async () => {
    mockListDependencies.mockResolvedValue(documents);
    const close = jest.fn();
    render(<DependencyModal variantId="popup-flow" packageId="app" onClose={close} />);
    const dialog = within(screen.getByRole('dialog', { name: 'Package dependencies' }));
    const tree = within(await dialog.findByRole('tree', { name: 'alpha: Depends on' }));
    expect(tree.getByRole('treeitem', { name: 'app@1.0' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.queryByLabelText('Dependency diagram')).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(tree.getByRole('button', { name: 'Expand lib@1.0' }));
    await user.click(tree.getByRole('treeitem', { name: 'util@1.0' }));
    const inspector = within(dialog.getByRole('complementary', { name: 'Package inspector' }));
    expect(inspector.getByRole('list', { name: 'Selected dependency path' })).toHaveTextContent('app@1.0lib@1.0util@1.0');
    await user.click(inspector.getByRole('button', { name: /Trace dependents/ }));
    expect(dialog.getByRole('tree', { name: 'alpha: Required by' })).toBeInTheDocument();
    expect(inspector.getByRole('button', { name: /Trace dependents/ })).toHaveTextContent('1 direct · 1 transitive only');
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
    expect(await screen.findByRole('treeitem', { name: 'app@1.0' })).toBeInTheDocument();
    first.unmount();
    const second = render(<DependencyModal variantId="cache-scope" dataRevision={1} packageId="lib" onClose={() => {}} />);
    expect(await screen.findByRole('treeitem', { name: 'util@1.0' })).toBeInTheDocument();
    expect(screen.queryByRole('treeitem', { name: 'app@1.0' })).not.toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(1);
    second.rerender(<DependencyModal variantId="cache-scope" dataRevision={2} packageId="lib" onClose={() => {}} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('treeitem', { name: 'util@1.0' })).toBeInTheDocument();
});

test('uses comparison semantics and resets exploration when the scope or selected package changes', async () => {
    mockListDependencies.mockResolvedValue(documents);
    const close = () => {};
    const view = render(<DependencyModal variantId="v1" projectId="p1" compareVariantId="v2"
        operation="difference" dataRevision={1} packageId="app" onClose={close} />);
    await screen.findByRole('tree');
    expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'difference');
    await userEvent.setup().type(screen.getByRole('searchbox'), 'util');
    view.rerender(<DependencyModal variantId="v1" projectId="p1" compareVariantId="v2"
        operation="intersection" dataRevision={1} packageId="app" onClose={close} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith('v1', 'p1', undefined, 'v2', 'intersection'));
    expect(await screen.findByRole('searchbox')).toHaveValue('');
    view.rerender(<DependencyModal projectId="p1" variantIds={['v1', 'v2']} operation="intersection"
        dataRevision={1} packageId="lib" onClose={close} />);
    await waitFor(() => expect(mockListDependencies).toHaveBeenLastCalledWith(undefined, 'p1', ['v1', 'v2'], undefined, 'intersection'));
    expect(await screen.findByRole('treeitem', { name: 'util@1.0' })).toBeInTheDocument();
    view.rerender(<DependencyModal projectId="p1" variantIds={['v1', 'v2']} operation="intersection"
        dataRevision={1} packageId="util" onClose={close} />);
    expect(screen.getAllByRole('treeitem')).toHaveLength(1);
    expect(screen.getByRole('treeitem', { name: 'util@1.0' })).toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(3);
});

test('surfaces request failures and evicts failed requests so retry can succeed', async () => {
    mockListDependencies.mockRejectedValueOnce(new Error('Request failed')).mockResolvedValueOnce(documents);
    render(<DependencyModal projectId="retry-scope" packageId="app" onClose={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load dependencies');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(await screen.findByRole('treeitem', { name: 'app@1.0' })).toBeInTheDocument();
    expect(mockListDependencies).toHaveBeenCalledTimes(2);
});
