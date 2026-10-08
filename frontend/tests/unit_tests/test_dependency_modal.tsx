import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DependencyModal, { DependencyModalView } from '../../src/components/DependencyModal';
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
            { id: 'app', name: 'app', version: '1.0' },
            { id: 'lib', name: 'lib', version: '1.0' },
            { id: 'util', name: 'util', version: '1.0' },
        ],
        edges: [
            { package_id: 'app', dependency_id: 'lib' },
            { package_id: 'app', dependency_id: 'util' },
            { package_id: 'lib', dependency_id: 'util' },
        ],
    },
    {
        id: 'doc-two', source_name: 'other.spdx.json', variant_id: 'v1', variant_name: 'alpha', dependencies_recorded: true,
        packages: [
            { id: 'app', name: 'app', version: '1.0' },
            { id: 'core', name: 'core', version: '2.0' },
        ],
        edges: [{ package_id: 'app', dependency_id: 'core' }],
    },
];

test('shows both directions and follows the selected SBOM source', async () => {
    const selectPackage = jest.fn();
    render(<DependencyModalView documents={documents} packageId="app" onSelectPackage={selectPackage} />);
    const user = userEvent.setup();

    expect(screen.getAllByText('In 3 / Out 0')).toHaveLength(2);
    expect(screen.getByLabelText('Dependency diagram').querySelectorAll('.react-flow__node')).toHaveLength(4);
    const tree = within(screen.getByRole('tree', { name: 'Depends on' }));
    expect(tree.getByRole('button', { name: 'lib@1.0' })).toBeTruthy();
    await user.click(tree.getByRole('button', { name: 'lib@1.0' }));
    expect(selectPackage).toHaveBeenCalledWith('lib');
    await user.click(tree.getByRole('button', { name: 'Expand lib' }));
    expect(tree.getAllByRole('button', { name: 'util@1.0' })).toHaveLength(2);

    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'doc-two');
    expect(screen.getAllByText('In 1 / Out 0')).toHaveLength(2);
    expect(screen.getByLabelText('Dependency diagram').querySelectorAll('.react-flow__node')).toHaveLength(2);
});

test('distinguishes incoming and outgoing dependencies per variant', async () => {
    const pkg = (id: string) => ({ id, name: id, version: '1.0' });
    const variantDocuments: DependencyDocument[] = [
        { id: 'beta-doc', source_name: 'beta.spdx.json', variant_id: 'beta', variant_name: 'beta', dependencies_recorded: true,
            packages: [pkg('app'), pkg('lib'), pkg('core')],
            edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'core', dependency_id: 'app' }] },
        { id: 'alpha-doc', source_name: 'alpha.spdx.json', variant_id: 'alpha', variant_name: 'alpha', dependencies_recorded: true,
            packages: [pkg('app'), pkg('lib'), pkg('util')],
            edges: [{ package_id: 'app', dependency_id: 'lib' }, { package_id: 'app', dependency_id: 'util' }] },
        { id: 'alpha-recipe', source_name: 'recipe-tool.spdx.json', variant_id: 'alpha', variant_name: 'alpha', dependencies_recorded: true,
            packages: [pkg('tool')], edges: [{ package_id: 'tool', dependency_id: 'app' }] },
    ];
    render(<DependencyModalView documents={variantDocuments} packageId="app" onSelectPackage={() => {}} />);
    const node = (id: string) => screen.getByLabelText('Dependency diagram')
        .querySelector<HTMLElement>(`.react-flow__node[data-id="${id}"]`)!;
    const legend = () => within(screen.getByRole('list', { name: 'Variants' }));
    const x = (id: string) => Number(/translate\(([-\d.]+)px/.exec(node(id).style.transform)![1]);

    expect(screen.getByText('In 2 / Out 2')).toBeTruthy();
    expect(legend().getAllByRole('listitem').map(item => item.textContent)).toEqual([
        'alphaIn 2 / Out 1', 'betaIn 1 / Out 1',
    ]);
    expect(x('lib')).toBeLessThan(x('app'));
    expect(x('core')).toBeGreaterThan(x('app'));
    expect(legend().getAllByRole('listitem').map(item => item.querySelector('span')!.style.backgroundColor)).toEqual([
        'rgb(125, 211, 252)', 'rgb(253, 164, 175)',
    ]);
    expect(node('util').style.background).toBe('rgb(125, 211, 252)');
    expect(node('tool').style.background).toBe('rgb(125, 211, 252)');
    expect(node('core').style.background).toBe('rgb(253, 164, 175)');
    expect(screen.getByTitle('Variants: alpha, beta').textContent).toBe('lib@1.0');
    expect(node('app').style.background).toBe('');

    await userEvent.setup().click(legend().getByRole('checkbox', { name: 'alpha' }));
    expect(legend().getByRole('checkbox', { name: 'alpha' })).toHaveProperty('checked', false);
    expect(screen.getAllByText('In 1 / Out 1')).toHaveLength(2);
    expect(legend().getAllByRole('listitem').map(item => item.textContent)).toEqual([
        'alphaIn 2 / Out 1', 'betaIn 1 / Out 1',
    ]);
    expect(screen.getByLabelText('Dependency diagram').querySelectorAll('.react-flow__node')).toHaveLength(3);
    expect(node('lib').style.background).toBe('rgb(253, 164, 175)');

    await userEvent.setup().click(legend().getByRole('checkbox', { name: 'beta' }));
    expect(screen.getByText('In 0 / Out 0')).toBeTruthy();
    expect(screen.getByLabelText('Dependency diagram').querySelectorAll('.react-flow__node')).toHaveLength(1);
});

test('marks variants whose SBOMs were imported without dependency support', () => {
    render(<DependencyModalView documents={[documents[0], {
        id: 'legacy', source_name: 'legacy.spdx.json', variant_id: 'v2', variant_name: 'beta', dependencies_recorded: false,
        packages: [{ id: 'app', name: 'app', version: '1.0' }], edges: [],
    }]} packageId="app" onSelectPackage={() => {}} />);
    expect(within(screen.getByRole('list', { name: 'Variants' })).getAllByRole('listitem')
        .map(item => item.textContent)).toEqual(['alphaIn 2 / Out 0', 'betaNot recorded']);
});

test('shows every neighbour in a single diagram', () => {
    const packages = Array.from({ length: 15 }, (_, index) => ({
        id: `pkg-${index}`, name: `pkg-${index}`, version: '1.0',
    }));
    const edges = packages.slice(1).map(pkg => ({ package_id: pkg.id, dependency_id: 'pkg-0' }));
    render(<DependencyModalView documents={[{ id: 'big', source_name: 'big.spdx.json', variant_id: 'v1',
        variant_name: 'alpha', dependencies_recorded: true, packages, edges }]} packageId="pkg-0" onSelectPackage={() => {}} />);

    expect(screen.getAllByText('In 0 / Out 14')).toHaveLength(2);
    expect(screen.getByRole('heading', { name: 'Required by (14)' })).toBeTruthy();
    expect(screen.getByLabelText('Dependency diagram').querySelectorAll('.react-flow__node')).toHaveLength(15);
    const columns = new Set([...screen.getByLabelText('Dependency diagram')
        .querySelectorAll<HTMLElement>('.react-flow__node')].map(node => node.style.transform.split(',')[0]));
    expect(columns.size).toBe(3);
    expect(screen.queryByRole('button', { name: 'Next dependency group' })).toBeNull();
});

test('shows loading, missing, and retry states', async () => {
    const retry = jest.fn();
    const view = render(<DependencyModalView documents={[]} packageId="missing" onSelectPackage={() => {}} loading />);
    expect(screen.getByRole('status').textContent).toContain('Loading');
    view.rerender(<DependencyModalView documents={[]} packageId="missing" onSelectPackage={() => {}}
        error="Unable to load dependencies" onRetry={retry} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry loading dependencies' }));
    expect(retry).toHaveBeenCalledTimes(1);
    view.rerender(<DependencyModalView documents={[]} packageId="missing" onSelectPackage={() => {}} />);
    expect(screen.getByText('No dependency data for this package.')).toBeTruthy();
});

test('reuses the scope graph across openings until the data revision changes', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(() => Promise.resolve({
        ok: true, json: () => Promise.resolve({ documents: [documents[0]] }),
    } as Response));
    const first = render(<DependencyModal variantId="cache-scope" dataRevision={1} packageId="app" onClose={() => {}} />);
    expect(await screen.findByRole('heading', { name: 'Depends on (2)' })).toBeTruthy();
    first.unmount();
    const second = render(<DependencyModal variantId="cache-scope" dataRevision={1} packageId="lib" onClose={() => {}} />);
    expect(await screen.findByRole('heading', { name: 'Depends on (1)' })).toBeTruthy();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    second.rerender(<DependencyModal variantId="cache-scope" dataRevision={2} packageId="lib" onClose={() => {}} />);
    expect(await screen.findByRole('heading', { name: 'Depends on (1)' })).toBeTruthy();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    fetchSpy.mockRestore();
});
