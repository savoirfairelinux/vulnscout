import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Edge } from '@xyflow/react';
import DependencyExplorer from '../../src/components/DependencyExplorer';
import type { DependencyDocument } from '../../src/handlers/dependencies';

// JSDOM cannot measure React Flow's SVG edges; exercise its click callback contract.
jest.mock('@xyflow/react', () => ({
    ...jest.requireActual('@xyflow/react'),
    ReactFlow: ({ edges, onEdgeClick }: {
        edges: Edge[];
        onEdgeClick: (event: unknown, edge: Edge) => void;
    }) => <div>{edges.map(edge => <button key={edge.id} onClick={event => onEdgeClick(event, edge)}>
        Graph link {edge.source} to {edge.target}
        <span>{edge.label}</span>
    </button>)}</div>,
}));

beforeAll(() => {
    global.ResizeObserver = class implements ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
});

test('graph link details retain direction and separate evidence when filtering variants', async () => {
    const documents: DependencyDocument[] = ['alpha', 'beta'].map((name, index) => ({
        id: name, source_name: `${name}.json`, variant_id: name, variant_name: name, dependencies_recorded: true,
        packages: [{ id: 'app', name: 'app', version: '' }, { id: 'lib', name: 'lib', version: '' }],
        edges: [{ package_id: 'app', dependency_id: 'lib', declarations: [{
            relationship_type: 'dependsOn', lifecycle_scope: index ? 'build' : 'runtime',
            source_document_id: name, source_name: `${name}.json`,
        }] }],
    }));
    render(<DependencyExplorer documents={documents} focusedPackageId="lib" />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Required by' }));
    const inspect = () => user.click(screen.getByRole('button', { name: /Graph link app to lib/ }));
    expect(screen.getByText('Runtime')).toBeTruthy();
    expect(screen.queryByText('Build')).toBeNull();
    await inspect();
    let details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('app depends on lib')).toBeTruthy();
    expect(details.getByText('Source: alpha.json')).toBeTruthy();
    expect(details.queryByText('Source: beta.json')).toBeNull();
    await user.click(screen.getByRole('checkbox', { name: /alpha/ }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('Runtime')).toBeNull();
    expect(screen.getByText('Build')).toBeTruthy();
    await inspect();
    details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('Lifecycle scope: Build')).toBeTruthy();
    expect(details.queryByText('Lifecycle scope: Runtime')).toBeNull();
    expect(details.queryByText('Source: alpha.json')).toBeNull();
});

test('graph labels retain every declared scope and unspecified legacy evidence per source', async () => {
    const documents: DependencyDocument[] = ['typed', 'legacy'].map(name => ({
        id: name, source_name: `${name}.json`, variant_id: 'default', variant_name: 'default', dependencies_recorded: true,
        packages: [{ id: 'app', name: 'app', version: '' }, { id: 'lib', name: 'lib', version: '' }],
        edges: [{ package_id: 'app', dependency_id: 'lib', declarations: name === 'typed'
            ? ['runtime', 'build', 'development', 'test', 'runtime'].map(scope => ({
                relationship_type: 'dependsOn', lifecycle_scope: scope, source_document_id: name, source_name: `${name}.json`,
            })) : [] }],
    }));
    render(<DependencyExplorer documents={documents} focusedPackageId="app" />);
    expect(screen.getByText('Build / Development / Runtime / Test / Unspecified')).toBeTruthy();
    expect(screen.getAllByText('Deps: 1 / Req by: 0')).toHaveLength(1);
    const user = userEvent.setup();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'typed');
    await user.click(screen.getByRole('treeitem', { name: /^app@/ }));
    await user.click(screen.getByRole('button', { name: 'Graph' }));
    expect(screen.getByText('Build / Development / Runtime / Test')).toBeTruthy();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'legacy');
    await user.click(screen.getByRole('treeitem', { name: /^app@/ }));
    await user.click(screen.getByRole('button', { name: 'Graph' }));
    expect(screen.getByText('Unspecified')).toBeTruthy();
    expect(screen.queryByText('Build / Development / Runtime / Test')).toBeNull();
});

test('dependency details do not expose compiler metadata', () => {
    const documents: DependencyDocument[] = ['alpha', 'beta'].map(name => ({
        id: name, source_name: `${name}.jsonld`, variant_id: name, variant_name: name, dependencies_recorded: true,
        packages: [{ id: 'mbedtls', name: 'mbedtls', version: '' }, { id: 'kernel', name: 'kernel', version: '' }],
        edges: [],
        build_targets: [{
            id: `builds/${name}`, name: `${name} target`, package_ids: ['mbedtls'],
            languages: [{ language: 'C', flags: [`-${name}`], defines: [] }],
        }],
    }));
    render(<DependencyModalView documents={documents} packageId="mbedtls" onSelectPackage={() => {}} />);
    expect(screen.queryByText('-alpha')).toBeNull();
    expect(screen.queryByText('-beta')).toBeNull();
    expect(screen.queryByText('Compiler flags and defines')).toBeNull();
});
