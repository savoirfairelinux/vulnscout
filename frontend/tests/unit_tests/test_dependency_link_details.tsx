import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Edge } from '@xyflow/react';
import { DependencyModalView } from '../../src/components/DependencyModal';
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
    render(<DependencyModalView documents={documents} packageId="lib" onSelectPackage={() => {}} />);
    const user = userEvent.setup();
    const inspect = () => user.click(screen.getByRole('button', { name: /Graph link lib to app/ }));
    expect(screen.getByText('Build / Runtime')).toBeTruthy();
    await inspect();
    let details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('app depends on lib')).toBeTruthy();
    expect(details.getByText('Source: alpha.json')).toBeTruthy();
    expect(details.getByText('Source: beta.json')).toBeTruthy();
    await user.click(screen.getByRole('checkbox', { name: 'beta' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('Build / Runtime')).toBeNull();
    expect(screen.getByText('Runtime')).toBeTruthy();
    await inspect();
    details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('Lifecycle scope: Runtime')).toBeTruthy();
    expect(details.queryByText('Lifecycle scope: Build')).toBeNull();
    expect(details.queryByText('Source: beta.json')).toBeNull();
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
    render(<DependencyModalView documents={documents} packageId="app" onSelectPackage={() => {}} />);
    expect(screen.getByText('Build / Development / Runtime / Test / Unspecified')).toBeTruthy();
    expect(screen.getAllByText('Deps: 1 / Req by: 0')).toHaveLength(2);
    const user = userEvent.setup();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'typed');
    expect(screen.getByText('Build / Development / Runtime / Test')).toBeTruthy();
    await user.selectOptions(screen.getByRole('combobox', { name: 'SBOM source' }), 'legacy');
    expect(screen.getByText('Unspecified')).toBeTruthy();
    expect(screen.queryByText('Build / Development / Runtime / Test')).toBeNull();
});
