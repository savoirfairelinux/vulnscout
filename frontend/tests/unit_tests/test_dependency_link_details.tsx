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
    const inspect = () => user.click(screen.getByRole('button', { name: 'Graph link lib to app' }));
    await inspect();
    let details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('app depends on lib')).toBeTruthy();
    expect(details.getByText('Source: alpha.json')).toBeTruthy();
    expect(details.getByText('Source: beta.json')).toBeTruthy();
    await user.click(screen.getByRole('checkbox', { name: 'beta' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    await inspect();
    details = within(screen.getByRole('dialog', { name: 'Dependency link details' }));
    expect(details.getByText('Lifecycle scope: Runtime')).toBeTruthy();
    expect(details.queryByText('Lifecycle scope: Build')).toBeNull();
    expect(details.queryByText('Source: beta.json')).toBeNull();
});
