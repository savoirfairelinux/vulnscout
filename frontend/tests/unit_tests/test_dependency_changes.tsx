import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import DependencyChanges from '../../src/components/DependencyChanges';
import type { DependencyChanges as Changes } from '../../src/handlers/scans';

const edge = {
    dependent: { package_id: 'app', package_name: 'app', package_version: '1' },
    dependency: { package_id: 'lib', package_name: 'lib', package_version: '2' },
};

test('shows separate expandable directed relationship counts and details', () => {
    render(<DependencyChanges changes={{
        status: 'available', added_count: 1, removed_count: 0, added: [edge], removed: [],
    }} />);
    const summary = screen.getByText('Added relationships (1)');
    expect(summary.parentElement).not.toHaveAttribute('open');
    fireEvent.click(summary);
    expect(summary.parentElement).toHaveAttribute('open');
    expect(screen.getByText('app@1 → lib@2')).toBeInTheDocument();
    expect(screen.getByText('Removed relationships (0)')).toBeInTheDocument();
});

test('identical imports show zero relationship changes', () => {
    render(<DependencyChanges changes={{
        status: 'available', added_count: 0, removed_count: 0, added: [], removed: [],
    }} />);
    expect(screen.getByText('Added relationships (0)')).toBeInTheDocument();
    expect(screen.getByText('Removed relationships (0)')).toBeInTheDocument();
    expect(screen.queryByText(/No comparable/)).not.toBeInTheDocument();
});

test.each([
    ['no_previous_import', 'first import'],
    ['incomparable_scope', 'different SBOM document scope'],
    ['not_recorded', 'not recorded'],
] as const)('explains unavailable baseline %s without implying zero changes', (status, reason) => {
    render(<DependencyChanges changes={{
        status, added_count: null, removed_count: null, added: null, removed: null,
    } as Changes} />);
    expect(screen.getByText(/No comparable dependency baseline/)).toHaveTextContent(reason);
    expect(screen.queryByText(/Added relationships/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Removed relationships/)).not.toBeInTheDocument();
});
