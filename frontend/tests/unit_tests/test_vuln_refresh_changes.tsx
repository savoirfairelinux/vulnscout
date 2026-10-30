import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from "react";
import VulnRefreshChanges from "../../src/components/VulnRefreshChanges";
import type { RefreshRun } from "../../src/handlers/vulnerabilityRefreshRun";

export const run: RefreshRun = {
    run_id: 'run-one', scope: { project_id: 'project-one', variant_id: 'variant-one' },
    sources: ['nvd', 'epss'], started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:01:00Z',
    status: 'complete',
    coverage: [
        { source: 'nvd', vuln_id: 'CVE-1', status: 'complete', error: null },
        { source: 'epss', vuln_id: 'CVE-1', status: 'complete', error: null },
    ],
    summary: { total_changes: 0, changed_vulnerabilities: 0, first_enrichments: 0 },
    changes: [], total: 0, limit: 1000, offset: 0,
};

test('distinguishes no baseline from an unchanged completed run', () => {
    const { rerender } = render(<VulnRefreshChanges run={null} vulnId="CVE-1" />);
    expect(screen.getByText(/No refresh baseline is available/)).toBeInTheDocument();
    rerender(<VulnRefreshChanges run={run} vulnId="CVE-1" />);
    expect(screen.getByText('No data changed in this refresh.')).toBeInTheDocument();
    expect(screen.getByText('run-one')).toBeInTheDocument();
    expect(screen.getByText(/Project project-one · Variant variant-one/)).toBeInTheDocument();
});

test('keeps successful changes visible alongside failed source coverage', () => {
    render(<VulnRefreshChanges run={{
        ...run, status: 'incomplete', coverage: [
            run.coverage[0], { source: 'epss', vuln_id: 'CVE-1', status: 'failed', error: 'Provider unavailable' },
        ],
        changes: [{
            vuln_id: 'CVE-1', source: 'nvd', field: 'description', before: 'old description', after: 'new description',
            changed_at: run.started_at, kind: 'changed', packages: [],
        }],
    }} vulnId="CVE-1" />);
    expect(screen.getByRole('status')).toHaveTextContent('coverage is incomplete');
    expect(screen.getByText(/EPSS: failed/)).toHaveTextContent('Provider unavailable');
    expect(screen.getByText('old description')).toBeInTheDocument();
    expect(screen.getByText('new description')).toBeInTheDocument();
    expect(screen.queryByText('No data changed in this refresh.')).not.toBeInTheDocument();
});

test('renders complete CVSS identity/version/score/vector and safe nested long values', () => {
    const field = 'cvss:3.1:nvd@nist.gov:00000000-0000-4000-8000-000000000001';
    const value = { advisory: { details: '<script>not executable</script>', list: ['x'.repeat(2000)] } };
    render(<VulnRefreshChanges run={{
        ...run, changes: [{
            vuln_id: 'CVE-1', source: 'nvd', field,
            before: { score: 7.5, vector: 'CVSS:3.1/AV:L' },
            after: { score: 9.8, vector: 'CVSS:3.1/AV:N' }, kind: 'changed',
            changed_at: run.started_at, packages: [],
        }, {
            vuln_id: 'CVE-1', source: 'nvd', field: 'custom_nested',
            before: null, after: value, kind: 'first_enrichment', changed_at: run.started_at, packages: [],
        }],
    }} vulnId="CVE-1" />);
    expect(screen.getByText('CVSS 3.1 (nvd@nist.gov #00000000)')).toBeInTheDocument();
    expect(screen.getByText(field)).toBeInTheDocument();
    expect(screen.getByText('7.5 (CVSS:3.1/AV:L)')).toBeInTheDocument();
    expect(screen.getByText('9.8 (CVSS:3.1/AV:N)')).toBeInTheDocument();
    expect(screen.getByText('No previous value (first enrichment)')).toBeInTheDocument();
    expect(screen.getByText(/"advisory"/)).toHaveTextContent('x'.repeat(2000));
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getAllByText('Before')).toHaveLength(2);
    expect(screen.getAllByText('After')).toHaveLength(2);
});

test.each(['running', 'incomplete'] as const)('never claims unchanged for %s checks', status => {
    render(<VulnRefreshChanges run={{ ...run, status, coverage: [{
        source: 'nvd', vuln_id: 'CVE-1', status: status === 'running' ? 'pending' : 'cancelled', error: null,
    }] }} vulnId="CVE-1" />);
    expect(screen.getByText('No successful baseline comparison is available for this refresh.')).toBeInTheDocument();
    expect(screen.queryByText('No data changed in this refresh.')).not.toBeInTheDocument();
});

test('exposes an incomplete source even when it produced no vulnerability coverage', () => {
    render(<VulnRefreshChanges run={{
        ...run, status: 'incomplete', coverage: [run.coverage[0]],
        source_status: { nvd: 'complete', epss: 'incomplete' },
    }} vulnId="CVE-1" />);
    expect(screen.getByText('EPSS: incomplete — no vulnerability-level comparison recorded')).toBeInTheDocument();
    expect(screen.getByText('No changes were recorded by the completed checks; other checks are incomplete.')).toBeInTheDocument();
});
