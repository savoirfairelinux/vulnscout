import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import EditAssessment from '../../src/components/EditAssessment';
import type { Assessment } from '../../src/handlers/assessments';

const asmt: Assessment = {
    id: 'a1', vuln_id: 'CVE-2023-1234',
    packages: ['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup'],
    status: 'affected', simplified_status: 'active',
    justification: 'none', impact_statement: '', status_notes: '', workaround: '',
    timestamp: '2023-01-01T00:00:00Z', origin: 'custom', responses: []
} as any;

const variants = [
    { id: 'v1', name: 'alpha', project_id: 'p1' },
    { id: 'v2', name: 'beta', project_id: 'p1' },
];
const map = { v1: ['pkgA@1.0.0::sup'], v2: ['pkgB@1.0.0::sup'] };

function cb(labelText: string): HTMLInputElement {
    return screen.getByText(labelText).closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement;
}

test('ASYNC: variants+map load after mount, then package toggle prunes variant', async () => {
    const user = userEvent.setup();
    const { rerender } = render(
        <EditAssessment
            assessment={asmt}
            onSaveAssessment={jest.fn()}
            onCancel={jest.fn()}
            availableVariants={[]}
            defaultSelectedVariantIds={['v1', 'v2']}
            availablePackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            defaultSelectedPackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            variantPackageMap={undefined}
        />
    );
    // simulate async arrival of variants + map (new refs)
    rerender(
        <EditAssessment
            assessment={asmt}
            onSaveAssessment={jest.fn()}
            onCancel={jest.fn()}
            availableVariants={[...variants]}
            defaultSelectedVariantIds={['v1', 'v2']}
            availablePackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            defaultSelectedPackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            variantPackageMap={{ ...map }}
        />
    );

    expect(cb('alpha').checked).toBe(true);
    expect(cb('beta').checked).toBe(true);

    // uncheck package pkgA -> v1 should be removed
    const pkgA = screen.getByText('pkgA@1.0.0 (sup)').closest('label')!.querySelector('input')!;
    await user.click(pkgA);

    console.log('ASYNC after uncheck pkgA: alpha=', cb('alpha').checked, 'beta=', cb('beta').checked);
    expect(cb('alpha').checked).toBe(false);
});

test('SHARED: both variants contain both packages (full SBOM) -> no pruning', async () => {
    const user = userEvent.setup();
    const sharedMap = {
        v1: ['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup', 'extra1@1::s'],
        v2: ['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup', 'extra2@1::s'],
    };
    render(
        <EditAssessment
            assessment={asmt}
            onSaveAssessment={jest.fn()}
            onCancel={jest.fn()}
            availableVariants={variants}
            defaultSelectedVariantIds={['v1', 'v2']}
            availablePackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            defaultSelectedPackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            variantPackageMap={sharedMap}
        />
    );

    const pkgA = screen.getByText('pkgA@1.0.0 (sup)').closest('label')!.querySelector('input')!;
    await user.click(pkgA);
    console.log('SHARED after uncheck pkgA: alpha=', cb('alpha').checked, 'beta=', cb('beta').checked);

    await user.click(cb('alpha'));
    console.log('SHARED after uncheck alpha: pkgA=', (screen.getByText('pkgA@1.0.0 (sup)').closest('label')!.querySelector('input')! as HTMLInputElement).checked);
});
