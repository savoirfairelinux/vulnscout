import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import EditAssessment from '../../src/components/EditAssessment';
import type { Assessment } from '../../src/handlers/assessments';

const asmt: Assessment = {
    id: 'a1',
    vuln_id: 'CVE-2023-1234',
    packages: ['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup'],
    status: 'affected',
    simplified_status: 'active',
    justification: 'none',
    impact_statement: '',
    status_notes: '',
    workaround: '',
    timestamp: '2023-01-01T00:00:00Z',
    origin: 'custom',
    responses: []
} as any;

const variants = [
    { id: 'v1', name: 'alpha', project_id: 'p1' },
    { id: 'v2', name: 'beta', project_id: 'p1' },
];

const variantPackageMap = {
    v1: ['pkgA@1.0.0::sup'],
    v2: ['pkgB@1.0.0::sup'],
};

function getCheckbox(labelText: string): HTMLInputElement {
    const label = screen.getByText(labelText).closest('label')!;
    return label.querySelector('input[type="checkbox"]') as HTMLInputElement;
}

test('REPRO: unchecking package removes incompatible variant', async () => {
    const user = userEvent.setup();
    render(
        <EditAssessment
            assessment={asmt}
            onSaveAssessment={jest.fn()}
            onCancel={jest.fn()}
            availableVariants={variants}
            defaultSelectedVariantIds={['v1', 'v2']}
            availablePackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            defaultSelectedPackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            variantPackageMap={variantPackageMap}
        />
    );

    // initial: all checked
    expect(getCheckbox('alpha').checked).toBe(true);
    expect(getCheckbox('beta').checked).toBe(true);

    // uncheck package pkgA -> variant v1 (only has pkgA) should be removed
    const pkgACheckbox = screen.getByText('pkgA@1.0.0 (sup)').closest('label')!.querySelector('input')!;
    await user.click(pkgACheckbox);

    console.log('After unchecking pkgA: v1(alpha)=', getCheckbox('alpha').checked, 'v2(beta)=', getCheckbox('beta').checked);
    expect(getCheckbox('alpha').checked).toBe(false); // EXPECT v1 removed
    expect(getCheckbox('beta').checked).toBe(true);
});

test('REPRO: unchecking variant removes incompatible package', async () => {
    const user = userEvent.setup();
    render(
        <EditAssessment
            assessment={asmt}
            onSaveAssessment={jest.fn()}
            onCancel={jest.fn()}
            availableVariants={variants}
            defaultSelectedVariantIds={['v1', 'v2']}
            availablePackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            defaultSelectedPackages={['pkgA@1.0.0::sup', 'pkgB@1.0.0::sup']}
            variantPackageMap={variantPackageMap}
        />
    );

    const pkgA = () => screen.getByText('pkgA@1.0.0 (sup)').closest('label')!.querySelector('input')! as HTMLInputElement;
    const pkgB = () => screen.getByText('pkgB@1.0.0 (sup)').closest('label')!.querySelector('input')! as HTMLInputElement;

    expect(pkgA().checked).toBe(true);
    expect(pkgB().checked).toBe(true);

    // uncheck variant v1 (alpha) -> pkgA (only in v1) should be removed
    await user.click(getCheckbox('alpha'));

    console.log('After unchecking alpha: pkgA=', pkgA().checked, 'pkgB=', pkgB().checked);
    expect(pkgA().checked).toBe(false);
    expect(pkgB().checked).toBe(true);
});
