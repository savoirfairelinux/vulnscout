import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { useState } from 'react';

import TargetPairSelector from '../../src/components/TargetPairSelector';
import type { AssessmentTargetPair } from '../../src/handlers/assessments';

const variants = [
    { id: 'v1', name: 'Variant One', project_id: 'project' },
    { id: 'v2', name: 'Variant Two', project_id: 'project' },
];
const packages = ['pkg1@1.0.0', 'pkg2@2.0.0'];
const compatibility = {
    v1: ['pkg1@1.0.0'],
    v2: ['pkg2@2.0.0'],
};

function Harness({ initial = [] }: Readonly<{ initial?: AssessmentTargetPair[] }>) {
    const [targets, setTargets] = useState(initial);
    return (
        <TargetPairSelector
            variants={variants}
            packages={packages}
            variantPackageMap={compatibility}
            selectedTargets={targets}
            onChange={setTargets}
        />
    );
}

describe('TargetPairSelector bulk controls', () => {
    test('select all and deselect all affect only compatible pairs', async () => {
        const user = userEvent.setup();
        render(<Harness />);

        await user.click(screen.getByRole('button', { name: 'Select all' }));
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg1@1.0.0' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg2@2.0.0' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg2@2.0.0' })).toBeDisabled();
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg1@1.0.0' })).toBeDisabled();

        await user.click(screen.getByRole('button', { name: 'Deselect all' }));
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg1@1.0.0' })).not.toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg2@2.0.0' })).not.toBeChecked();
    });

    test('row controls select all compatible packages for one variant', async () => {
        const user = userEvent.setup();
        render(<Harness />);

        await user.click(screen.getByRole('button', { name: 'Select all for variant Variant One' }));
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg1@1.0.0' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg2@2.0.0' })).not.toBeChecked();

        await user.click(screen.getByRole('button', { name: 'Deselect all for variant Variant One' }));
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg1@1.0.0' })).not.toBeChecked();
    });

    test('column controls select all compatible variants for one package', async () => {
        const user = userEvent.setup();
        render(<Harness />);

        await user.click(screen.getByRole('button', { name: 'Select all for package pkg2@2.0.0' }));
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg2@2.0.0' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Variant One / pkg1@1.0.0' })).not.toBeChecked();

        await user.click(screen.getByRole('button', { name: 'Deselect all for package pkg2@2.0.0' }));
        expect(screen.getByRole('checkbox', { name: 'Variant Two / pkg2@2.0.0' })).not.toBeChecked();
    });
});
