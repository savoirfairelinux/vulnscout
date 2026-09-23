import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import { MemoryRouter } from 'react-router-dom';

import NavigationBar from '../../src/components/NavigationBar';
import { ROUTES } from '../../src/routes';

jest.mock('../../src/components/VersionDisplay', () => ({ __esModule: true, default: () => null }));
jest.mock('../../src/components/ProjectVariantSelector', () => ({ __esModule: true, default: () => null }));

const DEFAULT_PROPS = {
    onApply: jest.fn(),
};

function renderAt(path: string) {
    return render(
        <MemoryRouter initialEntries={[path]}>
            <NavigationBar {...DEFAULT_PROPS} />
        </MemoryRouter>,
    );
}

describe('NavigationBar', () => {
    test.each([
        ['VulnScout', ROUTES.metrics],
        ['SBOM', ROUTES.packages],
        ['Vulnerabilities', ROUTES.vulnerabilities],
        ['Scans', ROUTES.scans],
        ['Review', ROUTES.review],
        ['AI', ROUTES.ai],
        ['Export', ROUTES.exports],
    ])('links "%s" to its route path', (label, path) => {
        renderAt('/');

        expect(screen.getByRole('link', { name: new RegExp(label) })).toHaveAttribute('href', path);
    });

    test('the settings link has an accessible name and its own route path', () => {
        renderAt('/');

        const settingsLink = screen.getByRole('link', { name: 'Settings' });
        expect(settingsLink).toHaveAttribute('href', ROUTES.settings);
    });

    test('marks the current page link with aria-current', () => {
        renderAt(ROUTES.vulnerabilities);

        expect(screen.getByRole('link', { name: 'Vulnerabilities' })).toHaveAttribute('aria-current', 'page');
        expect(screen.getByRole('link', { name: /VulnScout/ })).not.toHaveAttribute('aria-current');
    });

    test('marks the dashboard link current only on the exact root path, not on other routes', () => {
        renderAt(ROUTES.packages);

        expect(screen.getByRole('link', { name: /VulnScout/ })).not.toHaveAttribute('aria-current');
        expect(screen.getByRole('link', { name: 'SBOM' })).toHaveAttribute('aria-current', 'page');
    });

    test('shows the operation queue button only once there are tracked operations', () => {
        renderAt('/');
        expect(screen.queryByLabelText(/Open operation queue/)).not.toBeInTheDocument();

        render(
            <MemoryRouter>
                <NavigationBar {...DEFAULT_PROPS} trackedScanCount={3} finishedScanCount={1} activeScanCount={1} />
            </MemoryRouter>,
        );
        expect(screen.getByLabelText('Open operation queue, 1 of 3 finished')).toBeInTheDocument();
    });
});
