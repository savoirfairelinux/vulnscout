import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import { MemoryRouter } from 'react-router-dom';

import NotFound from '../../src/pages/NotFound';
import { ROUTES } from '../../src/routes';

describe('NotFound', () => {
    test('shows a 404 heading and message', () => {
        render(<NotFound />, { wrapper: MemoryRouter });

        expect(screen.getByRole('heading', { name: '404' })).toBeInTheDocument();
        expect(screen.getByText(/page.*not.*found/i)).toBeInTheDocument();
    });

    test('links back to the dashboard', () => {
        render(<NotFound />, { wrapper: MemoryRouter });

        expect(screen.getByRole('link', { name: /dashboard/i })).toHaveAttribute('href', ROUTES.metrics);
    });
});
