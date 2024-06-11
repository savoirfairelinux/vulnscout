import { render, screen } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-ignore
import React from 'react';

import Loading from '../../src/pages/Loading';



describe('Loading Page', () => {

    test('should render loading page', async () => {
        // ARRANGE
        render(<Loading />);

        // ACT
        const title = await screen.getByText(/running/i);
        const subtitle = await screen.getByText(/step 0/i);

        // ASSERT
        expect(title).toBeInTheDocument();
        expect(subtitle).toBeInTheDocument();
    })
});
