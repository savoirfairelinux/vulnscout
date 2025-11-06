import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import PackageDetails from '../../src/components/PackageDetails';

describe('PackageDetails Component', () => {
    test('renders title and toggles visibility when clicked', async () => {
        render(
            <PackageDetails title="Test Package Details">
                <li>Child item 1</li>
                <li>Child item 2</li>
            </PackageDetails>
        );

        // Title should be visible
        const title = screen.getByText('Test Package Details');
        expect(title).toBeInTheDocument();

        // Children should be hidden initially
        const childList = screen.getByRole('list');
        expect(childList).toHaveClass('hidden');
        
        // Click to show children
        const user = userEvent.setup();
        await user.click(title);
        
        // Children should now be displayed
        expect(childList).toHaveClass('display');
        
        // Click again to hide children
        await user.click(title);
        
        // Children should be hidden again
        expect(childList).toHaveClass('hidden');
    });

    test('renders children content when expanded', async () => {
        render(
            <PackageDetails title="Package Info">
                <li>Item 1</li>
                <li>Item 2</li>
                <li>Item 3</li>
            </PackageDetails>
        );

        const title = screen.getByText('Package Info');
        const user = userEvent.setup();
        
        // Expand the details
        await user.click(title);
        
        // All children should be rendered
        expect(screen.getByText('Item 1')).toBeInTheDocument();
        expect(screen.getByText('Item 2')).toBeInTheDocument();
        expect(screen.getByText('Item 3')).toBeInTheDocument();
    });

    test('handles single child element', async () => {
        render(
            <PackageDetails title="Single Child">
                <div>Single child content</div>
            </PackageDetails>
        );

        const title = screen.getByText('Single Child');
        const user = userEvent.setup();
        
        await user.click(title);
        
        expect(screen.getByText('Single child content')).toBeInTheDocument();
    });
});