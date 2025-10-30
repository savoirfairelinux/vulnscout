import { render } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import MessageBanner from '../../src/components/MessageBanner';

describe('MessageBanner', () => {

    test('renders error banner', () => {
        const { container } = render(
            <MessageBanner 
                type="error" 
                message="Test error" 
                isVisible={true} 
                onClose={() => {}} 
            />
        );
        expect(container.firstChild).not.toBeNull();
    });

    test('renders success banner', () => {
        const { container } = render(
            <MessageBanner 
                type="success" 
                message="Test success" 
                isVisible={true} 
                onClose={() => {}} 
            />
        );
        expect(container.firstChild).not.toBeNull();
    });

    test('does not render when invisible', () => {
        const { container } = render(
            <MessageBanner 
                type="error" 
                message="Test" 
                isVisible={false} 
                onClose={() => {}} 
            />
        );
        expect(container.firstChild).toBeNull();
    });
});