import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import ScanProgressModal from '../../src/components/ScanProgressModal';

describe('ScanProgressModal', () => {
    it('closes from its close button, backdrop, and Escape key', () => {
        const onClose = jest.fn();
        const { rerender } = render(<ScanProgressModal isOpen={true} onClose={onClose} />);

        expect(screen.getByRole('dialog', { name: 'Scan progress' })).toBeInTheDocument();
    expect(screen.getByText('This window can be safely closed. Track scan progress in the navigation bar.')).toBeInTheDocument();
        expect(screen.getByText('No scan progress to display.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close scan progress' }));
        fireEvent.mouseDown(screen.getByRole('dialog', { name: 'Scan progress' }));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(3);

        rerender(<ScanProgressModal isOpen={false} onClose={onClose} />);
        expect(screen.queryByRole('dialog', { name: 'Scan progress' })).not.toBeInTheDocument();
    });
});