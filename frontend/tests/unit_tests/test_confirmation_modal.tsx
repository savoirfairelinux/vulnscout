import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import ConfirmationModal from '../../src/components/ConfirmationModal';

describe('ConfirmationModal', () => {
    const defaultProps = {
        isOpen: true,
        message: 'Are you sure you want to delete this item?',
        onConfirm: jest.fn(),
        onCancel: jest.fn()
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should not render when isOpen is false', () => {
        // ARRANGE & ACT
        render(<ConfirmationModal {...defaultProps} isOpen={false} />);

        // ASSERT
        expect(screen.queryByText('Are you sure you want to delete this item?')).not.toBeInTheDocument();
    });

    test('should render with default props when isOpen is true', () => {
        // ARRANGE & ACT
        render(<ConfirmationModal {...defaultProps} />);

        // ASSERT
        expect(screen.getByText('Confirm Action')).toBeInTheDocument();
        expect(screen.getByText('Are you sure you want to delete this item?')).toBeInTheDocument();
        expect(screen.getByText('Yes')).toBeInTheDocument();
        expect(screen.getByText('No')).toBeInTheDocument();
        expect(screen.queryByRole('img', { hidden: true })).not.toBeInTheDocument(); // No title icon by default
    });

    test('should render with custom props', () => {
        // ARRANGE & ACT
        render(
            <ConfirmationModal
                {...defaultProps}
                title="Custom Title"
                confirmText="Delete"
                cancelText="Cancel"
                showTitleIcon={true}
            />
        );

        // ASSERT
        expect(screen.getByText('Custom Title')).toBeInTheDocument();
        expect(screen.getByText('Delete')).toBeInTheDocument();
        expect(screen.getByText('Cancel')).toBeInTheDocument();
        // Check for the warning icon SVG by finding SVG with specific class
        const titleIcon = document.querySelector('svg.w-5.h-5.text-yellow-500');
        expect(titleIcon).toBeInTheDocument();
    });

    test('should call onConfirm when confirm button is clicked', async () => {
        // ARRANGE
        const user = userEvent.setup();
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        const confirmButton = screen.getByText('Yes');
        await user.click(confirmButton);

        // ASSERT
        expect(defaultProps.onConfirm).toHaveBeenCalledTimes(1);
    });

    test('should call onCancel when cancel button is clicked', async () => {
        // ARRANGE
        const user = userEvent.setup();
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        const cancelButton = screen.getByText('No');
        await user.click(cancelButton);

        // ASSERT
        expect(defaultProps.onCancel).toHaveBeenCalledTimes(1);
    });

    test('should call onCancel when close button (X) is clicked', async () => {
        // ARRANGE
        const user = userEvent.setup();
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        const closeButton = screen.getByRole('button', { name: /close modal/i });
        await user.click(closeButton);

        // ASSERT
        expect(defaultProps.onCancel).toHaveBeenCalledTimes(1);
    });

    test('should call onCancel when Escape key is pressed', () => {
        // ARRANGE
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });

        // ASSERT
        expect(defaultProps.onCancel).toHaveBeenCalledTimes(1);
    });

    test('should not call onCancel when other keys are pressed', () => {
        // ARRANGE
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        fireEvent.keyDown(document, { key: 'Enter', code: 'Enter' });
        fireEvent.keyDown(document, { key: 'Space', code: 'Space' });
        fireEvent.keyDown(document, { key: 'Tab', code: 'Tab' });

        // ASSERT
        expect(defaultProps.onCancel).not.toHaveBeenCalled();
    });

    test('should not add event listener when modal is closed', () => {
        // ARRANGE
        const addEventListenerSpy = jest.spyOn(document, 'addEventListener');
        
        // ACT
        render(<ConfirmationModal {...defaultProps} isOpen={false} />);

        // ASSERT
        expect(addEventListenerSpy).not.toHaveBeenCalledWith('keydown', expect.any(Function));
        
        addEventListenerSpy.mockRestore();
    });

    test('should add and remove event listener when modal opens and closes', () => {
        // ARRANGE
        const addEventListenerSpy = jest.spyOn(document, 'addEventListener');
        const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');
        
        // ACT - Initial render with modal open
        const { rerender } = render(<ConfirmationModal {...defaultProps} isOpen={true} />);
        expect(addEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
        
        // ACT - Close modal
        rerender(<ConfirmationModal {...defaultProps} isOpen={false} />);
        
        // ASSERT
        expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
        
        addEventListenerSpy.mockRestore();
        removeEventListenerSpy.mockRestore();
    });

    test('should cleanup event listener on unmount', () => {
        // ARRANGE
        const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');
        
        // ACT
        const { unmount } = render(<ConfirmationModal {...defaultProps} />);
        unmount();

        // ASSERT
        expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
        
        removeEventListenerSpy.mockRestore();
    });

    test('should show title icon when showTitleIcon is true', () => {
        // ARRANGE & ACT
        render(<ConfirmationModal {...defaultProps} showTitleIcon={true} />);

        // ASSERT
        const titleIcon = document.querySelector('svg.w-5.h-5.text-yellow-500');
        expect(titleIcon).toBeInTheDocument();
        expect(titleIcon).toHaveAttribute('xmlns', 'http://www.w3.org/2000/svg');
    });

    test('should not show title icon when showTitleIcon is false', () => {
        // ARRANGE & ACT
        render(<ConfirmationModal {...defaultProps} showTitleIcon={false} />);

        // ASSERT
        const titleIcon = document.querySelector('svg.w-5.h-5.text-yellow-500');
        expect(titleIcon).not.toBeInTheDocument();
    });

    test('should have correct modal structure and accessibility attributes', () => {
        // ARRANGE & ACT
        render(<ConfirmationModal {...defaultProps} />);

        // ASSERT
        const modal = document.querySelector('[tabindex="-1"]');
        expect(modal).toBeInTheDocument();
        expect(modal).toHaveAttribute('tabIndex', '-1');
        
        const closeButton = screen.getByRole('button', { name: /close modal/i });
        expect(closeButton).toBeInTheDocument();
    });

    test('should handle multiple rapid escape key presses', () => {
        // ARRANGE
        render(<ConfirmationModal {...defaultProps} />);

        // ACT
        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });
        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });
        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });

        // ASSERT
        expect(defaultProps.onCancel).toHaveBeenCalledTimes(3);
    });

    test('should handle onCancel callback changes', () => {
        // ARRANGE
        const newOnCancel = jest.fn();
        const { rerender } = render(<ConfirmationModal {...defaultProps} />);

        // ACT - Update onCancel prop
        rerender(<ConfirmationModal {...defaultProps} onCancel={newOnCancel} />);
        fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });

        // ASSERT
        expect(newOnCancel).toHaveBeenCalledTimes(1);
        expect(defaultProps.onCancel).not.toHaveBeenCalled();
    });
});