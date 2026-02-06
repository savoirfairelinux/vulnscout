import { render, screen, fireEvent } from '@testing-library/react';
import { createRef } from 'react';
import '@testing-library/jest-dom';
import Popup from '../../src/components/Popup';

describe('Popup component', () => {
    it('should not render when isOpen is false', () => {
        const anchorRef = createRef<HTMLDivElement>();
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={false} onClose={() => {}} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        expect(screen.queryByText('Popup content')).not.toBeInTheDocument();
    });

    it('should render when isOpen is true', () => {
        const anchorRef = createRef<HTMLDivElement>();
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={() => {}} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        expect(screen.getByText('Popup content')).toBeInTheDocument();
    });

    it('should call onClose when clicking outside', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Click on document body (outside popup)
        fireEvent.mouseDown(document.body);
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('should not call onClose when clicking inside popup', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Click inside popup
        const popup = screen.getByText('Popup content');
        fireEvent.mouseDown(popup);
        expect(onClose).not.toHaveBeenCalled();
    });

    it('should not call onClose when clicking on anchor element', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Click on anchor
        const anchor = screen.getByText('Anchor');
        fireEvent.mouseDown(anchor);
        expect(onClose).not.toHaveBeenCalled();
    });

    it('should call onClose when pressing Escape key', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Press Escape key
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('should not call onClose when pressing other keys', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Press other key
        fireEvent.keyDown(document, { key: 'Enter' });
        expect(onClose).not.toHaveBeenCalled();
    });

    it('should apply custom className', () => {
        const anchorRef = createRef<HTMLDivElement>();
        render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={() => {}} anchorRef={anchorRef} className="custom-class">
                    Popup content
                </Popup>
            </>
        );
        
        const popup = screen.getByText('Popup content');
        expect(popup).toHaveClass('custom-class');
    });

    it('should position popup relative to anchor', () => {
        const anchorRef = createRef<HTMLDivElement>();
        
        // First render to attach the ref
        const { rerender } = render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={false} onClose={() => {}} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Now that the ref is attached, mock getBoundingClientRect on the actual element
        if (anchorRef.current) {
            anchorRef.current.getBoundingClientRect = jest.fn(() => ({
                left: 100,
                top: 200,
                width: 50,
                height: 30,
                bottom: 230,
                right: 150,
                x: 100,
                y: 200,
                toJSON: () => {}
            }));
        }
        
        // Re-render with popup open to trigger position calculation
        rerender(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={() => {}} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Popup renders in a portal to document.body
        const popup = screen.getByText('Popup content');
        
        // Verify positioning classes and inline styles
        expect(popup).toHaveClass('-translate-x-1/2');
        expect(popup).toHaveClass('fixed');
        // Check that position is set via inline styles (left: 125px = 100 + 50/2, top: 234px = 230 + 4)
        expect(popup.style.left).toBe('125px');
        expect(popup.style.top).toBe('234px');
    });

    it('should handle missing anchor ref gracefully', () => {
        const anchorRef = createRef<HTMLDivElement>();
        
        render(
            <Popup isOpen={true} onClose={() => {}} anchorRef={anchorRef}>
                Popup content
            </Popup>
        );
        
        const popup = screen.getByText('Popup content');
        expect(popup).toHaveStyle({ left: '0px', top: '0px' });
    });

    it('should cleanup event listeners when closing', () => {
        const onClose = jest.fn();
        const anchorRef = createRef<HTMLDivElement>();
        
        const { rerender } = render(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={true} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Close the popup
        rerender(
            <>
                <div ref={anchorRef}>Anchor</div>
                <Popup isOpen={false} onClose={onClose} anchorRef={anchorRef}>
                    Popup content
                </Popup>
            </>
        );
        
        // Events should not trigger after closing
        fireEvent.mouseDown(document.body);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).not.toHaveBeenCalled();
    });
});
