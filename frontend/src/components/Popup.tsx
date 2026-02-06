import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

type Props = {
    isOpen: boolean;
    onClose: () => void;
    anchorRef: React.RefObject<HTMLElement>;
    children: React.ReactNode;
    className?: string;
};

function Popup({ isOpen, onClose, anchorRef, children, className = '' }: Readonly<Props>) {
    const popupRef = useRef<HTMLDivElement>(null);

    // Close popup when clicking outside
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (popupRef.current && !popupRef.current.contains(event.target as Node) &&
                anchorRef.current && !anchorRef.current.contains(event.target as Node)) {
                onClose();
            }
        }

        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
            return () => document.removeEventListener('mousedown', handleClickOutside);
        }
    }, [isOpen, onClose, anchorRef]);

    // Close on Escape key
    useEffect(() => {
        function handleEscape(event: KeyboardEvent) {
            if (event.key === 'Escape') {
                onClose();
            }
        }

        if (isOpen) {
            document.addEventListener('keydown', handleEscape);
            return () => document.removeEventListener('keydown', handleEscape);
        }
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    const getPosition = () => {
        if (!anchorRef.current) return { top: 0, left: 0 };
        const rect = anchorRef.current.getBoundingClientRect();
        return {
            left: rect.left + rect.width / 2,
            top: rect.bottom + 4
        };
    };

    const position = getPosition();

    return createPortal(
        <div
            ref={popupRef}
            className={`fixed z-[9999] bg-gray-800 text-white text-xs rounded py-2 px-3 whitespace-nowrap shadow-lg border border-gray-600 -translate-x-1/2 ${className}`}
            style={{
                left: `${position.left}px`,
                top: `${position.top}px`
            }}
        >
            {children}
        </div>,
        document.body
    );
}

export default Popup;
