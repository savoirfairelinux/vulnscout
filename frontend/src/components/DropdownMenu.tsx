import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEllipsisH } from '@fortawesome/free-solid-svg-icons';

type DropdownItem = {
    label: string;
    onClick: () => void;
    icon?: any;
};

type Props = {
    items: DropdownItem[];
    buttonClassName?: string;
    menuClassName?: string;
};

function DropdownMenu({ 
    items, 
    buttonClassName = "bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg text-white transition-colors duration-150",
    menuClassName = "bg-slate-800 border border-slate-600 rounded-lg shadow-lg"
}: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);
    const buttonRef = useRef<HTMLButtonElement>(null);

    // Close dropdown when clicking outside
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (menuRef.current && !menuRef.current.contains(event.target as Node) &&
                buttonRef.current && !buttonRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        }

        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
            return () => document.removeEventListener('mousedown', handleClickOutside);
        }
    }, [isOpen]);

    const handleToggle = (e: React.MouseEvent) => {
        e.stopPropagation();
        e.preventDefault();
        setIsOpen(!isOpen);
    };

    // Get button position for portal positioning
    const getButtonPosition = () => {
        if (!buttonRef.current) return { top: 0, left: 0 };
        const rect = buttonRef.current.getBoundingClientRect();
        const viewportHeight = window.innerHeight;
        const dropdownHeight = items.length * 40 + 16; // Estimate dropdown height
        
        // Check if dropdown would be clipped at the bottom
        const spaceBelow = viewportHeight - rect.bottom;
        
        if (spaceBelow < dropdownHeight && rect.top > dropdownHeight) {
            // Show above the button
            return {
                top: rect.top - dropdownHeight,
                left: rect.right - 120 // Align to the right of button
            };
        } else {
            // Show below the button
            return {
                top: rect.bottom + 4,
                left: rect.right - 120 // Align to the right of button
            };
        }
    };

    const buttonPosition = isOpen ? getButtonPosition() : { top: 0, left: 0 };

    return (
        <>
            <div className="relative inline-block">
                <button
                    ref={buttonRef}
                    className={`${buttonClassName} ${isOpen ? 'bg-slate-600' : ''}`}
                    onClick={handleToggle}
                    aria-label="Actions menu"
                    type="button"
                >
                    <FontAwesomeIcon icon={faEllipsisH} />
                </button>
            </div>

            {isOpen && createPortal(
                <div
                    ref={menuRef}
                    className={`fixed z-[9999] ${menuClassName}`}
                    style={{
                        top: buttonPosition.top,
                        left: buttonPosition.left,
                        minWidth: '120px'
                    }}
                >
                    <div className="py-1">
                        {items.map((item, index) => (
                            <button
                                key={index}
                                className="w-full text-left px-4 py-2 text-white hover:bg-slate-700 transition-colors duration-150 flex items-center gap-2"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    item.onClick();
                                    setIsOpen(false);
                                }}
                            >
                                {item.icon && <FontAwesomeIcon icon={item.icon} className="w-4" />}
                                {item.label}
                            </button>
                        ))}
                    </div>
                </div>,
                document.body
            )}
        </>
    );
}

export default DropdownMenu;