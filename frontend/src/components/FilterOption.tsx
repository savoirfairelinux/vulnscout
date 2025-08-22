import { useState, useEffect, useRef } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCaretDown } from '@fortawesome/free-solid-svg-icons';

type Props = {
    label: string;
    options: string[];
    selected: string[];
    setSelected: (values: string[]) => void;
    parentRef?: React.RefObject<HTMLElement>;
};

function FilterOption({ label, options, selected, setSelected, parentRef }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const [maxHeight, setMaxHeight] = useState<string>('2500px'); 
    const dropdownRef = useRef<HTMLDivElement>(null);

    const toggleOption = (value: string) => {
        if (selected.includes(value)) {
            setSelected(selected.filter(item => item !== value));
        } else {
            setSelected([...selected, value]);
        }
    };

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (
                dropdownRef.current &&
                !dropdownRef.current.contains(event.target as Node)
            ) {
                setIsOpen(false);
            }
        };

        if (isOpen) {
            document.addEventListener("mousedown", handleClickOutside);
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [isOpen]);

    useEffect(() => {
        if (parentRef?.current) {
            const parentHeight = parentRef.current.offsetHeight;
            setMaxHeight(`${parentHeight * 0.6}px`); // 60% of parent height
        }
    }, [parentRef, isOpen]);

    return (
        <div ref={dropdownRef} className="ml-4 relative inline-block text-left">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className={`py-1 px-2 rounded flex items-center gap-1 ${
                    isOpen ? 'bg-sky-950' : 'bg-sky-900'
                } text-white hover:bg-sky-950`}
            >
                {label}
                <FontAwesomeIcon icon={faCaretDown} />
            </button>

            {isOpen && (
                <div 
                    className="absolute mt-1 w-48 bg-sky-900 text-white border border-sky-800 rounded-md shadow-lg z-50"
                    style={{ maxHeight, overflowY: 'auto' }} // <-- dynamic max-height
                >
                    <div className="p-2 space-y-1">
                        {options.map(option => (
                            <label key={option} className="flex items-center space-x-2">
                                <input
                                    type="checkbox"
                                    checked={selected.includes(option)}
                                    onChange={() => toggleOption(option)}
                                    className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                />
                                <span>{option}</span>
                            </label>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

export default FilterOption;
