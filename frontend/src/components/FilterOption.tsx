import { useState, useEffect, useRef } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCaretDown } from '@fortawesome/free-solid-svg-icons';

type Props = {
    label: string;
    options: string[];
    selected: string[];
    setSelected: (values: string[]) => void;
    parentRef?: React.RefObject<HTMLElement>;
    CustomFilterComponent?: React.ComponentType<any>;
    customFilterName?: string;
    showCustomFilterComponent?: boolean;
    setShowCustomFilterComponent?: (show: boolean) => void;
    /** Render a search input at the top of the dropdown to narrow the option list */
    searchable?: boolean;
    /** Format an option value for display; checkbox values stay raw */
    formatLabel?: (value: string) => string;
};

function FilterOption({ label, options, selected, setSelected, parentRef, CustomFilterComponent, customFilterName = 'custom', showCustomFilterComponent, setShowCustomFilterComponent, searchable = false, formatLabel }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const [maxHeight, setMaxHeight] = useState<string>('500px'); 
    const [optionSearch, setOptionSearch] = useState('');
    const dropdownRef = useRef<HTMLDivElement>(null);
    const isActive = selected.length > 0 || showCustomFilterComponent;

    const displayLabel = (value: string) => formatLabel ? formatLabel(value) : value;

    const visibleOptions = searchable && optionSearch.trim() !== ''
        ? options.filter(option => {
            const needle = optionSearch.trim().toLowerCase();
            return option.toLowerCase().includes(needle) || displayLabel(option).toLowerCase().includes(needle);
        })
        : options;

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

    // Reset the option search whenever the dropdown closes
    useEffect(() => {
        if (!isOpen) setOptionSearch('');
    }, [isOpen]);

    return (
        <div ref={dropdownRef} className="ml-4 relative inline-block text-left">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className={`py-1 px-2 rounded flex items-center gap-1 border ${
                    isOpen ? 'bg-sky-950' : 'bg-sky-900'
                } ${
                    isActive ? 'border-cyan-400' : 'border-transparent'
                } text-white hover:bg-sky-950`}
            >
                {label}
                <FontAwesomeIcon icon={faCaretDown} />
            </button>

            {isOpen && (
                <div 
                    className={`absolute mt-1 ${searchable ? 'w-72' : 'w-48'} bg-sky-900 text-white border border-sky-800 rounded-md shadow-lg z-50`}
                    style={{ maxHeight, overflowY: 'auto' }} // <-- dynamic max-height
                >
                    <div className="p-2 space-y-1">
                        {searchable && (
                            <input
                                type="search"
                                value={optionSearch}
                                onChange={(event) => setOptionSearch(event.target.value)}
                                placeholder={`Search ${label.toLowerCase()}...`}
                                aria-label={`Search ${label.toLowerCase()}`}
                                className="w-full mb-1 py-1 px-2 rounded bg-sky-800 focus:bg-sky-950 placeholder-gray-400 text-sm"
                            />
                        )}
                        {visibleOptions.map(option => (
                            <label key={option} className="flex items-center space-x-2">
                                <input
                                    type="checkbox"
                                    checked={selected.includes(option)}
                                    onChange={() => {
                                        toggleOption(option)
                                        setShowCustomFilterComponent?.(false); // Uncheck custom when any option is toggled
                                    }}
                                    className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                />
                                <span>{displayLabel(option)}</span>
                            </label>
                        ))}
                        {searchable && visibleOptions.length === 0 && (
                            <span className="text-xs text-gray-400 italic">No match found</span>
                        )}
                        {CustomFilterComponent && 
                            <label key={`custom-filter-${customFilterName}`} className="flex items-center space-x-2">
                                <input
                                    type="checkbox"
                                    id={`custom-filter-checkbox-${customFilterName}`}
                                    checked={showCustomFilterComponent}
                                    onChange={() => {
                                        setShowCustomFilterComponent?.(!showCustomFilterComponent)
                                        if(!showCustomFilterComponent){
                                            setSelected([]); // Clear other options when custom is selected
                                        }
                                    }}
                                    className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                />
                                <span>{customFilterName}</span>
                            </label>
                        }
                        {(CustomFilterComponent && showCustomFilterComponent) && <CustomFilterComponent />}
                    </div>
                </div>
            )}
        </div>
    );
}

export default FilterOption;
