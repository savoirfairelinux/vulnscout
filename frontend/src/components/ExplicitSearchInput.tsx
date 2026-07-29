import { forwardRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faMagnifyingGlass } from '@fortawesome/free-solid-svg-icons';

type Props = {
    id: string;
    label: string;
    value: string;
    onChange: (value: string) => void;
    onSearch: () => void | Promise<void>;
    placeholder: string;
    ariaLabel: string;
    loading?: boolean;
    ariaInvalid?: boolean;
    labelClassName?: string;
    inputClassName?: string;
    inputType?: 'search' | 'text';
};

const ExplicitSearchInput = forwardRef<HTMLInputElement, Readonly<Props>>(function ExplicitSearchInput({
    id,
    label,
    value,
    onChange,
    onSearch,
    placeholder,
    ariaLabel,
    loading = false,
    ariaInvalid = false,
    labelClassName,
    inputClassName = 'py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]',
    inputType = 'search',
}, ref) {
    const applySearch = () => void onSearch();

    return <>
        <label htmlFor={id} className={labelClassName}>{label}</label>
        <input
            id={id}
            ref={ref}
            value={value}
            onChange={event => onChange(event.target.value)}
            onKeyDown={event => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    applySearch();
                }
            }}
            type={inputType}
            aria-invalid={ariaInvalid}
            className={inputClassName}
            placeholder={placeholder}
        />
        <button
            type="button"
            aria-label={ariaLabel}
            title={ariaLabel}
            disabled={loading}
            onClick={applySearch}
            className="py-1 px-3 rounded bg-cyan-700 hover:bg-cyan-600 disabled:cursor-wait disabled:opacity-60"
        >
            <FontAwesomeIcon
                icon={faMagnifyingGlass}
                aria-hidden="true"
                className={loading ? 'animate-pulse' : undefined}
            />
        </button>
    </>;
});

export default ExplicitSearchInput;
