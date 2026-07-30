import { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion } from '@fortawesome/free-solid-svg-icons';

type Props = {
    heading: string;
    text: string;
    ariaLabel: string;
};

export default function HintButton({ heading, text, ariaLabel }: Readonly<Props>) {
    const [open, setOpen] = useState(false);

    return (
        <div className="relative">
            <button
                type="button"
                aria-label={ariaLabel}
                title={`View ${heading.toLowerCase()}`}
                className="text-white hover:text-blue-300 transition-colors"
                onClick={() => setOpen(!open)}
            >
                <FontAwesomeIcon icon={faCircleQuestion} />
            </button>
            {open && (
                <div
                    className="absolute top-full right-0 mt-1 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-4 z-50 w-[400px] text-sm"
                >
                    <h3 className="font-bold text-white mb-3">{heading}</h3>
                    <div className="text-gray-100">{text}</div>
                </div>
            )}
        </div>
    );
}