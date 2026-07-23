import { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleInfo } from '@fortawesome/free-solid-svg-icons';

type Props = {
    id: string;
    condition: string;
    error: string;
    subject: string;
    onConditionChange: (condition: string) => void;
    onApply: () => void;
};

function MatchConditionFilter({ id, condition, error, subject, onConditionChange, onApply }: Readonly<Props>) {
    const [showHelp, setShowHelp] = useState(false);
    const helpButtonRef = useRef<HTMLButtonElement>(null);
    const helpDropdownRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!showHelp) return;

        const handleClickOutside = (event: MouseEvent) => {
            if (
                helpDropdownRef.current &&
                helpButtonRef.current &&
                !helpDropdownRef.current.contains(event.target as Node) &&
                !helpButtonRef.current.contains(event.target as Node)
            ) {
                setShowHelp(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [showHelp]);

    const helpId = `${id}-help`;

    return (
        <>
            <label htmlFor={id} className="ml-2">Match condition</label>
            <input
                id={id}
                value={condition}
                onChange={event => onConditionChange(event.target.value)}
                onKeyDown={event => { if (event.key === 'Enter') onApply(); }}
                className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[260px]"
                placeholder="cvss >= 7 and pending"
                aria-invalid={error ? 'true' : 'false'}
            />
            <div className="relative">
                <button
                    ref={helpButtonRef}
                    aria-label="match condition help"
                    aria-expanded={showHelp}
                    aria-controls={helpId}
                    title="View match condition help"
                    type="button"
                    className="text-white hover:text-blue-300 transition-colors"
                    onClick={() => setShowHelp(!showHelp)}
                >
                    <FontAwesomeIcon icon={faCircleInfo} />
                </button>
                {showHelp && (
                    <div
                        id={helpId}
                        ref={helpDropdownRef}
                        className="absolute right-0 top-full mt-1 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-4 z-50 w-[360px] text-sm"
                    >
                        <h3 className="font-bold text-white mb-2">Match condition</h3>
                        <div className="space-y-2 text-gray-100">
                            <p>Filter {subject} by vulnerability facts. Press Enter to apply the condition.</p>
                            <p><code className="text-cyan-300">field operator value</code> with <code className="text-cyan-300">==</code>, <code className="text-cyan-300">!=</code>, <code className="text-cyan-300">&lt;</code>, <code className="text-cyan-300">&gt;</code>, <code className="text-cyan-300">&lt;=</code>, or <code className="text-cyan-300">&gt;=</code>. Combine conditions with <code className="text-cyan-300">and</code>, <code className="text-cyan-300">or</code>, <code className="text-cyan-300">not</code>, and parentheses.</p>
                            <p>Facts: <code className="text-cyan-300">cvss</code>, <code className="text-cyan-300">cvss_min</code>, <code className="text-cyan-300">epss</code>, <code className="text-cyan-300">effort</code>, <code className="text-cyan-300">effort_min</code>, <code className="text-cyan-300">effort_max</code>, <code className="text-cyan-300">fixed</code>, <code className="text-cyan-300">ignored</code>, <code className="text-cyan-300">affected</code>, <code className="text-cyan-300">pending</code>, and <code className="text-cyan-300">new</code>.</p>
                            <p>Examples: <code className="text-cyan-300">cvss &gt;= 7 and pending</code>; <code className="text-cyan-300">epss &gt;= 10% or fixed</code>.</p>
                        </div>
                    </div>
                )}
            </div>
        </>
    );
}

export default MatchConditionFilter;