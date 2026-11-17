import { useEffect, useRef, useState, type ReactNode } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCheck, faCopy } from '@fortawesome/free-solid-svg-icons';

/** Markdown code block with its own copy button, so each value can be pasted on its own. */
function AgentCodeBlock({ children, buttonClassName, onCopyError }: Readonly<{
    children?: ReactNode; buttonClassName: string; onCopyError: () => void;
}>) {
    const block = useRef<HTMLPreElement>(null);
    const [copied, setCopied] = useState(false);
    useEffect(() => {
        if (!copied) return;
        const timer = window.setTimeout(() => setCopied(false), 2000);
        return () => window.clearTimeout(timer);
    }, [copied]);

    async function copy() {
        try {
            // Markdown keeps the fence's final newline; a pasted field value should not end with it.
            await navigator.clipboard.writeText((block.current?.textContent ?? '').replace(/\n$/, ''));
            setCopied(true);
        } catch {
            onCopyError();
        }
    }

    return (
        <div className="relative my-3">
            <pre ref={block} className="max-w-full overflow-x-auto rounded border border-neutral-200 bg-neutral-50 p-3 pr-11 dark:border-neutral-800 dark:bg-neutral-900 [&_code]:bg-transparent [&_code]:p-0">{children}</pre>
            <button type="button" title={copied ? 'Copied' : 'Copy code block'} aria-label="Copy code block" onClick={() => void copy()} className={`${buttonClassName} absolute right-1 top-1 h-8 w-8`}>
                <FontAwesomeIcon icon={copied ? faCheck : faCopy} className="text-xs" />
            </button>
        </div>
    );
}

export default AgentCodeBlock;
