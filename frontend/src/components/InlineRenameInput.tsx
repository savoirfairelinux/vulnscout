// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { useEffect, useId, useRef, useState, type FocusEvent, type KeyboardEvent } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCheck, faSpinner } from '@fortawesome/free-solid-svg-icons';

type InlineRenameInputProps = {
    initialName: string;
    /** Reject with an Error to keep the input open and display its message under it. */
    onSubmit: (name: string) => Promise<void>;
    onClose: () => void;
    inputAriaLabel: string;
    submitAriaLabel: string;
    className?: string;
};

const inputClass = 'min-w-0 flex-1 rounded px-2 py-1 text-xs bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400';
const submitClass = 'flex h-7 w-7 shrink-0 items-center justify-center rounded bg-cyan-800 text-white hover:bg-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed';

export default function InlineRenameInput({
    initialName,
    onSubmit,
    onClose,
    inputAriaLabel,
    submitAriaLabel,
    className,
}: Readonly<InlineRenameInputProps>) {
    const [name, setName] = useState(initialName);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const mountedRef = useRef(true);
    const inputRef = useRef<HTMLInputElement>(null);
    const submitRef = useRef<HTMLButtonElement>(null);
    const errorId = useId();

    useEffect(() => {
        mountedRef.current = true;
        inputRef.current?.select();
        return () => { mountedRef.current = false; };
    }, []);

    useEffect(() => {
        if (!busy && error) inputRef.current?.focus();
    }, [busy, error]);

    const trimmed = name.trim();

    const submit = async () => {
        if (!trimmed || busy) return;
        if (trimmed === initialName) {
            onClose();
            return;
        }
        setBusy(true);
        setError(null);
        try {
            await onSubmit(trimmed);
            if (mountedRef.current) onClose();
        } catch (err) {
            if (!mountedRef.current) return;
            setError(err instanceof Error && err.message ? err.message : 'Failed to rename.');
            setBusy(false);
        }
    };

    const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
        if (event.nativeEvent.isComposing) return;
        if (event.key === 'Enter') {
            event.preventDefault();
            void submit();
        } else if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            onClose();
        }
    };

    const handleBlur = (event: FocusEvent<HTMLInputElement>) => {
        if (busy || event.relatedTarget === submitRef.current) return;
        onClose();
    };

    return (
        <div className={className}>
            <div className="flex items-center gap-1">
                <input
                    ref={inputRef}
                    type="text"
                    value={name}
                    aria-label={inputAriaLabel}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={error ? errorId : undefined}
                    autoFocus
                    disabled={busy}
                    className={inputClass}
                    onChange={(event) => {
                        setName(event.target.value);
                        setError(null);
                    }}
                    onKeyDown={handleKeyDown}
                    onBlur={handleBlur}
                />
                <button
                    ref={submitRef}
                    type="button"
                    aria-label={submitAriaLabel}
                    className={submitClass}
                    disabled={!trimmed || busy}
                    onClick={() => void submit()}
                >
                    <FontAwesomeIcon icon={busy ? faSpinner : faCheck} spin={busy} />
                </button>
            </div>
            {error && <p id={errorId} role="alert" className="mt-1 text-xs text-red-400">{error}</p>}
        </div>
    );
}
