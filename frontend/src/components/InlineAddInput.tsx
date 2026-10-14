// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { useEffect, useId, useRef, useState, type FocusEvent, type KeyboardEvent, type ReactNode } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPlus, faSpinner } from '@fortawesome/free-solid-svg-icons';

type InlineAddInputProps = {
    isOpen: boolean;
    onOpenChange: (open: boolean) => void;
    /** Reject with an Error to display its message under the input. */
    onSubmit: (name: string) => Promise<void>;
    inputAriaLabel: string;
    submitAriaLabel: string;
    placeholder?: string;
    buttonClassName: string;
    /** Collapsed button content, which also provides its accessible name. */
    children: ReactNode;
    /** Wrapper classes applied while open. */
    className?: string;
};

const inputClass = 'min-w-0 flex-1 rounded px-2 py-1 text-xs bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400';
const submitClass = 'flex h-7 w-7 shrink-0 items-center justify-center rounded bg-cyan-800 text-white hover:bg-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed';

export default function InlineAddInput({
    isOpen,
    onOpenChange,
    onSubmit,
    inputAriaLabel,
    submitAriaLabel,
    placeholder,
    buttonClassName,
    children,
    className,
}: Readonly<InlineAddInputProps>) {
    const [name, setName] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const mountedRef = useRef(true);
    const submitRef = useRef<HTMLButtonElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);
    const triggerRef = useRef<HTMLButtonElement>(null);
    const focusTriggerRef = useRef(false);
    const focusInputRef = useRef(false);
    // Bumped on every close so a submit that settles later knows it no longer owns the input.
    const openSessionRef = useRef(0);
    const errorId = useId();

    useEffect(() => {
        mountedRef.current = true;
        return () => { mountedRef.current = false; };
    }, []);

    useEffect(() => {
        setError(null);
        if (!isOpen) {
            openSessionRef.current += 1;
            setName('');
            if (focusTriggerRef.current) triggerRef.current?.focus();
        }
        focusTriggerRef.current = false;
    }, [isOpen]);

    useEffect(() => {
        if (!busy && focusInputRef.current) inputRef.current?.focus();
        focusInputRef.current = false;
    }, [busy]);

    const trimmed = name.trim();

    const submit = async () => {
        if (!trimmed || busy) return;
        const session = openSessionRef.current;
        const stillOpen = () => mountedRef.current && openSessionRef.current === session;
        setBusy(true);
        setError(null);
        try {
            await onSubmit(trimmed);
            if (mountedRef.current) setBusy(false);
            if (stillOpen()) onOpenChange(false);
        } catch (err) {
            if (!mountedRef.current) return;
            if (stillOpen()) {
                setError(err instanceof Error && err.message ? err.message : 'Failed to create.');
                focusInputRef.current = true;
            }
            setBusy(false);
        }
    };

    if (!isOpen) {
        return (
            <button ref={triggerRef} type="button" className={buttonClassName} onClick={() => onOpenChange(true)}>
                {children}
            </button>
        );
    }

    const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
        if (event.nativeEvent.isComposing) return;
        if (event.key === 'Enter') {
            event.preventDefault();
            void submit();
        } else if (event.key === 'Escape') {
            focusTriggerRef.current = true;
            onOpenChange(false);
        }
    };

    const handleBlur = (event: FocusEvent<HTMLInputElement>) => {
        if (!name && event.relatedTarget !== submitRef.current) {
            onOpenChange(false);
        }
    };

    return (
        <div className={className}>
            <div className="flex items-center gap-1">
                <input
                    ref={inputRef}
                    type="text"
                    value={name}
                    placeholder={placeholder}
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
                    <FontAwesomeIcon icon={busy ? faSpinner : faPlus} spin={busy} />
                </button>
            </div>
            {error && <p id={errorId} role="alert" className="mt-1 text-xs text-red-400">{error}</p>}
        </div>
    );
}
