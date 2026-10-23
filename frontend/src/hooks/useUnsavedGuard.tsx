import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import UnsavedChangesDialog from "../components/UnsavedChangesDialog";

/** What a page with unsaved edits registers: a name for the prompt and how to save. */
export type UnsavedGuard = { label: string; save: () => Promise<boolean> };

type UnsavedGuardApi = {
    registerGuard: (guard: UnsavedGuard | null) => void;
    hasGuard: boolean;
    /** Resolves true when leaving may go ahead (no guard, saved, or discarded). */
    confirmLeave: () => Promise<boolean>;
};

const NO_GUARD: UnsavedGuardApi = {
    registerGuard: () => undefined,
    hasGuard: false,
    confirmLeave: () => Promise.resolve(true),
};

const UnsavedGuardContext = createContext<UnsavedGuardApi | null>(null);

type Prompt = { label: string; resolve: (proceed: boolean) => void };
type Choice = 'save' | 'discard' | 'cancel';

export function UnsavedGuardProvider({ children }: Readonly<{ children: ReactNode }>) {
    const guardRef = useRef<UnsavedGuard | null>(null);
    const [hasGuard, setHasGuard] = useState(false);
    const [prompt, setPrompt] = useState<Prompt | null>(null);
    const promptRef = useRef<Prompt | null>(null);

    const registerGuard = useCallback((guard: UnsavedGuard | null) => {
        guardRef.current = guard;
        setHasGuard(guard !== null);
    }, []);

    const showPrompt = useCallback((next: Prompt | null) => {
        promptRef.current = next;
        setPrompt(next);
    }, []);

    const confirmLeave = useCallback((): Promise<boolean> => {
        const guard = guardRef.current;
        if (!guard) return Promise.resolve(true);
        // A second request while the prompt is open does not proceed on its own.
        if (promptRef.current) return Promise.resolve(false);
        return new Promise<boolean>(resolve => showPrompt({ label: guard.label, resolve }));
    }, [showPrompt]);

    const answer = useCallback((choice: Choice) => {
        const current = promptRef.current;
        if (!current) return;
        showPrompt(null);
        const guard = guardRef.current;
        if (choice !== 'save' || !guard) {
            current.resolve(choice !== 'cancel');
            return;
        }
        guard.save().then(current.resolve, () => current.resolve(false));
    }, [showPrompt]);

    useEffect(() => {
        if (!hasGuard) return;
        const handleBeforeUnload = (event: BeforeUnloadEvent) => {
            event.preventDefault();
            // Older browsers only prompt when returnValue is set.
            event.returnValue = '';
        };
        window.addEventListener('beforeunload', handleBeforeUnload);
        return () => window.removeEventListener('beforeunload', handleBeforeUnload);
    }, [hasGuard]);

    const api = useMemo(() => ({ registerGuard, hasGuard, confirmLeave }), [registerGuard, hasGuard, confirmLeave]);

    return (
        <UnsavedGuardContext.Provider value={api}>
            {children}
            {prompt && (
                <UnsavedChangesDialog
                    label={prompt.label}
                    onSave={() => answer('save')}
                    onDiscard={() => answer('discard')}
                    onCancel={() => answer('cancel')}
                />
            )}
        </UnsavedGuardContext.Provider>
    );
}

/** Outside a provider every leave is allowed, so unrelated trees need no setup. */
// eslint-disable-next-line react-refresh/only-export-components
export function useUnsavedGuard(): UnsavedGuardApi {
    return useContext(UnsavedGuardContext) ?? NO_GUARD;
}
