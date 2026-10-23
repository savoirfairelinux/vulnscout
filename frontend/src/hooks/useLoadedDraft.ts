import { useCallback, useEffect, useRef, useState } from "react";

type DraftState<T> = { draft: T; baseline: T | null; loading: boolean };

export type LoadedDraft<T> = DraftState<T> & {
    /** True once loaded and the draft differs from the last loaded or saved value. */
    dirty: boolean;
    setDraft: (draft: T) => void;
    /**
     * Adopt a saved value as the baseline, and as the draft unless the draft
     * was edited after `sent` went out (those edits stay, as unsaved changes).
     */
    commit: (saved: T, sent: T) => void;
    /** Drop edits: the draft goes back to the baseline. */
    reset: () => void;
    reload: () => void;
};

/**
 * Editable copy of a server value plus the value it was loaded from. `key`
 * identifies what to load; null means nothing is open. Load failures are
 * reported through `onError` and leave no baseline, so nothing can be saved
 * over a value that was never seen.
 */
export function useLoadedDraft<T>(
    key: string | null,
    load: () => Promise<T>,
    empty: T,
    equal: (a: T, b: T) => boolean,
    onError: (message: string) => void,
): LoadedDraft<T> {
    const [state, setState] = useState<DraftState<T>>({ draft: empty, baseline: null, loading: false });
    const loadRef = useRef(load);
    const emptyRef = useRef(empty);
    const onErrorRef = useRef(onError);
    const equalRef = useRef(equal);
    const loadIdRef = useRef(0);
    const keyRef = useRef<string | null>(null);
    useEffect(() => {
        loadRef.current = load;
        onErrorRef.current = onError;
        equalRef.current = equal;
    });

    const reload = useCallback(() => {
        const loadId = ++loadIdRef.current;
        const keyChanged = keyRef.current !== key;
        keyRef.current = key;
        if (key === null) {
            setState({ draft: emptyRef.current, baseline: null, loading: false });
            return;
        }
        // A reload of the same item keeps showing it; a new item starts blank.
        setState(prev => keyChanged
            ? { draft: emptyRef.current, baseline: null, loading: true }
            : { ...prev, loading: true });
        loadRef.current().then(value => {
            if (loadId === loadIdRef.current) setState({ draft: value, baseline: value, loading: false });
        }).catch((e: unknown) => {
            if (loadId !== loadIdRef.current) return;
            setState({ draft: emptyRef.current, baseline: null, loading: false });
            onErrorRef.current(e instanceof Error && e.message ? e.message : "Failed to load context.");
        });
    }, [key]);

    useEffect(() => {
        reload();
    }, [reload]);
    // Responses arriving after unmount are ignored.
    useEffect(() => () => { loadIdRef.current += 1; }, []);

    const setDraft = useCallback((draft: T) => setState(prev => ({ ...prev, draft })), []);
    const commit = useCallback((saved: T, sent: T) => setState(prev => (
        !equalRef.current(prev.draft, sent)
            ? { ...prev, baseline: saved }
            : { ...prev, draft: saved, baseline: saved }
    )), []);
    const reset = useCallback(() => setState(prev => (
        prev.baseline === null ? prev : { ...prev, draft: prev.baseline }
    )), []);

    const dirty = state.baseline !== null && !equal(state.draft, state.baseline);
    return { ...state, dirty, setDraft, commit, reset, reload };
}
