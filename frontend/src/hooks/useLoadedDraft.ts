import { useCallback, useEffect, useRef, useState } from "react";

type DraftState<T> = { draft: T; baseline: T | null; loading: boolean; epoch: number; commits: number };

export type LoadedDraft<T> = DraftState<T> & {
    /** True once loaded and the draft differs from the last loaded or saved value. */
    dirty: boolean;
    /** Bumps whenever the draft is loaded, reloaded or reset (not on edits or saves). */
    epoch: number;
    /** `epoch` plus every save: bumps whenever the draft is replaced by a known value. */
    generation: number;
    setDraft: (draft: T) => void;
    /**
     * Adopt a saved value as the baseline, and as the draft unless the draft
     * was edited after `sent` went out (those edits stay, as unsaved changes).
     * Returns false when such newer edits were kept.
     */
    commit: (saved: T, sent: T) => boolean;
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
    const [state, setState] = useState<DraftState<T>>({ draft: empty, baseline: null, loading: false, epoch: 0, commits: 0 });
    const loadRef = useRef(load);
    const emptyRef = useRef(empty);
    const onErrorRef = useRef(onError);
    const equalRef = useRef(equal);
    const loadIdRef = useRef(0);
    const stateRef = useRef(state);
    stateRef.current = state;
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
            setState(prev => ({ ...prev, draft: emptyRef.current, baseline: null, loading: false, epoch: prev.epoch + 1 }));
            return;
        }
        // A reload of the same item keeps showing it; a new item starts blank.
        setState(prev => keyChanged
            ? { ...prev, draft: emptyRef.current, baseline: null, loading: true, epoch: prev.epoch + 1 }
            : { ...prev, loading: true });
        loadRef.current().then(value => {
            if (loadId === loadIdRef.current) {
                setState(prev => ({ ...prev, draft: value, baseline: value, loading: false, epoch: prev.epoch + 1 }));
            }
        }).catch((e: unknown) => {
            if (loadId !== loadIdRef.current) return;
            setState(prev => ({ ...prev, draft: emptyRef.current, baseline: null, loading: false, epoch: prev.epoch + 1 }));
            onErrorRef.current(e instanceof Error && e.message ? e.message : "Failed to load context.");
        });
    }, [key]);

    useEffect(() => {
        reload();
    }, [reload]);
    // Responses arriving after unmount are ignored.
    useEffect(() => () => { loadIdRef.current += 1; }, []);

    const setDraft = useCallback((draft: T) => {
        stateRef.current = { ...stateRef.current, draft };
        setState(prev => ({ ...prev, draft }));
    }, []);
    const commit = useCallback((saved: T, sent: T) => {
        const unchanged = equalRef.current(stateRef.current.draft, sent);
        setState(prev => (
            !equalRef.current(prev.draft, sent)
                ? { ...prev, baseline: saved }
                : { ...prev, draft: saved, baseline: saved, commits: prev.commits + 1 }
        ));
        return unchanged;
    }, []);
    const reset = useCallback(() => setState(prev => (
        prev.baseline === null ? prev : { ...prev, draft: prev.baseline, epoch: prev.epoch + 1 }
    )), []);

    const dirty = state.baseline !== null && !equal(state.draft, state.baseline);
    return { ...state, generation: state.epoch + state.commits, dirty, setDraft, commit, reset, reload };
}
