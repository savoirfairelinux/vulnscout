import { Dispatch, SetStateAction, useEffect, useState } from 'react';

function readStoredValue<T>(key: string | null, initialValue: T): T {
    if (key === null) return initialValue;
    try {
        const storedValue = window.localStorage.getItem(key);
        return storedValue === null ? initialValue : JSON.parse(storedValue) as T;
    } catch {
        return initialValue;
    }
}


export function useLocalStorageState<T>(key: string | null, initialValue: T): [T, Dispatch<SetStateAction<T>>] {
    const [value, setValue] = useState<T>(() => readStoredValue(key, initialValue));

    useEffect(() => {
        if (key === null) return;
        try {
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch {
            // Storage can be unavailable or full; keep the in-memory state usable.
        }
    }, [key, value]);

    return [value, setValue];
}