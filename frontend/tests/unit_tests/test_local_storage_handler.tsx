import { act, renderHook } from '@testing-library/react';
import { useLocalStorageState } from '../../src/handlers/localStorage';

describe('useLocalStorageState', () => {
    beforeEach(() => window.localStorage.clear());

    it('restores a stored value', () => {
        window.localStorage.setItem('test.preference', JSON.stringify(['saved']));

        const { result } = renderHook(() => useLocalStorageState('test.preference', [] as string[]));

        expect(result.current[0]).toEqual(['saved']);
    });

    it('persists direct and functional updates', () => {
        const { result } = renderHook(() => useLocalStorageState('test.preference', 1));

        act(() => result.current[1](2));
        expect(window.localStorage.getItem('test.preference')).toBe('2');

        act(() => result.current[1](value => value + 1));
        expect(window.localStorage.getItem('test.preference')).toBe('3');
    });

    it('uses the default when stored JSON is invalid', () => {
        window.localStorage.setItem('test.preference', '{invalid');

        const { result } = renderHook(() => useLocalStorageState('test.preference', 'default'));

        expect(result.current[0]).toBe('default');
    });
});
