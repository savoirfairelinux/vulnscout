import { act, renderHook } from '@testing-library/react';
import useAgentWriteRefresh from '../../src/hooks/useAgentWriteRefresh';
import { AGENT_WRITE_EVENT, type AgentWriteDetail } from '../../src/types/agent';

const announce = (detail?: unknown) => act(() => {
    window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail }));
});
const settle = () => act(async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); });

function deferred() {
    let resolve: () => void = () => undefined;
    let reject: (error: Error) => void = () => undefined;
    const promise = new Promise<void>((done, fail) => { resolve = done; reject = fail; });
    return { promise, resolve, reject };
}

test('runs the refresh with the tools of each announcement', () => {
    const refresh = jest.fn();
    renderHook(() => useAgentWriteRefresh(refresh));

    announce({ tool: 'write_assessment', tools: ['write_review', 'write_assessment'] });
    expect(refresh).toHaveBeenLastCalledWith({ tool: 'write_assessment', tools: ['write_review', 'write_assessment'] });
});

test('accepts a single-tool or empty announcement', async () => {
    const refresh = jest.fn();
    renderHook(() => useAgentWriteRefresh(refresh));

    announce({ tool: 'write_assessment' });
    expect(refresh).toHaveBeenLastCalledWith({ tool: 'write_assessment', tools: ['write_assessment'] });
    await settle();
    announce();
    expect(refresh).toHaveBeenLastCalledWith({ tool: undefined, tools: [] });
});

test('merges announcements arriving during a refresh into one rerun once it settles', async () => {
    const first = deferred();
    const second = deferred();
    const refresh = jest.fn<Promise<void>, [AgentWriteDetail]>()
        .mockReturnValueOnce(first.promise)
        .mockReturnValueOnce(second.promise);
    renderHook(() => useAgentWriteRefresh(refresh));

    announce({ tool: 'a', tools: ['a'] });
    announce({ tool: 'b', tools: ['b'] });
    announce({ tool: 'a', tools: ['a'] });
    announce({ tools: [] });
    expect(refresh).toHaveBeenCalledTimes(1);

    first.resolve();
    await settle();
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(refresh).toHaveBeenLastCalledWith({ tool: 'a', tools: ['b', 'a'] });

    // A failed refresh does not stop later announcements.
    announce({ tool: 'c', tools: ['c'] });
    second.reject(new Error('offline'));
    await settle();
    expect(refresh).toHaveBeenCalledTimes(3);
    expect(refresh).toHaveBeenLastCalledWith({ tool: 'c', tools: ['c'] });
});

test('uses the latest callback, survives a throwing one and stops listening on unmount', async () => {
    const first = jest.fn<unknown, [AgentWriteDetail]>(() => { throw new Error('boom'); });
    const second = jest.fn<unknown, [AgentWriteDetail]>();
    const { rerender, unmount } = renderHook(
        ({ refresh }: { refresh: (detail: AgentWriteDetail) => unknown }) => useAgentWriteRefresh(refresh),
        { initialProps: { refresh: first } },
    );

    announce({ tool: 'a', tools: ['a'] });
    expect(first).toHaveBeenCalledTimes(1);
    await settle();
    rerender({ refresh: second });
    announce({ tool: 'b', tools: ['b'] });
    expect(second).toHaveBeenCalledTimes(1);

    await settle();
    unmount();
    announce({ tool: 'c', tools: ['c'] });
    expect(second).toHaveBeenCalledTimes(1);
});

test('drops a queued rerun once unmounted', async () => {
    const running = deferred();
    const refresh = jest.fn(() => running.promise);
    const { unmount } = renderHook(() => useAgentWriteRefresh(refresh));

    announce({ tool: 'a', tools: ['a'] });
    announce({ tool: 'b', tools: ['b'] });
    unmount();
    running.resolve();
    await settle();
    expect(refresh).toHaveBeenCalledTimes(1);
});
