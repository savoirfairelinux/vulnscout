import { useSyncExternalStore } from 'react';
import { getAgentQueue, subscribeAgentQueue } from '../handlers/agentQueue';

export default function useAgentQueue(threadId?: string) {
    const tasks = useSyncExternalStore(subscribeAgentQueue, getAgentQueue);
    return tasks.filter(task => task.threadId === threadId);
}
