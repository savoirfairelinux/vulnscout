import { useSyncExternalStore } from 'react';
import { getAgentQueue, subscribeAgentQueue } from '../handlers/agentQueue';

export default function useAgentQueue() {
    return useSyncExternalStore(subscribeAgentQueue, getAgentQueue);
}
