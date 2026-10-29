import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleNotch, faHourglassHalf, faTriangleExclamation, faWandMagicSparkles, type IconDefinition } from '@fortawesome/free-solid-svg-icons';
import { openAgentChat } from '../handlers/agentQueue';
import type { AgentActionState } from '../types/agent';

type Props = {
    /** Where the action stands in the AI queue; once queued, the button opens it in the agent chat. */
    state?: AgentActionState;
    label: string;
    /** Accessible name of the action; defaults to the label. */
    name?: string;
    onRun: () => void;
    disabled?: boolean;
    title?: string;
    preparing?: string;
    icon?: IconDefinition;
    className?: string;
    iconClassName?: string;
    openView?: 'chat' | 'conversations';
};

const stateText = (state: AgentActionState) => state.status === 'queued' ? `queued, position ${state.position}` : state.status;

/** One look and behaviour for every AI action button: idle, preparing, queued, running or failed. */
export default function AgentActionButton({
    state, label, name = label, onRun, disabled = false, title, preparing, icon = faWandMagicSparkles, className = '', iconClassName = '', openView = 'chat',
}: Readonly<Props>) {
    const content = preparing ? <><FontAwesomeIcon icon={faCircleNotch} spin className={iconClassName} />{preparing}</>
        : state?.status === 'running' ? <><FontAwesomeIcon icon={faCircleNotch} spin className={iconClassName} />{label}<span className="text-xs font-normal">Running…</span></>
        : state?.status === 'failed' ? <><FontAwesomeIcon icon={faTriangleExclamation} className={iconClassName} />{label}<span className="text-xs font-normal">Failed · view</span></>
        : state?.status === 'queued' ? <><FontAwesomeIcon icon={faHourglassHalf} className={iconClassName} />{label}<span className="text-xs font-normal">Queued · #{state.position}</span></>
        : <><FontAwesomeIcon icon={icon} className={iconClassName} />{label}</>;
    const hint = state?.status === 'running' ? 'Running in the agent chat. Click to follow the conversation.'
        : state?.status === 'failed' ? 'Failed. Click to retry or remove it in the agent chat.'
        : state?.status === 'queued' ? `Waiting in the AI queue (#${state.position}). Click to see it.`
        : title;
    return <button
        type="button"
        onClick={() => state ? openAgentChat(openView === 'chat' ? state.taskId : undefined, openView) : onRun()}
        disabled={Boolean(preparing) || (!state && disabled)}
        aria-busy={Boolean(preparing) || state?.status === 'running'}
        aria-label={preparing ? `${name} (preparing)` : state ? `${name} (${stateText(state)})` : name}
        title={hint}
        data-ai-state={preparing ? 'preparing' : state?.status ?? 'idle'}
        className={`${className} ${state?.status === 'failed' ? '!border-amber-500 !text-amber-300' : ''}`.trim()}
    >{content}</button>;
}
