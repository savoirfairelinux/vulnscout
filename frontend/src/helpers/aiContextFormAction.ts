import type { AgentContext } from '../types/agent';

const TAB_LABELS: Record<string, string> = {
    context: 'Context', system: 'System', threat_model: 'Threat model', risks: 'Risks',
};
const INSTRUCTIONS = 'Use get_ai_context_form_guide and the saved context, ask me for anything missing, '
    + 'and give copy-ready values for each field. Do not save anything.';

/** Chat shortcut asking the agent to help fill the AI Context form tab that is open, if any. */
export function aiContextFormAction(context: AgentContext): { label: string; message: string } | null {
    if (context.page !== 'ai') return null;
    const view = context.view ?? {};
    const project = view.selectedProjectName ? ` for project "${view.selectedProjectName}"` : '';
    if (view.section === 'project_description') {
        return {
            label: 'Help write project description',
            message: `Help me write the Project description in the AI Context form${project}. ${INSTRUCTIONS}`,
        };
    }
    const tab = view.section ? TAB_LABELS[view.section] : undefined;
    if (!tab || !view.selectedVariantName) return null;
    const ofProject = view.selectedProjectName ? ` of project "${view.selectedProjectName}"` : '';
    return {
        label: 'Help fill this tab',
        message: `Help me fill the ${tab} tab of the AI Context form for variant "${view.selectedVariantName}"${ofProject}. ${INSTRUCTIONS}`,
    };
}
