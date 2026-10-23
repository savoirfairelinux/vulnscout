import type { AgentContext } from '../types/agent';

/** Human-readable scope of a queued AI request: page, project, variant(s) and vulnerabilities. */
export function agentScopeEntries(context: AgentContext): Array<[string, string]> {
    const view = context.view;
    const vulnerabilities = view?.openVulnerabilityId ? [view.openVulnerabilityId] : view?.selectedVulnerabilityIds ?? [];
    const variants = context.variantIds ?? view?.matchingVariantIds ?? [];
    return ([
        ['Page', context.page],
        ['Project', view?.selectedProjectName ?? context.projectId],
        ['Variant', view?.selectedVariantName ?? context.variantId],
        ['Variants', variants.length ? `${variants.length} variant${variants.length === 1 ? '' : 's'}` : undefined],
        ['Vulnerabilities', vulnerabilities.length ? vulnerabilities.join(', ') : undefined],
    ] as Array<[string, string | undefined]>).filter((entry): entry is [string, string] => Boolean(entry[1]));
}
