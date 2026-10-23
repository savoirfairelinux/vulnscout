import type { QueuedAgentMessage } from '../types/agent';
import type { AssessmentTargetPair } from '../handlers/assessments';
import type { Variant } from '../handlers/variant';
import type { Vulnerability } from '../handlers/vulnerabilities';
import { AGENT_MESSAGE_MAX_LENGTH, type AgentContext } from '../types/agent';

export const assessmentKey = (targets: AssessmentTargetPair[]) =>
    `assess:${targets.map(target => `${target.variant_id}|${target.package}`).sort().join(',')}`;

/** Keep each variant whole so its packages are assessed together. */
export function buildAiAssessmentMessages(
    vulnerabilityId: string,
    targets: AssessmentTargetPair[],
    variants: Variant[] = [],
): Omit<QueuedAgentMessage, 'id'>[] {
    if (!targets.length) throw new Error(`No active assessment targets for ${vulnerabilityId}.`);
    const variantName = (id?: string | null) => variants.find(variant => variant.id === id)?.name;
    const variantLabel = (id?: string | null) => {
        const name = variantName(id);
        return name ? `"${name}" (variant_id ${id})` : `variant_id ${id}`;
    };
    const groupMap = new Map<string, AssessmentTargetPair[]>();
    targets.forEach(target => {
        const id = target.variant_id ?? '';
        groupMap.set(id, [...(groupMap.get(id) ?? []), target]);
    });
    const groups = [...groupMap.values()];
    const lines = groups.map(group =>
        `- variant ${variantLabel(group[0].variant_id)}: ${group.map(target => target.package).join(', ')}`);
    const prompt = (batchLines: string[], batch = '') =>
        `Assess ${vulnerabilityId}${batch} for exactly these targets (packages listed per variant):\n${batchLines.join('\n')}\n` +
        `Retrieve the vulnerability details and each variant's merged context with VulnScout MCP first, ` +
        `then record the result with write_assessment for these targets only.`;
    const budget = AGENT_MESSAGE_MAX_LENGTH - ' (batch 9999 of 9999)'.length;
    const oversized = groups.filter((_, index) => prompt([lines[index]]).length > budget);
    if (oversized.length) {
        const names = oversized.map(group => variantName(group[0].variant_id) ?? group[0].variant_id).join(', ');
        throw new Error(`Too many packages selected for variant ${names} to assess with AI in one request. Select fewer packages for that variant.`);
    }
    const batches: number[][] = [];
    lines.forEach((line, index) => {
        const current = batches[batches.length - 1];
        if (current && prompt([...current.map(i => lines[i]), line]).length <= budget) current.push(index);
        else batches.push([index]);
    });
    return batches.map((indexes, index) => {
        const batchTargets = indexes.flatMap(i => groups[i]);
        const unique = (values: string[]) => [...new Set(values)].join(', ');
        const batchLabel = batches.length > 1 ? ` (batch ${index + 1} of ${batches.length})` : '';
        return {
            key: assessmentKey(targets), kind: 'assess',
            text: prompt(indexes.map(i => lines[i]), batchLabel),
            title: `${batchTargets.length} target${batchTargets.length === 1 ? '' : 's'}${batches.length > 1 ? ` · batch ${index + 1} of ${batches.length}` : ''}`,
            detail: `${unique(batchTargets.map(target => variantName(target.variant_id) ?? target.variant_id ?? ''))} · ${unique(batchTargets.map(target => target.package))}`,
        };
    });
}

/** Resolve real variant/package pairs, never a Cartesian product of table packages and variants. */
export async function loadAiAssessmentTargets(
    vulnerability: Vulnerability,
    scope: AgentContext,
    signal: AbortSignal,
): Promise<AssessmentTargetPair[]> {
    const url = new URL(
        import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnerability.id)}/variant-active-packages`,
        window.location.href,
    );
    if (scope.projectId) url.searchParams.set('project_id', scope.projectId);
    let response: Response;
    try {
        response = await fetch(url.toString(), { mode: 'cors', signal });
    } catch (error) {
        if (signal.aborted) throw error;
        throw new Error(`Unable to load targets for ${vulnerability.id}. Check the connection and try again.`);
    }
    if (!response.ok) throw new Error(`Unable to load targets for ${vulnerability.id} (HTTP ${response.status}). Try again.`);
    let data: unknown;
    try {
        data = await response.json();
    } catch {
        throw new Error(`Invalid target compatibility response for ${vulnerability.id}. Try again.`);
    }
    if (!Array.isArray(data)) throw new Error(`Invalid target compatibility response for ${vulnerability.id}. Try again.`);
    const variantIds = scope.variantId
        ? [scope.variantId, ...(scope.compareOperation === 'intersection' && scope.baseVariantId ? [scope.baseVariantId] : [])]
        : scope.variantIds;
    const packages = new Set(vulnerability.packages_current.length ? vulnerability.packages_current : vulnerability.packages);
    let basePackages: Set<string> | undefined;
    if (scope.compareOperation === 'intersection' && scope.variantId && scope.baseVariantId
        && scope.baseVariantId !== scope.variantId) {
        const baseUrl = new URL(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnerability.id)}`,
            window.location.href,
        );
        baseUrl.searchParams.set('variant_id', scope.baseVariantId);
        baseUrl.searchParams.set('agent_scoped', '1');
        try {
            const baseResponse = await fetch(baseUrl.toString(), { mode: 'cors', signal });
            if (!baseResponse.ok) throw new Error();
            const base = await baseResponse.json();
            const current = base?.packages_current_by_variant?.[scope.baseVariantId];
            if (base?.id !== vulnerability.id || !Array.isArray(current) || !current.length
                || !current.every((item: unknown) => typeof item === 'string')) throw new Error();
            basePackages = new Set(current);
        } catch (error) {
            if (signal.aborted) throw error;
            throw new Error(`Unable to load active base-variant targets for ${vulnerability.id}. Refresh the table and try again.`);
        }
    }
    const targets = new Map<string, AssessmentTargetPair>();
    for (const entry of data) {
        if (typeof entry?.variant_id !== 'string' || !Array.isArray(entry.findings)) {
            throw new Error(`Invalid target compatibility response for ${vulnerability.id}. Try again.`);
        }
        const variantId: string = entry.variant_id;
        if (variantIds?.length && !variantIds.includes(variantId)) continue;
        // The comparison table omits the base variant's packages. Its scoped
        // payload requires active CVE observations, not just an installed package.
        const comparisonBase = basePackages !== undefined && scope.baseVariantId === variantId;
        const currentPackages = vulnerability.packages_current_by_variant?.[variantId];
        for (const finding of entry.findings) {
            if (typeof finding?.package !== 'string' || typeof finding.outdated !== 'boolean') {
                throw new Error(`Invalid target compatibility response for ${vulnerability.id}. Try again.`);
            }
            if (finding.outdated) continue;
            if (comparisonBase && !basePackages?.has(finding.package)) continue;
            if (!comparisonBase && !packages.has(finding.package)) continue;
            if (!comparisonBase && vulnerability.packages_current_by_variant && !currentPackages?.includes(finding.package)) continue;
            targets.set(`${variantId}|${finding.package}`, { variant_id: variantId, package: finding.package });
        }
    }
    if (!targets.size) throw new Error(`No active assessment targets for ${vulnerability.id} in the selected scope. Refresh the table and try again.`);
    return [...targets.values()];
}
