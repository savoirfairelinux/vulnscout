import type { ModeledRiskLink } from "../handlers/assessments";

export default function ModeledRiskLinks({ links }: Readonly<{ links?: ModeledRiskLink[] }>) {
    if (!links?.length) return <span>No modeled risk linked</span>;
    return <ul>{links.map(link => <li key={`${link.risk_id}/${link.threat_id ?? ''}`}>
        {link.risk_id}{link.risk_description && ` — ${link.risk_description}`}
        {link.threat_id && `; ${link.threat_id}${link.threat_description ? ` — ${link.threat_description}` : ''}`}
        {link.threat_id && `; saved targets: ${link.threat_target_ids ? link.threat_target_ids.join(', ') || 'none' : 'not recorded'}`}
        {link.stale && <strong className="text-amber-400"> (stale reference)</strong>}
    </li>)}</ul>;
}
