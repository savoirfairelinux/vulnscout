import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import type { Assessment } from "../handlers/assessments";
import { formatPkgId } from "../helpers/pkgId";

// An assessment is written per variant, so one row always belongs to exactly one
// variant and its package list. Both the vulnerability modal and the review table
// group several such rows behind a single visual entry, which makes a bare id
// ambiguous. This tag pins each id back to the variant and packages it covers.
type Props = {
    assessment: Pick<Assessment, 'id' | 'variant_id' | 'packages'>;
    variantName?: string;
    // Render the package list inline. Off by default so narrow table cells keep
    // the detail in the tooltip instead.
    showPackages?: boolean;
};

const SHORT_ID_LENGTH = 8;

function AssessmentIdTag({ assessment, variantName, showPackages = false }: Props) {
    const { id, variant_id, packages } = assessment;
    const variantLabel = variantName ?? (variant_id ? variant_id.slice(0, SHORT_ID_LENGTH) : '');
    const packagesLabel = (packages ?? []).map(formatPkgId).join(', ');

    const title = [
        `Assessment ${id}`,
        `Variant: ${variantLabel || '—'}`,
        `Packages: ${packagesLabel || '—'}`,
    ].join('\n');

    return (
        <span className="inline-flex items-center gap-1 text-xs" title={title}>
            <span className="font-mono">{id.slice(0, SHORT_ID_LENGTH)}</span>
            {variantLabel && <span className="opacity-80">· {variantLabel}</span>}
            {showPackages && packagesLabel && <span className="opacity-80">· {packagesLabel}</span>}
            <button
                type="button"
                title="Copy this assessment id"
                aria-label="Copy this assessment id"
                onClick={() => navigator.clipboard.writeText(id)}
                className="text-gray-400 hover:text-gray-200 transition-colors"
            >
                <FontAwesomeIcon icon={faCopy} className="w-3 h-3" />
            </button>
        </span>
    );
}

export default AssessmentIdTag;
