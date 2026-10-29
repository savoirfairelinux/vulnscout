import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { BADGE_PROJECT, BUTTON_PRIMARY, ERROR, LABEL, PANEL, TEXTAREA } from "./styles";

type Props = {
    projectName: string;
    value: string;
    onChange: (value: string) => void;
    onSave: () => void;
    saving: boolean;
    dirty: boolean;
    error: string;
};

function ProjectDescriptionPanel({ projectName, value, onChange, onSave, saving, dirty, error }: Readonly<Props>) {
    return (
        <section aria-labelledby="ai-project-heading" className={`${PANEL} space-y-3`}>
            <div className="flex flex-wrap items-center gap-3">
                <h2 id="ai-project-heading" className="text-xl font-bold text-white">{projectName}</h2>
                <span className={BADGE_PROJECT}>Project</span>
                <button
                    type="button"
                    onClick={onSave}
                    disabled={!dirty || saving}
                    className={`${BUTTON_PRIMARY} ml-auto`}
                >
                    {saving && <FontAwesomeIcon icon={faSpinner} spin />}
                    Save changes
                </button>
            </div>
            <div>
                <label className={LABEL} htmlFor="ai-project-description">Project description</label>
                <textarea
                    id="ai-project-description"
                    className={`${TEXTAREA} min-h-[160px]`}
                    value={value}
                    onChange={e => onChange(e.target.value)}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={error ? "ai-project-description-error" : undefined}
                    placeholder="Describe your project..."
                />
                {error && <p id="ai-project-description-error" className={`${ERROR} mt-1`}>{error}</p>}
            </div>
        </section>
    );
}

export default ProjectDescriptionPanel;
