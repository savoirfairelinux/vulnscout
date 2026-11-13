import type { AiDraftConflict } from "../../handlers/context";
import { BUTTON_SECONDARY } from "./styles";

export type AiDraftNoticeState =
    | { kind: 'drafting'; fileName: string; onCancel?: () => void }
    | { kind: 'loaded'; source: string; summary: string; rebased: boolean; renumbered: Record<string, string> }
    | { kind: 'pending'; source: string }
    | { kind: 'conflict'; source: string; conflicts: AiDraftConflict[] };

const MAX_CONFLICTS = 10;
const BOX = "flex flex-wrap items-start gap-3 rounded border px-3 py-2 text-sm";
const INFO = `${BOX} border-cyan-700 bg-cyan-950/40 text-cyan-100`;
const WARN = `${BOX} border-amber-500/60 bg-amber-950/40 text-amber-100`;

/** Where the variant's AI draft stands: being drafted, loaded for review, waiting, or in conflict. */
export default function AiDraftNotice({ notice, onDiscard, busy }: Readonly<{
    notice: AiDraftNoticeState; onDiscard: () => void; busy: boolean;
}>) {
    if (notice.kind === 'drafting') {
        return (
            <div role="status" className={INFO}>
                <p className="flex-1">AI is drafting from {notice.fileName}… Editing is paused until the draft is ready.</p>
                {notice.onCancel && <button type="button" className={BUTTON_SECONDARY} onClick={notice.onCancel}>Cancel</button>}
            </div>
        );
    }
    const discard = <button type="button" className={BUTTON_SECONDARY} onClick={onDiscard} disabled={busy}>Discard AI draft</button>;
    if (notice.kind === 'pending') {
        return (
            <div role="status" className={WARN}>
                <p className="flex-1">The agent prepared a draft from {notice.source}. Save or discard your edits to review it.</p>
                {discard}
            </div>
        );
    }
    if (notice.kind === 'conflict') {
        const hidden = notice.conflicts.length - MAX_CONFLICTS;
        return (
            <div role="alert" className={WARN}>
                <div className="flex-1 space-y-1">
                    <p>The AI draft from {notice.source} conflicts with changes saved since it was made, so it was not loaded.</p>
                    <ul className="list-disc pl-5">
                        {notice.conflicts.slice(0, MAX_CONFLICTS).map((c, i) => <li key={`${c.path}-${i}`}>{c.path}: {c.reason}</li>)}
                    </ul>
                    {hidden > 0 && <p>…and {hidden} more.</p>}
                </div>
                {discard}
            </div>
        );
    }
    const renumbered = Object.entries(notice.renumbered).map(([from, to]) => `${from} → ${to}`).join(', ');
    return (
        <div role="status" className={INFO}>
            <div className="flex-1 space-y-1">
                <p>Unsaved AI draft from {notice.source}: {notice.summary}. Review every tab, then Save changes to accept or Discard AI draft to reject.</p>
                {notice.rebased && (
                    <p className="text-xs">
                        The context was saved after the draft was made; the draft was merged onto it{renumbered ? ` and renumbered ${renumbered}` : ''}.
                    </p>
                )}
            </div>
            {discard}
        </div>
    );
}
