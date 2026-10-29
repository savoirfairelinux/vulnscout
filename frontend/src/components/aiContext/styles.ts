// Shared Tailwind classes for the AI Context page (VulnScout dark theme).

export const FIELD =
    "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
export const TEXTAREA = `${FIELD} resize-y min-h-[80px]`;
export const LABEL = "block text-sm text-zinc-300 mb-1";
export const HELP = "text-xs text-zinc-400";
export const WARNING = "text-xs text-amber-300";
export const ERROR = "text-xs text-red-400";

const BUTTON_BASE =
    "px-3 py-1.5 rounded text-sm font-semibold flex items-center gap-1.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
export const BUTTON_PRIMARY = `${BUTTON_BASE} bg-cyan-800 hover:bg-cyan-700 text-white`;
export const BUTTON_SECONDARY = `${BUTTON_BASE} border border-slate-500 text-cyan-300 hover:bg-slate-700`;
// Same look as the Import/Export buttons on the Review page.
export const BUTTON_TRANSFER =
    "bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";

export const BADGE_BASE = "rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide";
export const BADGE_PROJECT = `${BADGE_BASE} bg-cyan-950 text-cyan-300`;
export const BADGE_VARIANT = `${BADGE_BASE} bg-violet-950 text-violet-300`;

export const PANEL = "rounded-lg bg-slate-800 border border-slate-700 p-4";
