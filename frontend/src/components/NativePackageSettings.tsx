import { useEffect, useState } from "react";
import Config from "../handlers/config";
import type { NativeScanPreferences } from "../handlers/project";

export default function NativePackageSettings() {
    const [configuration, setConfiguration] = useState<NativeScanPreferences | null>(null);
    const [names, setNames] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        const controller = new AbortController();
        Config.nativePackages(undefined, controller.signal).then(value => {
            if (controller.signal.aborted) return;
            setConfiguration(value);
            setNames(value.native_package_exceptions.join("\n"));
        }).catch((reason: unknown) => {
            if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Failed to load native-package settings.");
        });
        return () => controller.abort();
    }, []);

    async function save(event: React.FormEvent) {
        event.preventDefault();
        if (!configuration || busy) return;
        const exceptions = [...new Set(names.split(/[\n,]+/).map(name => name.trim().toLowerCase()).filter(Boolean))].sort();
        setError(null);
        setSaved(false);
        if (exceptions.length > 1000 || exceptions.some(name => name.length > 255 || !name.endsWith("-native"))) {
            setError("Enter up to 1000 package names ending in -native, each at most 255 characters.");
            return;
        }
        setBusy(true);
        try {
            const updated = await Config.nativePackages({ ...configuration, native_package_exceptions: exceptions });
            setConfiguration(updated);
            setNames(updated.native_package_exceptions.join("\n"));
            setSaved(true);
        } catch (reason: unknown) {
            setError(reason instanceof Error ? reason.message : "Failed to save native-package settings.");
        } finally {
            setBusy(false);
        }
    }

    return <section aria-labelledby="settings-heading-native" className="rounded-lg border border-slate-700 bg-slate-800 p-6">
        <h2 id="settings-heading-native" className="text-xl font-bold text-white">Global native-package exclusions</h2>
        <p className="mt-2 text-sm text-zinc-400">Default scan filters for projects without saved selections. Saved project selections override these defaults. Changes apply the next time the scan wizard opens.</p>
        {error && <p role="alert" className="mt-3 text-sm text-red-400">{error}</p>}
        {!configuration && !error && <p role="status" className="mt-3 text-sm text-zinc-400">Loading native-package settings...</p>}
        {configuration && <form onSubmit={save} className="mt-4 space-y-4">
            <label className="flex items-start gap-2 text-sm text-zinc-300">
                <input type="checkbox" checked={configuration.exclude_native} disabled={busy}
                    onChange={event => { setConfiguration({ ...configuration, exclude_native: event.target.checked }); setSaved(false); }}
                    className="mt-1 accent-cyan-500" />
                Exclude native packages by default
            </label>
            <div>
                <label htmlFor="global-native-exceptions" className="text-sm font-medium text-zinc-300">Native packages to scan by default</label>
                <p id="global-native-help" className="mt-1 text-xs text-zinc-400">Exceptions to native exclusion. Enter one package name per line, or separate names with commas. Names must end in -native. This list is retained when exclusion is disabled.</p>
                <textarea id="global-native-exceptions" aria-describedby="global-native-help" rows={5} value={names} disabled={busy}
                    onChange={event => { setNames(event.target.value); setSaved(false); }}
                    className="mt-2 w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none" />
            </div>
            <button type="submit" disabled={busy} className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">{busy ? "Saving..." : "Save native-package defaults"}</button>
            {saved && <p role="status" className="text-sm text-green-400">Global native-package defaults saved.</p>}
        </form>}
    </section>;
}
