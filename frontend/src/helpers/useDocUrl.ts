import { useState, useEffect } from "react";

const DOC_BASE = "https://vulnscout.readthedocs.io/en";

let cachedVersion: string | null = null;

/**
 * Returns the full ReadTheDocs URL for the given documentation path,
 * using the current container version instead of "latest".
 *
 * @param path - Path after the version slug, e.g. `"interactive-mode.html#scan-history"`
 */
export function useDocUrl(path: string): string {
  const [version, setVersion] = useState<string>(cachedVersion || "latest");

  useEffect(() => {
    if (cachedVersion) return;
    fetch(import.meta.env.VITE_API_URL + "/api/version", { mode: "cors" })
      .then((res) => res.json())
      .then((data) => {
        if (data?.version && data.version !== "unknown") {
          cachedVersion = data.version;
          setVersion(data.version);
        }
      })
      .catch(() => {});
  }, []);

  return `${DOC_BASE}/${version}/${path}`;
}
