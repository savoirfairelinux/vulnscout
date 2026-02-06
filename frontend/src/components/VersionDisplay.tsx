import { useState, useEffect } from "react";

/**
 * A component that displays the VulnScout version in the bottom right corner
 * @constructor
 * @returns VersionDisplay A react component
 */
function VersionDisplay() {
  const [version, setVersion] = useState<string>('');

  useEffect(() => {
    fetch(import.meta.env.VITE_API_URL + "/api/version", {
      mode: 'cors'
    })
    .then(res => res.json())
    .then(data => {
      if (data?.version) {
        setVersion(data.version);
      }
    })
    .catch(error => {
      console.error('Error fetching version:', error);
    });
  }, []);

  if (!version) return null;

  return (
    <div className="fixed bottom-4 right-4 text-xs text-gray-400 dark:text-gray-500 font-mono select-none pointer-events-none z-10">
      VulnScout {version}
    </div>
  );
}

export default VersionDisplay;
