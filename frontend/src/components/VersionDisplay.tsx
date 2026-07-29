import { useState, useEffect } from "react";

type Props = {
  inline?: boolean;
  showName?: boolean;
};

/**
 * A component that displays the VulnScout version.
 * @constructor
 * @returns VersionDisplay A react component
 */
function VersionDisplay({ inline = false, showName = true }: Readonly<Props>) {
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
    <div className={inline
      ? "text-[10px] font-mono font-normal leading-none text-cyan-200 select-none"
      : "fixed bottom-4 right-4 text-xs text-gray-400 dark:text-gray-500 font-mono select-none pointer-events-none z-10"
    }>
      {showName ? `VulnScout ${version}` : version}
    </div>
  );
}

export default VersionDisplay;
