import { useState, useEffect } from "react";
import NavigationBar from "../components/NavigationBar";
import type { Package } from "../handlers/packages";
import Packages from "../handlers/packages";
import TablePackages from "./TablePackages";

type Props = {
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
}

function Explorer({ darkMode, setDarkMode }: Props) {
    const [pkgs, setPkgs] = useState<Package[]>([]);

    useEffect(() => {
        Promise.allSettled([
            Packages.list()
        ]).then(([pkgs]) => {
            if (pkgs.status === 'rejected') {
                console.error(pkgs);
                alert("Failed to load data");
                return;
            }
            setPkgs(pkgs.value);
        })
    }, []);

    const [tab, setTab] = useState("packages");

    return (
      <div className="w-screen min-h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee]">
        <NavigationBar tab={tab} changeTab={setTab} darkMode={darkMode} setDarkMode={setDarkMode} />

        <div className="p-8">
          {tab == 'packages' && <TablePackages packages={pkgs} />}
        </div>
      </div>
    )
}

export default Explorer
