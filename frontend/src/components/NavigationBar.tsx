import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faShieldHalved, faFileExport, faMoon, faSun, faBugSlash } from '@fortawesome/free-solid-svg-icons';

const greenTheme = true;
const bgColor = greenTheme ? 'bg-cyan-800 text-neutral-50' : 'dark:bg-neutral-900 dark:text-neutral-50';
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Props = {
  tab: string;
  changeTab: (tab: string) => void;
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
};

function NavigationBar({ tab, changeTab, darkMode, setDarkMode }: Readonly<Props>) {
  return (
  <nav>
    <ul className={["flex flex-row font-bold items-stretch", bgColor].join(' ')}>
      {/* === VulnScout (Logo + text) === */}
      <li className={[bgHoverColor, tab == 'metrics' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('metrics')}
          className="flex items-center h-full px-4 py-2"
        >
          <img
            src="/vulnscout_logo.png"
            alt="VulnScout Logo"
            className="w-8 h-8 mr-2 align-middle"
          />
          VulnScout
        </button>
      </li>

      {/* === Packages === */}
      <li className={[bgHoverColor, tab == 'packages' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('packages')}
          className="flex items-center h-full px-4 py-2"
        >
          <FontAwesomeIcon icon={faBox} className="mr-1" />
          Packages
        </button>
      </li>

      {/* === Vulnerabilities === */}
      <li className={[bgHoverColor, tab == 'vulnerabilities' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('vulnerabilities')}
          className="flex items-center h-full px-4 py-2"
        >
          <FontAwesomeIcon icon={faShieldHalved} className="mr-1" />
          Vulnerabilities
        </button>
      </li>

      {/* === Patch-Finder === */}
      <li className={[bgHoverColor, tab == 'patch-finder' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('patch-finder')}
          className="flex items-center h-full px-4 py-2"
        >
          <FontAwesomeIcon icon={faBugSlash} className="mr-1" />
          Patch-Finder
        </button>
      </li>

      {/* === Divider === */}
      <li className="flex items-center mx-3">
        <div className="border-l h-8 dark:border-neutral-300"></div>
      </li>

      {/* === Export === */}
      <li className={[bgHoverColor, tab == 'exports' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('exports')}
          className="flex items-center h-full px-4 py-2"
        >
          <FontAwesomeIcon icon={faFileExport} className="mr-1" />
          Export
        </button>
      </li>

      {/* Spacer */}
      <li className="grow"></li>

      {/* === Dark Mode Toggle === */}
      <li className="px-4 py-2">
        <div
          onClick={() => setDarkMode(!darkMode)}
          className="flex items-center w-14 h-7 bg-neutral-300 dark:bg-neutral-700 rounded-full px-1 cursor-pointer relative transition-all duration-300"
        >
          <FontAwesomeIcon icon={faSun} className="text-yellow-500 text-sm" />
          <div className="flex-1"></div>
          <FontAwesomeIcon icon={faMoon} className="text-blue-900 text-sm" />

          <div
            className={[
              "absolute top-[2px] left-[2px] w-6 h-6 rounded-full bg-white shadow-md transition-transform duration-300",
              darkMode ? "translate-x-7" : "translate-x-0"
            ].join(' ')}
          ></div>
        </div>
      </li>
    </ul>
  </nav>
  );
}

export default NavigationBar;
