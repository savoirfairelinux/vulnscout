import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faShieldHalved, faFileExport, faMoon, faSun, faClockRotateLeft, faClipboardCheck, faGear, faRightLeft, faRobot } from '@fortawesome/free-solid-svg-icons';
import ProjectVariantSelector from './ProjectVariantSelector';
import type { FrontendScope } from '../handlers/config';

const greenTheme = true;
const bgColor = greenTheme ? 'bg-cyan-800 text-neutral-50' : 'dark:bg-neutral-900 dark:text-neutral-50';
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Props = {
  tab: string;
  changeTab: (tab: string) => void;
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
  defaultProject?: { id: string; name: string } | null;
  defaultVariant?: { id: string; name: string } | null;
  defaultScope?: FrontendScope | null;
  onApply: (projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => void;
};

function NavigationBar({ tab, changeTab, darkMode, setDarkMode, defaultProject, defaultVariant, defaultScope, onApply }: Readonly<Props>) {
  return (
  <nav aria-label="Main navigation">
    <ul className={["flex flex-row font-bold items-stretch", bgColor].join(' ')}>
      {/* === VulnScout (Logo + text) === */}
      <li className={[bgHoverColor, tab == 'metrics' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('metrics')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'metrics' ? 'page' : undefined}
        >
          <img
            src="/vulnscout_logo.png"
            alt="VulnScout Logo"
            className="w-8 h-8 mr-2 align-middle"
          />
          VulnScout
        </button>
      </li>

      {/* === SBOM === */}
      <li className={[bgHoverColor, tab == 'packages' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('packages')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'packages' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faBox} className="mr-1" />
          SBOM
        </button>
      </li>

      {/* === Vulnerabilities === */}
      <li className={[bgHoverColor, tab == 'vulnerabilities' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('vulnerabilities')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'vulnerabilities' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faShieldHalved} className="mr-1" />
          Vulnerabilities
        </button>
      </li>

      {/* === Scans === */}
      <li className={[bgHoverColor, tab == 'scans' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('scans')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'scans' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faClockRotateLeft} className="mr-1" />
          Scans
        </button>
      </li>

      {/* === Review === */}
      <li className={[bgHoverColor, tab == 'review' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('review')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'review' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faClipboardCheck} className="mr-1" />
          Review
        </button>
      </li>

      {/* === Transfer === */}
      <li className={[bgHoverColor, tab == 'transfer' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('transfer')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'transfer' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faRightLeft} className="mr-1" />
          Transfer
        </button>
      </li>

      <li className={[bgHoverColor, tab == 'ai' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('ai')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'ai' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faRobot} className="mr-1" />
          AI
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
          aria-current={tab === 'exports' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faFileExport} className="mr-1" />
          Export
        </button>
      </li>

      {/* === Settings === */}
      <li className={[bgHoverColor, tab == 'settings' && bgActiveColor].join(' ')}>
        <button
          onClick={() => changeTab('settings')}
          className="flex items-center h-full px-4 py-2"
          aria-current={tab === 'settings' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faGear} className="mr-1" />
          Settings
        </button>
      </li>

      {/* Spacer */}
      <li className="grow"></li>

      {/* === Project / Variant Selector === */}
      <li className="flex items-stretch">
        <ProjectVariantSelector
          defaultProject={defaultProject}
          defaultVariant={defaultVariant}
          defaultScope={defaultScope}
          onApply={onApply}
        />
      </li>

      {/* === Divider === */}
      <li className="flex items-center mx-3">
        <div className="border-l h-8 dark:border-neutral-300"></div>
      </li>

      {/* === Dark Mode Toggle === */}
      <li className="px-4 py-2">
        <button
          type="button"
          onClick={() => setDarkMode(!darkMode)}
          aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
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
        </button>
      </li>
    </ul>
  </nav>
  );
}

export default NavigationBar;
