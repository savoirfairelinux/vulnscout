import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faShieldHalved, faFileExport, faBinoculars, faMoon, faSun, faBugSlash } from '@fortawesome/free-solid-svg-icons';

const greenTheme = true;
const bgColor = greenTheme ? 'bg-green-800 text-neutral-50' : 'dark:bg-neutral-900 dark:text-neutral-50';
const bgHoverColor = greenTheme ? 'hover:bg-green-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-green-900' : 'dark:bg-neutral-800';

type Props = {
  tab: string;
  changeTab: (tab: string) => void;
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
};

function NavigationBar({ tab, changeTab, darkMode, setDarkMode }: Readonly<Props>) {
  return (
    <nav>
      <ul className={["flex flex-row font-bold items-center", bgColor].join(' ')}>
        <li className={["px-4 py-2 mr-4 text-lg cursor-pointer", bgHoverColor].join(' ')} onClick={() => changeTab('metrics')}>
            <FontAwesomeIcon icon={faBinoculars} className='mr-1 fa-rotate-180' size='xl' />
            VulnScout
        </li>
        <li className={["px-4 py-2", bgHoverColor, tab == 'packages' && bgActiveColor].join(' ')}>
          <button onClick={() => changeTab('packages')}>
            <FontAwesomeIcon icon={faBox} className='mr-1' />
            Packages
          </button>
        </li>
        <li className={["px-4 py-2", bgHoverColor, tab == 'vulnerabilities' && bgActiveColor].join(' ')}>
          <button onClick={() => changeTab('vulnerabilities')}>
            <FontAwesomeIcon icon={faShieldHalved} className='mr-1' />
            Vulnerabilities
          </button>
        </li>
        <li className={["px-4 py-2", bgHoverColor, tab == 'patch-finder' && bgActiveColor].join(' ')}>
          <button onClick={() => changeTab('patch-finder')}>
            <FontAwesomeIcon icon={faBugSlash} className='mr-1' />
            Patch-Finder
          </button>
        </li>

        <li className="mx-3 border-l h-8 dark:border-neutral-300"></li>

        <li className={["px-4 py-2", bgHoverColor, tab == 'exports' && bgActiveColor].join(' ')}>
          <button onClick={() => changeTab('exports')}>
            <FontAwesomeIcon icon={faFileExport} className='mr-1' />
            Export
          </button>
        </li>

        <li className='grow'></li>

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
