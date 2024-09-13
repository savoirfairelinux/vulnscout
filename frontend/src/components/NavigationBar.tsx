import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChartLine, faBox, faShieldHalved, faMagnifyingGlass, faFileImport, faFileExport, faBinoculars, faMoon, faSun, faBugSlash } from '@fortawesome/free-solid-svg-icons';

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
        <li className={["px-4 py-2 mr-4 text-lg", bgHoverColor].join(' ')}>
            <FontAwesomeIcon icon={faBinoculars} className='mr-1 fa-rotate-180' size='xl' />
            VulnScout
        </li>

        <li className={["px-4 py-2", bgHoverColor, tab == 'metrics' && bgActiveColor].join(' ')}>
            <button onClick={() => changeTab('metrics')}>
                <FontAwesomeIcon icon={faChartLine} className='mr-1' />
                Dashboard
            </button>
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
        <li className={["px-4 py-2", bgHoverColor, tab == 'audit' && bgActiveColor].join(' ')}>
            <button onClick={() => changeTab('audit')}>
                <FontAwesomeIcon icon={faMagnifyingGlass} className='mr-1' />
                Audit
            </button>
        </li>
        <li className={["px-4 py-2", bgHoverColor, tab == 'patch-finder' && bgActiveColor].join(' ')}>
            <button onClick={() => changeTab('patch-finder')}>
                <FontAwesomeIcon icon={faBugSlash} className='mr-1' />
                Patch-Finder
            </button>
        </li>

        <li className="mx-3 border-l h-8 dark:border-neutral-300"></li>

        <li className={["px-4 py-2", bgHoverColor].join(' ')}>
            <button>
                <FontAwesomeIcon icon={faFileImport} className='mr-1' />
                Import
            </button>
        </li>
        <li className={["px-4 py-2", bgHoverColor, tab == 'exports' && bgActiveColor].join(' ')}>
            <button onClick={() => changeTab('exports')}>
                <FontAwesomeIcon icon={faFileExport} className='mr-1' />
                Export
            </button>
        </li>

        <li className='grow'></li>

        <li className={["px-4 py-2", bgHoverColor].join(' ')}>
            <button onClick={() => setDarkMode(!darkMode)}>
                {!darkMode && <FontAwesomeIcon icon={faMoon} />}
                {darkMode && <FontAwesomeIcon icon={faSun} />}
            </button>
        </li>
      </ul>
    </nav>
  );
}

export default NavigationBar;
