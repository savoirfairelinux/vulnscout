import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faShieldHalved, faFileExport, faClockRotateLeft, faClipboardCheck, faGear, faRobot, faArrowsRotate, faCheck } from '@fortawesome/free-solid-svg-icons';
import ProjectVariantSelector from './ProjectVariantSelector';
import type { FrontendScope } from '../handlers/config';
import VersionDisplay from './VersionDisplay';

const greenTheme = true;
const bgColor = greenTheme ? 'bg-cyan-800 text-neutral-50' : 'dark:bg-neutral-900 dark:text-neutral-50';
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Props = {
  tab: string;
  changeTab: (tab: string) => void;
  defaultProject?: { id: string; name: string } | null;
  defaultVariant?: { id: string; name: string } | null;
  defaultScope?: FrontendScope | null;
  onApply: (projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => void;
  trackedScanCount?: number;
  finishedScanCount?: number;
  activeScanCount?: number;
  onOpenOperationQueue?: () => void;
};

function NavigationBar({ tab, changeTab, defaultProject, defaultVariant, defaultScope, onApply, trackedScanCount = 0, finishedScanCount = 0, activeScanCount = 0, onOpenOperationQueue }: Readonly<Props>) {
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
          <span className="flex flex-col items-start gap-0.5">
            <span>VulnScout</span>
            <span className="self-start">
              <VersionDisplay inline showName={false} />
            </span>
          </span>
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

      {/* Spacer */}
      <li className="grow"></li>

      {trackedScanCount > 0 && (
        <li className="flex items-stretch">
          <button
            type="button"
            onClick={onOpenOperationQueue}
            title={activeScanCount > 0 ? `${activeScanCount} operation${activeScanCount === 1 ? '' : 's'} in progress` : 'Open operation queue'}
            aria-label={`Open operation queue, ${finishedScanCount} of ${trackedScanCount} finished`}
            className={`flex h-full items-center px-4 py-2 transition-colors ${bgHoverColor}`}
          >
            <FontAwesomeIcon icon={activeScanCount > 0 ? faArrowsRotate : faCheck} className={`mr-2 ${activeScanCount > 0 ? 'animate-spin text-cyan-200' : 'text-green-300'}`} />
            <span className="flex flex-col items-start leading-tight">
              <span className="text-sm font-bold">Operation queue</span>
              <span className="text-xs font-normal tabular-nums opacity-75">{finishedScanCount} / {trackedScanCount} finished</span>
            </span>
          </button>
        </li>
      )}

      {/* === Project / Variant Selector === */}
      <li className="flex items-stretch">
        <ProjectVariantSelector
          defaultProject={defaultProject}
          defaultVariant={defaultVariant}
          defaultScope={defaultScope}
          onApply={onApply}
        />
      </li>

      {/* === Settings === */}
      <li className={[bgHoverColor, tab == 'settings' && bgActiveColor].join(' ')}>
        <button
          type="button"
          onClick={() => changeTab('settings')}
          className="flex items-center h-full px-4 py-2"
          aria-label="Settings"
          aria-current={tab === 'settings' ? 'page' : undefined}
        >
          <FontAwesomeIcon icon={faGear} />
        </button>
      </li>

    </ul>
  </nav>
  );
}

export default NavigationBar;
