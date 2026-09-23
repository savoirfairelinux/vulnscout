import { NavLink } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faShieldHalved, faFileExport, faClockRotateLeft, faClipboardCheck, faGear, faRobot, faArrowsRotate, faCheck } from '@fortawesome/free-solid-svg-icons';
import ProjectVariantSelector from './ProjectVariantSelector';
import type { FrontendScope } from '../handlers/config';
import { ROUTES } from '../routes';
import VersionDisplay from './VersionDisplay';

const greenTheme = true;
const bgColor = greenTheme ? 'bg-cyan-800 text-neutral-50' : 'dark:bg-neutral-900 dark:text-neutral-50';
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Props = {
  defaultProject?: { id: string; name: string } | null;
  defaultVariant?: { id: string; name: string } | null;
  defaultScope?: FrontendScope | null;
  onApply: (projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => void;
  trackedScanCount?: number;
  finishedScanCount?: number;
  activeScanCount?: number;
  onOpenOperationQueue?: () => void;
};

function navLiClass({ isActive }: { isActive: boolean }) {
  return [bgHoverColor, isActive && bgActiveColor].join(' ');
}

function NavigationBar({ defaultProject, defaultVariant, defaultScope, onApply, trackedScanCount = 0, finishedScanCount = 0, activeScanCount = 0, onOpenOperationQueue }: Readonly<Props>) {
  return (
  <nav aria-label="Main navigation">
    <ul className={["flex flex-row font-bold items-stretch", bgColor].join(' ')}>
      {/* === VulnScout (Logo + text) === */}
      <li>
        <NavLink
          to={ROUTES.metrics}
          end
          className={navLiClass}
          style={{ display: 'flex' }}
        >
          {({ isActive }) => (
            <span
              className="flex items-center h-full px-4 py-2"
              aria-current={isActive ? 'page' : undefined}
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
            </span>
          )}
        </NavLink>
      </li>

      {/* === SBOM === */}
      <li>
        <NavLink to={ROUTES.packages} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faBox} className="mr-1" />
              SBOM
            </span>
          )}
        </NavLink>
      </li>

      {/* === Vulnerabilities === */}
      <li>
        <NavLink to={ROUTES.vulnerabilities} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faShieldHalved} className="mr-1" />
              Vulnerabilities
            </span>
          )}
        </NavLink>
      </li>

      {/* === Scans === */}
      <li>
        <NavLink to={ROUTES.scans} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faClockRotateLeft} className="mr-1" />
              Scans
            </span>
          )}
        </NavLink>
      </li>

      {/* === Review === */}
      <li>
        <NavLink to={ROUTES.review} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faClipboardCheck} className="mr-1" />
              Review
            </span>
          )}
        </NavLink>
      </li>

      {/* === AI Context === */}
      <li>
        <NavLink to={ROUTES.ai} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faRobot} className="mr-1" />
              AI
            </span>
          )}
        </NavLink>
      </li>

      {/* === Export === */}
      <li>
        <NavLink to={ROUTES.exports} className={navLiClass} style={{ display: 'flex', height: '100%' }}>
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faFileExport} className="mr-1" />
              Export
            </span>
          )}
        </NavLink>
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
      <li>
        <NavLink to={ROUTES.settings} className={navLiClass} style={{ display: 'flex', height: '100%' }} aria-label="Settings">
          {({ isActive }) => (
            <span className="flex items-center h-full px-4 py-2" aria-current={isActive ? 'page' : undefined}>
              <FontAwesomeIcon icon={faGear} />
            </span>
          )}
        </NavLink>
      </li>

    </ul>
  </nav>
  );
}

export default NavigationBar;
