import { createPortal } from 'react-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTriangleExclamation, faBan, faCircleInfo } from '@fortawesome/free-solid-svg-icons';

type Notification = {
    level: 'warning' | 'error' | 'info';
    title: string;
    message: string;
    action?: string;
};

type Props = {
    notification: Notification;
};

const LEVEL_ACCENT: Record<string, { border: string; label: string; icon: string; iconColor: string }> = {
    warning: { border: 'border-yellow-500', label: 'text-yellow-400', icon: 'warning', iconColor: 'text-yellow-400' },
    error:   { border: 'border-red-500',    label: 'text-red-400',    icon: 'error',   iconColor: 'text-red-400'    },
    info:    { border: 'border-cyan-500',   label: 'text-cyan-300',   icon: 'info',    iconColor: 'text-cyan-300'   },
};

const LEVEL_FA_ICON = {
    warning: faTriangleExclamation,
    error:   faBan,
    info:    faCircleInfo,
};

function NotificationModal({ notification }: Readonly<Props>) {
    const accent = LEVEL_ACCENT[notification.level] ?? LEVEL_ACCENT.info;
    const faIcon = LEVEL_FA_ICON[notification.level] ?? LEVEL_FA_ICON.info;

    return createPortal(
        <div className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className={`w-full max-w-lg rounded-lg border ${accent.border} bg-cyan-900 text-neutral-50 shadow-xl p-6`}>

                <p className={`text-xs font-semibold uppercase tracking-wide mb-3 ${accent.label}`}>
                    {notification.level}
                </p>

                <div className="flex items-start gap-3 mb-4">
                    <FontAwesomeIcon icon={faIcon} className={`mt-0.5 text-xl shrink-0 ${accent.iconColor}`} />
                    <h2 className="text-base font-semibold leading-snug">{notification.title}</h2>
                </div>

                <p className="text-sm text-cyan-100 mb-3 leading-relaxed">{notification.message}</p>

                {notification.action && (
                    <p className="text-xs font-mono bg-black/40 border border-cyan-700 rounded px-3 py-2 text-cyan-200 break-all">
                        {notification.action}
                    </p>
                )}
            </div>
        </div>,
        document.body
    );
}

export default NotificationModal;
export type { Notification };
