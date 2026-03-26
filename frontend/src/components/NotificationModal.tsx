import { createPortal } from 'react-dom';

type Notification = {
    level: 'warning' | 'error' | 'info';
    title: string;
    message: string;
    action?: string;
};

type Props = {
    notification: Notification;
};

const LEVEL_STYLES: Record<string, string> = {
    warning: 'border-yellow-500 bg-yellow-900/30',
    error:   'border-red-500 bg-red-900/30',
    info:    'border-blue-500 bg-blue-900/30',
};

const LEVEL_ICON: Record<string, string> = {
    warning: '⚠️',
    error:   '🚫',
    info:    'ℹ️',
};

function NotificationModal({ notification }: Readonly<Props>) {
    const borderStyle = LEVEL_STYLES[notification.level] ?? LEVEL_STYLES.info;
    const icon = LEVEL_ICON[notification.level] ?? LEVEL_ICON.info;

    return createPortal(
        <div className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/60">
            <div className={`w-full max-w-lg rounded-lg border-2 p-6 shadow-2xl text-white ${borderStyle}`}>
                <div className="flex items-start gap-3 mb-4">
                    <span className="text-2xl">{icon}</span>
                    <h2 className="text-lg font-semibold leading-tight">{notification.title}</h2>
                </div>
                <p className="text-sm text-gray-200 mb-3">{notification.message}</p>
                {notification.action && (
                    <p className="text-sm font-mono bg-black/40 rounded p-2 text-yellow-200">
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
