import { useEffect, useId } from "react";
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, MouseEvent, ReactNode, RefObject } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark } from "@fortawesome/free-solid-svg-icons";

type ModalSize = "compact" | "standard" | "large" | "wide" | "fullscreen";

const sizeClasses: Record<ModalSize, string> = {
    compact: "max-w-md",
    standard: "max-w-xl",
    large: "max-w-3xl",
    wide: "max-w-4xl",
    fullscreen: "h-[calc(100vh-2rem)] max-w-[calc(100vw-2rem)]",
};

type ModalButtonVariant = "primary" | "secondary" | "danger";

const buttonVariantClasses: Record<ModalButtonVariant, string> = {
    primary: "bg-cyan-700 text-white hover:bg-cyan-600",
    secondary: "border border-neutral-600 bg-neutral-800 text-neutral-200 hover:bg-neutral-700 hover:text-white",
    danger: "bg-red-700 text-white hover:bg-red-600",
};

export function ModalActions({ children, align = "end" }: Readonly<{ children: ReactNode; align?: "end" | "between" }>) {
    return <div className={`flex items-center gap-3 ${align === "between" ? "justify-between" : "justify-end"}`}>{children}</div>;
}

export function ModalButton({ variant = "secondary", className = "", type = "button", ...props }: Readonly<ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ModalButtonVariant }>) {
    return (
        <button
            {...props}
            type={type}
            className={`rounded-md px-4 py-2 text-sm font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-neutral-950 disabled:cursor-not-allowed disabled:opacity-50 ${buttonVariantClasses[variant]} ${className}`.trim()}
        />
    );
}

export function ModalLink({ variant = "primary", className = "", ...props }: Readonly<AnchorHTMLAttributes<HTMLAnchorElement> & { variant?: ModalButtonVariant }>) {
    return (
        <a
            {...props}
            className={`rounded-md px-4 py-2 text-center text-sm font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-neutral-950 ${buttonVariantClasses[variant]} ${className}`.trim()}
        />
    );
}

export type ModalHeaderProps = {
    title: ReactNode;
    titleId: string;
    onClose: () => void;
    children?: ReactNode;
    subtitle?: ReactNode;
    icon?: ReactNode;
    actions?: ReactNode;
    closeLabel?: string;
    showCloseButton?: boolean;
    closeDisabled?: boolean;
    className?: string;
};

export function ModalHeader({
    title,
    titleId,
    onClose,
    children,
    subtitle,
    icon,
    actions,
    closeLabel = "Close modal",
    showCloseButton = true,
    closeDisabled = false,
    className = "",
}: Readonly<ModalHeaderProps>) {
    return (
        <div className={`border-b border-neutral-700 bg-neutral-900 px-5 py-4 ${className}`.trim()}>
            <div className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                    <div className="flex items-center gap-2">
                        {icon}
                        <h2 id={titleId} className="text-lg font-semibold text-white">{title}</h2>
                    </div>
                    {subtitle && <div className="mt-1 text-sm text-neutral-400">{subtitle}</div>}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                    {actions}
                    {showCloseButton && <button
                        type="button"
                        onClick={onClose}
                        disabled={closeDisabled}
                        aria-label={closeLabel}
                        className="inline-flex h-8 w-8 items-center justify-center rounded-md text-sm text-neutral-400 transition-colors hover:bg-neutral-700 hover:text-white disabled:cursor-not-allowed disabled:text-neutral-600"
                    >
                        <FontAwesomeIcon icon={faXmark} aria-hidden="true" role="presentation" />
                    </button>}
                </div>
            </div>
            {children}
        </div>
    );
}

export type ModalShellProps = {
    isOpen: boolean;
    title: ReactNode;
    children: ReactNode;
    onClose: () => void;
    subtitle?: ReactNode;
    icon?: ReactNode;
    headerActions?: ReactNode;
    headerContent?: ReactNode;
    footer?: ReactNode;
    size?: ModalSize;
    closeLabel?: string;
    showCloseButton?: boolean;
    closeDisabled?: boolean;
    closeOnEscape?: boolean;
    closeOnBackdrop?: boolean;
    closeOnPanel?: boolean;
    embedded?: boolean;
    testId?: string;
    titleId?: string;
    descriptionId?: string;
    contentClassName?: string;
    panelRef?: RefObject<HTMLDivElement>;
    panelTabIndex?: number;
};

export default function ModalShell({
    isOpen,
    title,
    children,
    onClose,
    subtitle,
    icon,
    headerActions,
    headerContent,
    footer,
    size = "standard",
    closeLabel = "Close modal",
    showCloseButton = true,
    closeDisabled = false,
    closeOnEscape = true,
    closeOnBackdrop = true,
    closeOnPanel = false,
    embedded = false,
    testId = "modal-backdrop",
    titleId,
    descriptionId,
    contentClassName = "",
    panelRef,
    panelTabIndex,
}: Readonly<ModalShellProps>) {
    const generatedTitleId = useId();
    const resolvedTitleId = titleId ?? generatedTitleId;

    useEffect(() => {
        if (!isOpen || !closeOnEscape || embedded) return;

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === "Escape") onClose();
        };

        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, [closeOnEscape, embedded, isOpen, onClose]);

    if (!isOpen) return null;

    const handleBackdropMouseDown = (event: MouseEvent<HTMLDivElement>) => {
        if (closeOnBackdrop && event.target === event.currentTarget) onClose();
    };

    return (
        <div
            data-testid={testId}
            tabIndex={-1}
            className={embedded ? "w-full" : "fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4"}
            onMouseDown={handleBackdropMouseDown}
        >
            <div
                ref={panelRef}
                tabIndex={panelTabIndex}
                role={embedded ? "region" : "dialog"}
                aria-modal={embedded ? undefined : true}
                aria-labelledby={resolvedTitleId}
                aria-describedby={descriptionId}
                onMouseDown={event => {
                    if (closeOnPanel && event.target === event.currentTarget) onClose();
                }}
                className={`relative flex max-h-[calc(100vh-2rem)] w-full flex-col overflow-hidden rounded-lg border border-neutral-700 bg-neutral-900 text-neutral-100 shadow-2xl outline-none ${sizeClasses[size]} ${embedded ? "max-w-none [&_.text-xs]:!text-base [&_.text-sm]:!text-lg [&_h3]:!text-2xl [&_h4]:!text-xl [&_input]:h-5 [&_input]:w-5" : ""}`.trim()}
            >
                <ModalHeader
                    title={title}
                    titleId={resolvedTitleId}
                    onClose={onClose}
                    subtitle={subtitle}
                    icon={icon}
                    actions={headerActions}
                    closeLabel={closeLabel}
                    showCloseButton={showCloseButton}
                    closeDisabled={closeDisabled}
                    className={embedded ? "px-10 py-8" : ""}
                >
                    {headerContent}
                </ModalHeader>
                <div className={`min-h-0 bg-neutral-900 p-5 text-left ${contentClassName}`.trim()}>{children}</div>
                {footer && <footer className={`border-t border-neutral-700 bg-neutral-950/60 px-5 py-4 ${embedded ? "px-10 py-7 [&_button]:px-6 [&_button]:py-3" : ""}`.trim()}>{footer}</footer>}
            </div>
        </div>
    );
}
