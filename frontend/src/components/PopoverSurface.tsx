import { forwardRef } from "react";
import type { ReactNode } from "react";

type Props = {
    children: ReactNode;
    id?: string;
    role?: "dialog" | "menu" | "tooltip";
    className?: string;
};

const PopoverSurface = forwardRef<HTMLDivElement, Readonly<Props>>(function PopoverSurface({ children, id, role = "dialog", className = "" }, ref) {
    return (
        <div
            ref={ref}
            id={id}
            role={role}
            className={`absolute right-0 top-full z-50 mt-2 w-[min(25rem,calc(100vw-2rem))] rounded-lg border border-neutral-700 bg-neutral-900 p-4 text-left text-sm font-normal text-neutral-100 shadow-2xl ${className}`.trim()}
        >
            {children}
        </div>
    );
});

export default PopoverSurface;