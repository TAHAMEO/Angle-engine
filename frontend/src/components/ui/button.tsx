import { Slot } from "radix-ui";
import { forwardRef } from "react";

import { cn } from "@/lib/utils";

import { Spinner } from "./feedback";

const VARIANTS = {
  primary: "bg-primary text-primary-fg hover:bg-primary-hover border border-transparent",
  secondary: "bg-surface-2 text-foreground hover:bg-surface-3 border border-border",
  outline: "bg-transparent text-foreground hover:bg-surface-2 border border-border-strong",
  ghost: "bg-transparent text-foreground hover:bg-surface-2 border border-transparent",
  danger: "bg-danger text-white dark:text-[#1a0b0d] hover:opacity-90 border border-transparent",
  link: "bg-transparent text-primary underline-offset-4 hover:underline border border-transparent px-0",
} as const;

const SIZES = {
  sm: "h-8 px-2.5 text-[13px] gap-1.5",
  md: "h-9 px-3.5 text-sm gap-2",
  lg: "h-10 px-4 text-sm gap-2",
  icon: "h-9 w-9 p-0 justify-center",
} as const;

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof VARIANTS;
  size?: keyof typeof SIZES;
  loading?: boolean;
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "secondary", size = "md", loading = false, asChild = false, disabled, children, ...props },
  ref,
) {
  const Comp = asChild ? Slot.Root : "button";
  return (
    <Comp
      ref={ref}
      className={cn(
        "inline-flex min-h-6 shrink-0 items-center rounded-md font-medium whitespace-nowrap transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {asChild ? (
        children
      ) : (
        <>
          {loading ? <Spinner className="h-4 w-4" label="Working" /> : null}
          {children}
        </>
      )}
    </Comp>
  );
});
