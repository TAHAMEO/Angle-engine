import { AlertTriangle, CheckCircle2, Info, Loader2, OctagonAlert } from "lucide-react";

import { cn } from "@/lib/utils";

export function Spinner({ className, label = "Loading" }: { className?: string; label?: string }) {
  return (
    <span role="status" className="inline-flex items-center">
      <Loader2 className={cn("h-5 w-5 animate-spin text-muted", className)} aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-surface-3", className)} aria-hidden />;
}

const ALERT = {
  info: { icon: Info, className: "border-primary/40 bg-info-bg", iconClass: "text-primary" },
  success: { icon: CheckCircle2, className: "border-success/40 bg-success-bg", iconClass: "text-success" },
  warning: { icon: AlertTriangle, className: "border-warning/50 bg-warning-bg", iconClass: "text-warning" },
  danger: { icon: OctagonAlert, className: "border-danger/50 bg-danger-bg", iconClass: "text-danger" },
} as const;

export function Alert({
  tone = "info",
  title,
  children,
  className,
  action,
  role,
}: {
  tone?: keyof typeof ALERT;
  title?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  action?: React.ReactNode;
  role?: "alert" | "status" | "note";
}) {
  const { icon: Icon, className: toneClass, iconClass } = ALERT[tone];
  return (
    <div
      role={role ?? (tone === "danger" ? "alert" : "note")}
      className={cn("flex gap-3 rounded-lg border px-3.5 py-3 text-sm", toneClass, className)}
    >
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", iconClass)} aria-hidden />
      <div className="min-w-0 flex-1 space-y-1">
        {title ? <p className="font-semibold">{title}</p> : null}
        {children ? <div className="text-foreground/90">{children}</div> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  className,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border px-6 py-10 text-center",
        className,
      )}
    >
      {Icon ? <Icon className="h-8 w-8 text-subtle" aria-hidden /> : null}
      <p className="font-semibold">{title}</p>
      {children ? <div className="max-w-prose text-sm text-muted">{children}</div> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function LoadingBlock({ label = "Loading", className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-center gap-2 py-10 text-sm text-muted", className)}>
      <Spinner label={label} />
      <span aria-hidden>{label}…</span>
    </div>
  );
}
