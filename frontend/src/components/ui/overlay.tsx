"use client";

import { X } from "lucide-react";
import { AlertDialog as AD, Dialog as D } from "radix-ui";

import { cn } from "@/lib/utils";

import { Button } from "./button";

const OVERLAY = "fixed inset-0 z-40 bg-black/50 backdrop-blur-[1px] data-[state=open]:animate-in";

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
  trigger,
}: {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  trigger?: React.ReactNode;
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      {trigger ? <D.Trigger asChild>{trigger}</D.Trigger> : null}
      <D.Portal>
        <D.Overlay className={OVERLAY} />
        <D.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 flex-col",
            "rounded-lg border border-border bg-surface shadow-xl",
            className,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="space-y-1">
              <D.Title className="text-base font-semibold">{title}</D.Title>
              {description ? (
                <D.Description className="text-sm text-muted">{description}</D.Description>
              ) : (
                <D.Description className="sr-only">{typeof title === "string" ? title : "Dialog"}</D.Description>
              )}
            </div>
            <D.Close asChild>
              <Button variant="ghost" size="icon" aria-label="Close">
                <X className="h-4 w-4" aria-hidden />
              </Button>
            </D.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer ? <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div> : null}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

/** Side panel (detail drawers). Non-modal variants are used for the assistant. */
export function Sheet({
  open,
  onOpenChange,
  title,
  description,
  children,
  side = "right",
  modal = true,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  side?: "right" | "left";
  modal?: boolean;
  className?: string;
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange} modal={modal}>
      <D.Portal>
        {modal ? <D.Overlay className={OVERLAY} /> : null}
        <D.Content
          onInteractOutside={modal ? undefined : (event) => event.preventDefault()}
          className={cn(
            "fixed top-0 bottom-0 z-50 flex w-full flex-col border-border bg-surface shadow-2xl sm:max-w-xl",
            side === "right" ? "right-0 border-l" : "left-0 border-r",
            className,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0 space-y-1">
              <D.Title className="text-base font-semibold">{title}</D.Title>
              {description ? (
                <D.Description className="text-sm text-muted">{description}</D.Description>
              ) : (
                <D.Description className="sr-only">Details</D.Description>
              )}
            </div>
            <D.Close asChild>
              <Button variant="ghost" size="icon" aria-label="Close panel">
                <X className="h-4 w-4" aria-hidden />
              </Button>
            </D.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  tone = "danger",
  onConfirm,
  loading,
  children,
  confirmDisabled,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  onConfirm: () => void;
  loading?: boolean;
  children?: React.ReactNode;
  confirmDisabled?: boolean;
}) {
  return (
    <AD.Root open={open} onOpenChange={onOpenChange}>
      <AD.Portal>
        <AD.Overlay className={OVERLAY} />
        <AD.Content className="fixed top-1/2 left-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-xl">
          <AD.Title className="text-base font-semibold">{title}</AD.Title>
          <AD.Description asChild>
            <div className="mt-2 space-y-3 text-sm text-muted">{description}</div>
          </AD.Description>
          {children ? <div className="mt-4">{children}</div> : null}
          <div className="mt-5 flex justify-end gap-2">
            <AD.Cancel asChild>
              <Button variant="secondary">Cancel</Button>
            </AD.Cancel>
            <Button
              variant={tone === "danger" ? "danger" : "primary"}
              loading={loading}
              disabled={confirmDisabled}
              onClick={(event) => {
                event.preventDefault();
                onConfirm();
              }}
            >
              {confirmLabel}
            </Button>
          </div>
        </AD.Content>
      </AD.Portal>
    </AD.Root>
  );
}
