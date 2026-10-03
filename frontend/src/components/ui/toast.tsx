"use client";

import { CheckCircle2, Info, OctagonAlert, X } from "lucide-react";
import { Toast as T } from "radix-ui";
import { useSyncExternalStore } from "react";

import { cn } from "@/lib/utils";

type Tone = "info" | "success" | "danger";
interface Item {
  id: number;
  title: string;
  description?: string;
  tone: Tone;
}

let items: Item[] = [];
let next = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export function toast(title: string, options: { description?: string; tone?: Tone } = {}): void {
  items = [...items, { id: next++, title, description: options.description, tone: options.tone ?? "info" }].slice(-4);
  emit();
}

function dismiss(id: number) {
  items = items.filter((i) => i.id !== id);
  emit();
}

const ICONS = { info: Info, success: CheckCircle2, danger: OctagonAlert };

export function Toaster() {
  const current = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => items,
    () => items,
  );
  return (
    <>
      {current.map((item) => {
        const Icon = ICONS[item.tone];
        return (
          <T.Root
            key={item.id}
            type={item.tone === "danger" ? "foreground" : "background"}
            onOpenChange={(open) => !open && dismiss(item.id)}
            className="flex items-start gap-3 rounded-lg border border-border bg-surface-2 p-3 shadow-xl"
          >
            <Icon
              className={cn(
                "mt-0.5 h-4 w-4 shrink-0",
                item.tone === "success" ? "text-success" : item.tone === "danger" ? "text-danger" : "text-primary",
              )}
              aria-hidden
            />
            <div className="min-w-0 flex-1">
              <T.Title className="text-sm font-semibold">{item.title}</T.Title>
              {item.description ? (
                <T.Description className="mt-0.5 text-[13px] text-muted">{item.description}</T.Description>
              ) : null}
            </div>
            <T.Close aria-label="Dismiss" className="rounded p-0.5 text-muted hover:text-foreground">
              <X className="h-4 w-4" aria-hidden />
            </T.Close>
          </T.Root>
        );
      })}
      <T.Viewport className="fixed right-4 bottom-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2 outline-none" />
    </>
  );
}
