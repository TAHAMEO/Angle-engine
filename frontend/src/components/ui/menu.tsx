"use client";

import { DropdownMenu as DM, Popover as P, Tooltip as TT } from "radix-ui";

import { cn } from "@/lib/utils";

export function Tooltip({ content, children }: { content: React.ReactNode; children: React.ReactNode }) {
  return (
    <TT.Root>
      <TT.Trigger asChild>{children}</TT.Trigger>
      <TT.Portal>
        <TT.Content
          sideOffset={6}
          className="z-50 max-w-xs rounded-md border border-border bg-surface-3 px-2.5 py-1.5 text-xs text-foreground shadow-lg"
        >
          {content}
        </TT.Content>
      </TT.Portal>
    </TT.Root>
  );
}

export function Menu({
  trigger,
  items,
  label,
  align = "end",
}: {
  trigger: React.ReactNode;
  label?: string;
  align?: "start" | "end";
  items: ({ label: React.ReactNode; onSelect: () => void; disabled?: boolean; danger?: boolean } | "separator")[];
}) {
  return (
    <DM.Root>
      <DM.Trigger asChild>{trigger}</DM.Trigger>
      <DM.Portal>
        <DM.Content
          align={align}
          sideOffset={6}
          aria-label={label}
          className="z-50 min-w-48 rounded-md border border-border bg-surface p-1 shadow-xl"
        >
          {items.map((item, index) =>
            item === "separator" ? (
              <DM.Separator key={index} className="my-1 h-px bg-border" />
            ) : (
              <DM.Item
                key={index}
                disabled={item.disabled}
                onSelect={item.onSelect}
                className={cn(
                  "flex cursor-default items-center gap-2 rounded-sm px-2.5 py-1.5 text-sm outline-none select-none",
                  "data-[disabled]:opacity-50 data-[highlighted]:bg-surface-2",
                  item.danger && "text-danger",
                )}
              >
                {item.label}
              </DM.Item>
            ),
          )}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

export function Popover({
  trigger,
  children,
  open,
  onOpenChange,
  className,
  align = "start",
}: {
  trigger: React.ReactNode;
  children: React.ReactNode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
  align?: "start" | "end" | "center";
}) {
  return (
    <P.Root open={open} onOpenChange={onOpenChange}>
      <P.Trigger asChild>{trigger}</P.Trigger>
      <P.Portal>
        <P.Content
          align={align}
          sideOffset={6}
          className={cn("z-50 rounded-md border border-border bg-surface p-3 shadow-xl", className)}
        >
          {children}
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}
