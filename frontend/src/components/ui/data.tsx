"use client";

import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Tabs as T } from "radix-ui";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/utils";

export function Card({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("card rounded-lg border border-border bg-surface", className)} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  description,
  action,
  className,
  as: Heading = "h2",
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  as?: "h2" | "h3";
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3 border-b border-border px-4 py-3", className)}>
      <div className="min-w-0">
        <Heading className="text-sm font-semibold">{title}</Heading>
        {description ? <p className="mt-0.5 text-[13px] text-muted">{description}</p> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function Badge({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <span
      className={cn(
        "badge inline-flex items-center gap-1 rounded-sm border border-border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** True while the element's content is wider than the element (it scrolls horizontally). */
function useHorizontalOverflow(ref: React.RefObject<HTMLElement | null>): boolean {
  const [overflowing, setOverflowing] = useState(false);
  useEffect(() => {
    const element = ref.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    // ResizeObserver reports once on observe, then on every size change of the wrapper or the table.
    const observer = new ResizeObserver(() => setOverflowing(element.scrollWidth > element.clientWidth + 1));
    observer.observe(element);
    if (element.firstElementChild) observer.observe(element.firstElementChild);
    return () => observer.disconnect();
  }, [ref]);
  return overflowing;
}

export function Table({ caption, children, className }: { caption?: string; children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  // A table that scrolls sideways (narrow screens) must be reachable by keyboard to scroll it (WCAG 2.1.1).
  const scrollable = useHorizontalOverflow(ref);
  return (
    <div
      ref={ref}
      className={cn("overflow-x-auto scrollbar-thin", className)}
      {...(scrollable ? { tabIndex: 0, role: "region", "aria-label": caption ? `${caption} (scrolls sideways)` : "Table (scrolls sideways)" } : {})}
    >
      <table className="w-full border-collapse text-[13px]">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        {children}
      </table>
    </div>
  );
}

export function Th({
  children,
  className,
  sort,
  onSort,
}: {
  children: React.ReactNode;
  className?: string;
  sort?: "asc" | "desc" | "none";
  onSort?: () => void;
}) {
  const ariaSort = sort === "asc" ? "ascending" : sort === "desc" ? "descending" : sort === "none" ? "none" : undefined;
  const Icon = sort === "asc" ? ArrowUp : sort === "desc" ? ArrowDown : ArrowUpDown;
  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={cn(
        "border-b border-border bg-surface-2 px-3 py-2 text-left text-xs font-semibold tracking-wide text-muted uppercase",
        className,
      )}
    >
      {onSort ? (
        <button type="button" onClick={onSort} className="inline-flex items-center gap-1 uppercase hover:text-foreground">
          {children}
          <Icon className="h-3.5 w-3.5" aria-hidden />
        </button>
      ) : (
        children
      )}
    </th>
  );
}

export function Td({ children, className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn("border-b border-border px-3 py-2 align-top", className)} {...props}>
      {children}
    </td>
  );
}

export function DefinitionList({ items, className }: { items: [React.ReactNode, React.ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-2 text-sm", className)}>
      {items.map(([term, value], index) => (
        <div key={index} className="contents">
          <dt className="text-muted">{term}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs({
  tabs,
  value,
  onValueChange,
  defaultValue,
  className,
  label,
}: {
  tabs: { value: string; label: React.ReactNode; content: React.ReactNode }[];
  value?: string;
  onValueChange?: (value: string) => void;
  defaultValue?: string;
  className?: string;
  label: string;
}) {
  return (
    <T.Root value={value} onValueChange={onValueChange} defaultValue={defaultValue ?? tabs[0]?.value} className={className}>
      <T.List aria-label={label} className="flex gap-1 overflow-x-auto border-b border-border">
        {tabs.map((tab) => (
          <T.Trigger
            key={tab.value}
            value={tab.value}
            className="-mb-px border-b-2 border-transparent px-3 py-2 text-sm whitespace-nowrap text-muted hover:text-foreground data-[state=active]:border-primary data-[state=active]:font-medium data-[state=active]:text-foreground"
          >
            {tab.label}
          </T.Trigger>
        ))}
      </T.List>
      {tabs.map((tab) => (
        <T.Content key={tab.value} value={tab.value} className="pt-4">
          {tab.content}
        </T.Content>
      ))}
    </T.Root>
  );
}

export function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <Card className="px-4 py-3">
      <p className="text-xs font-medium tracking-wide text-muted uppercase">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular">{value}</p>
      {hint ? <p className="mt-0.5 text-xs text-muted">{hint}</p> : null}
    </Card>
  );
}
