"use client";

import { ArrowRight, CalendarClock, FileSearch, Network } from "lucide-react";
import Link from "next/link";

import { STATUS, VerificationStatusBadge, type Status } from "@/components/provenance/badges";
import { Alert, EmptyState } from "@/components/ui/feedback";
import { Card, CardHeader, Stat } from "@/components/ui/data";
import { REL_LABELS, asGraph } from "@/features/graph/types";
import type { EventOut, FindingRow, S } from "@/lib/api/types";
import { formatAtPrecision } from "@/lib/format";
import { path } from "@/lib/investigation";
import { cn } from "@/lib/utils";

type Dashboard = S<"Dashboard">;

const SEVERITY_TONE = { critical: "danger", caution: "warning", info: "info" } as const;

export function WarningsList({ warnings }: { warnings: Dashboard["warnings"] }) {
  if (!warnings.length) return null;
  return (
    <section aria-label="Risk and privacy warnings" className="space-y-2">
      {warnings.map((warning) => (
        <Alert key={warning.kind} tone={SEVERITY_TONE[warning.severity as keyof typeof SEVERITY_TONE] ?? "info"}>
          {warning.message}
          {warning.count && warning.kind !== "faces_detected" ? <span className="text-muted"> ({warning.count})</span> : null}
          {warning.kind === "faces_detected" && warning.count ? (
            <span className="block text-xs text-muted">
              {warning.count} image{warning.count === 1 ? "" : "s"} with detected faces — faces are blurred in previews.
            </span>
          ) : null}
        </Alert>
      ))}
    </section>
  );
}

export function StatTiles({ stats }: { stats: Dashboard["stats"] }) {
  const verified = (stats.by_status.confirmed_by_source ?? 0) + (stats.by_status.corroborated ?? 0);
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      <Stat label="Evidence items" value={stats.evidence} />
      <Stat label="Sources" value={stats.sources} />
      <Stat label="Findings" value={stats.findings} hint={`${verified} verified`} />
      <Stat label="Images" value={stats.images} />
      <Stat label="Entities" value={stats.entities} hint={`${stats.relationships} relationships`} />
      <Stat label="Timeline events" value={stats.timeline_events} />
    </div>
  );
}

const ORDER: Status[] = ["confirmed_by_source", "corroborated", "unverified", "contradicted", "ai_hypothesis"];
const BAR: Record<Status, string> = {
  confirmed_by_source: "bg-st-confirmed",
  corroborated: "bg-st-corroborated",
  unverified: "bg-st-unverified",
  contradicted: "bg-st-contradicted",
  ai_hypothesis: "bg-st-ai",
};

/** Stacked bar with a full legend; the legend carries every number, so colour is never the only signal. */
export function StatusBreakdown({ byStatus, investigationId }: { byStatus: Record<string, number>; investigationId: string }) {
  const total = ORDER.reduce((sum, key) => sum + (byStatus[key] ?? 0), 0);
  return (
    <Card>
      <CardHeader title="Verification status" description="Findings by verification status — set only by people, never by AI." />
      <div className="space-y-3 p-4">
        {total ? (
          <div className="flex h-3 overflow-hidden rounded-full bg-surface-3" aria-hidden>
            {ORDER.map((key) =>
              byStatus[key] ? (
                <div key={key} className={cn(BAR[key], "h-full")} style={{ width: `${((byStatus[key] ?? 0) / total) * 100}%` }} />
              ) : null,
            )}
          </div>
        ) : null}
        <ul className="grid gap-1.5">
          {ORDER.map((key) => (
            <li key={key} className="flex items-center justify-between gap-2 text-sm">
              <Link href={`${path(investigationId, "evidence")}?status=${key}`} className="rounded hover:underline">
                <VerificationStatusBadge status={key} size="sm" />
              </Link>
              <span className="tabular font-medium">
                {byStatus[key] ?? 0}
                <span className="sr-only"> findings {STATUS[key].label}</span>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

export function RecentFindings({ rows, investigationId }: { rows: FindingRow[]; investigationId: string }) {
  return (
    <Card>
      <CardHeader
        title="Recently updated findings"
        action={
          <Link href={path(investigationId, "evidence")} className="inline-flex items-center gap-1 text-[13px] text-primary underline underline-offset-2 hover:decoration-2">
            All evidence <ArrowRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        }
      />
      {rows.length ? (
        <ul className="divide-y divide-border">
          {rows.map((row) => (
            <li key={row.id} className="px-4 py-2.5">
              <Link href={`${path(investigationId, "evidence")}?finding=${row.id}`} className="group block space-y-1">
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-xs text-muted">{row.label}</span>
                  <VerificationStatusBadge status={row.verification_status} size="sm" />
                </span>
                <span className="line-clamp-2 text-sm group-hover:underline">{row.statement}</span>
              </Link>
            </li>
          ))}
        </ul>
      ) : (
        <div className="p-4">
          <EmptyState icon={FileSearch} title="No findings yet">
            Upload an image or collect public sources to create evidence-backed findings.
          </EmptyState>
        </div>
      )}
    </Card>
  );
}

export function MiniTimeline({ events, investigationId }: { events: EventOut[]; investigationId: string }) {
  return (
    <Card>
      <CardHeader
        title="Timeline"
        action={
          <Link href={path(investigationId, "timeline")} className="inline-flex items-center gap-1 text-[13px] text-primary underline underline-offset-2 hover:decoration-2">
            Open timeline <ArrowRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        }
      />
      {events.length ? (
        <ol className="relative space-y-3 p-4 pl-8 before:absolute before:top-5 before:bottom-5 before:left-4 before:w-px before:bg-border">
          {events.map((event) => (
            <li key={event.id} className="relative">
              <span aria-hidden className="absolute top-1.5 -left-[1.15rem] h-2 w-2 rounded-full bg-primary" />
              <p className="font-mono text-xs text-muted">{formatAtPrecision(event.occurred_start, event.precision)}</p>
              <p className="text-sm">{event.title}</p>
            </li>
          ))}
        </ol>
      ) : (
        <div className="p-4">
          <EmptyState icon={CalendarClock} title="No dated events yet" />
        </div>
      )}
    </Card>
  );
}

export function MiniGraph({ graph, investigationId }: { graph: unknown; investigationId: string }) {
  const { nodes, edges } = asGraph(graph);
  const names = new Map(nodes.map((n) => [n.id, n.name]));
  return (
    <Card>
      <CardHeader
        title="Relationships"
        description={`${nodes.length} entities · ${edges.length} relationships`}
        action={
          <Link href={path(investigationId, "graph")} className="inline-flex items-center gap-1 text-[13px] text-primary underline underline-offset-2 hover:decoration-2">
            Open graph <ArrowRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        }
      />
      {edges.length ? (
        <ul className="divide-y divide-border">
          {edges.slice(0, 8).map((edge) => (
            <li key={edge.id} className="flex flex-wrap items-center gap-x-1.5 gap-y-1 px-4 py-2 text-sm">
              <span className="font-medium">{names.get(edge.from) ?? "?"}</span>
              <span className="font-mono text-xs text-muted">{REL_LABELS[edge.rel_type] ?? edge.rel_type}</span>
              <span className="font-medium">{names.get(edge.to) ?? "?"}</span>
              <span className="ml-auto flex items-center gap-1.5">
                <span className="text-xs text-muted">
                  {edge.supporting_count} source{edge.supporting_count === 1 ? "" : "s"}
                </span>
                <VerificationStatusBadge status={edge.verification_status} size="sm" />
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="p-4">
          <EmptyState icon={Network} title="No relationships yet" />
        </div>
      )}
    </Card>
  );
}
