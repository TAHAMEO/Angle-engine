"use client";

import { AlertTriangle, Star } from "lucide-react";

import { ConfidenceLevel, ProvenanceBadge, VerificationStatusBadge } from "@/components/provenance/badges";
import { Table, Td, Th } from "@/components/ui/data";
import type { FindingRow } from "@/lib/api/types";
import { formatAtPrecision, formatDate, formatDateTime } from "@/lib/format";

function SourceCell({ row }: { row: FindingRow }) {
  if (!row.source) return <span className="text-subtle">{row.provenance === "ai_hypothesis" ? "AI output" : "—"}</span>;
  return (
    <div className="min-w-0">
      <span className="font-mono text-xs">{row.source.label}</span>
      <span className="block truncate text-xs text-muted" title={row.source.host}>
        {row.source.host}
      </span>
    </div>
  );
}

function EvidenceCell({ row }: { row: FindingRow }) {
  const e = row.evidence;
  return (
    <div className="space-y-0.5 text-xs">
      <span className="font-medium">
        {e.count} item{e.count === 1 ? "" : "s"}
      </span>
      <span className="block text-muted">
        {e.supporting} supporting{e.contradicting ? ` · ${e.contradicting} contradicting` : ""}
      </span>
      {row.evidence_removed ? <span className="block text-warning">Some evidence was deleted</span> : null}
    </div>
  );
}

function TimestampCell({ row }: { row: FindingRow }) {
  const t = row.timestamps;
  return (
    <div className="space-y-0.5 text-xs whitespace-nowrap">
      {t.captured_at ? <span className="block">Captured {formatDate(t.captured_at)}</span> : null}
      {t.published_at ? <span className="block text-muted">Published {formatDate(t.published_at)}</span> : null}
      {t.event_time ? <span className="block text-muted">Event {formatAtPrecision(t.event_time, t.event_precision)}</span> : null}
      {!t.captured_at && !t.published_at && !t.event_time ? <span className="text-muted">Recorded {formatDate(t.created_at)}</span> : null}
    </div>
  );
}

function Statement({ row }: { row: FindingRow }) {
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-xs font-semibold">{row.label}</span>
        <ProvenanceBadge provenance={row.provenance} size="sm" />
        {row.importance === "key" ? (
          <span className="inline-flex items-center gap-0.5 text-[11px] text-warning">
            <Star className="h-3 w-3" aria-hidden /> Key
          </span>
        ) : null}
        {row.has_active_contradiction ? (
          <span className="inline-flex items-center gap-0.5 text-[11px] text-st-contradicted">
            <AlertTriangle className="h-3 w-3" aria-hidden /> Contradiction
          </span>
        ) : null}
        {row.retracted ? <span className="text-[11px] text-muted">Retracted</span> : null}
      </div>
      <p className={row.retracted ? "text-muted line-through" : ""}>{row.statement}</p>
    </div>
  );
}

/**
 * Findings in the required order: Source → Finding → Evidence → Timestamp → Confidence → Verification status.
 * Below the md breakpoint the same fields stack as cards.
 */
export function FindingsTable({ rows, onOpen, selectedId }: { rows: FindingRow[]; onOpen: (id: string) => void; selectedId?: string | null }) {
  return (
    <>
      <Table caption="Findings" className="hidden rounded-lg border border-border md:block">
        <thead>
          <tr>
            <Th className="w-32">Source</Th>
            <Th>Finding</Th>
            <Th className="w-36">Evidence</Th>
            <Th className="w-40">Timestamp</Th>
            <Th className="w-28">Confidence</Th>
            <Th className="w-44">Verification status</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id}
              aria-selected={selectedId === row.id || undefined}
              className="cursor-pointer hover:bg-surface-2/60 aria-selected:bg-primary/10"
              onClick={() => onOpen(row.id)}
            >
              <Td>
                <SourceCell row={row} />
              </Td>
              <Td>
                <button
                  type="button"
                  className="text-left hover:underline focus-visible:underline"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpen(row.id);
                  }}
                  aria-label={`Open finding ${row.label}`}
                >
                  <Statement row={row} />
                </button>
              </Td>
              <Td>
                <EvidenceCell row={row} />
              </Td>
              <Td>
                <TimestampCell row={row} />
              </Td>
              <Td>
                <ConfidenceLevel confidence={row.sensitive ? null : row.confidence} />
              </Td>
              <Td>
                <VerificationStatusBadge status={row.verification_status} />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <ul className="space-y-2 md:hidden" aria-label="Findings">
        {rows.map((row) => (
          <li key={row.id}>
            <button
              type="button"
              onClick={() => onOpen(row.id)}
              className="w-full space-y-2 rounded-lg border border-border bg-surface p-3 text-left text-sm"
            >
              <div className="flex items-center justify-between gap-2 text-xs text-muted">
                <span>Source: {row.source ? `${row.source.label} · ${row.source.host}` : "—"}</span>
              </div>
              <Statement row={row} />
              <div className="grid grid-cols-2 gap-2">
                <EvidenceCell row={row} />
                <TimestampCell row={row} />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <ConfidenceLevel confidence={row.sensitive ? null : row.confidence} />
                <VerificationStatusBadge status={row.verification_status} />
              </div>
              <span className="sr-only">Updated {formatDateTime(row.timestamps.updated_at)}</span>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
