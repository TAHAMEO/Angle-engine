"use client";

import { ShieldAlert } from "lucide-react";
import Link from "next/link";

import { Table, Td, Th } from "@/components/ui/data";
import { InvestigationStatus } from "@/features/common/states";
import type { InvestigationSummary } from "@/lib/api/types";
import { formatDate, relative } from "@/lib/format";

import { PURPOSE_CATEGORIES, SUBJECT_TYPES } from "./labels";

export function InvestigationTable({ items, caption }: { items: InvestigationSummary[]; caption: string }) {
  return (
    <>
      <Table caption={caption} className="hidden md:block">
        <thead>
          <tr>
            <Th>Reference</Th>
            <Th>Title</Th>
            <Th>Status</Th>
            <Th>Subject</Th>
            <Th>Purpose</Th>
            <Th className="text-right">Evidence</Th>
            <Th className="text-right">Findings</Th>
            <Th>Updated</Th>
          </tr>
        </thead>
        <tbody>
          {items.map((inv) => (
            <tr key={inv.id} className="hover:bg-surface-2/60">
              <Td className="font-mono text-xs whitespace-nowrap">
                <Link href={`/investigations/${inv.id}`} className="text-primary underline underline-offset-2 hover:decoration-2">
                  {inv.ref}
                </Link>
              </Td>
              <Td className="max-w-[22rem]">
                <Link href={`/investigations/${inv.id}`} className="font-medium hover:underline">
                  {inv.title}
                </Link>
                {inv.role ? <span className="block text-xs text-muted capitalize">You: {inv.role}</span> : null}
              </Td>
              <Td>
                <InvestigationStatus status={inv.status} />
              </Td>
              <Td className="whitespace-nowrap">
                {SUBJECT_TYPES[inv.subject_type]?.label ?? inv.subject_type}
                {inv.restricted_mode ? (
                  <span className="mt-0.5 flex items-center gap-1 text-xs text-warning">
                    <ShieldAlert className="h-3 w-3" aria-hidden /> Restricted mode
                  </span>
                ) : null}
              </Td>
              <Td>{PURPOSE_CATEGORIES[inv.purpose_category] ?? inv.purpose_category}</Td>
              <Td className="text-right tabular">{inv.counts.evidence ?? 0}</Td>
              <Td className="text-right tabular">{inv.counts.findings ?? 0}</Td>
              <Td className="whitespace-nowrap" title={formatDate(inv.updated_at)}>
                {relative(inv.updated_at)}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <ul className="space-y-2 md:hidden" aria-label={caption}>
        {items.map((inv) => (
          <li key={inv.id} className="rounded-lg border border-border bg-surface p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-xs text-muted">{inv.ref}</span>
              <InvestigationStatus status={inv.status} />
            </div>
            <Link href={`/investigations/${inv.id}`} className="mt-1 block font-medium hover:underline">
              {inv.title}
            </Link>
            <p className="mt-1 text-xs text-muted">
              {SUBJECT_TYPES[inv.subject_type]?.label ?? inv.subject_type} · {inv.counts.evidence ?? 0} evidence ·{" "}
              {inv.counts.findings ?? 0} findings · updated {relative(inv.updated_at)}
            </p>
          </li>
        ))}
      </ul>
    </>
  );
}
