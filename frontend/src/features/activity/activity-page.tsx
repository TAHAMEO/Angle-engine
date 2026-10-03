"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Table, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { formatDateTime, humanize } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

/** Human-readable audit actions. The audit log never contains evidence content, only what happened. */
export function describeAction(action: string): string {
  const [area, verb] = action.split(".");
  const AREA: Record<string, string> = {
    investigation: "Investigation",
    finding: "Finding",
    evidence: "Evidence",
    image: "Image",
    collection: "Collection",
    report: "Report",
    ai: "Assistant",
    note: "Note",
    member: "Membership",
    relationship: "Relationship",
    timeline: "Timeline",
    policy: "Policy",
    source: "Source",
    entity: "Entity",
    access: "Access",
  };
  return `${AREA[area ?? ""] ?? humanize(area ?? action)}: ${humanize(verb ?? "")}`.trim();
}

function Details({ details }: { details: Record<string, unknown> }) {
  const entries = Object.entries(details).filter(
    ([, v]) =>
      v !== null &&
      v !== undefined &&
      v !== "" &&
      !(Array.isArray(v) && v.length === 0) &&
      !(typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0),
  );
  if (!entries.length) return <span className="text-subtle">—</span>;
  return (
    <span className="text-xs text-muted">
      {entries
        .slice(0, 6)
        .map(([k, v]) => `${humanize(k)}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
        .join(" · ")}
    </span>
  );
}

export function ActivityPage() {
  const { investigation: inv } = useInvestigation();
  const query = useInfiniteQuery({
    queryKey: qk.activity(inv.id),
    initialPageParam: null as number | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/activity", {
          params: { path: { investigation_id: inv.id }, query: { before_seq: pageParam ?? undefined, limit: 50 } },
        }),
      ),
    getNextPageParam: (last) => (last.length === 50 ? (last[last.length - 1]?.seq ?? null) : null),
  });
  const rows = query.data?.pages.flat() ?? [];
  return (
    <>
      <PageHeader
        title="Activity"
        description="The investigation's audit trail, from the tamper-evident audit log. It records who did what and when — never evidence content."
      />
      {query.isPending ? (
        <LoadingBlock />
      ) : query.error ? (
        <QueryError error={query.error} retry={() => void query.refetch()} />
      ) : rows.length ? (
        <>
          <Table caption="Activity" className="rounded-lg border border-border">
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Who</Th>
                <Th>What</Th>
                <Th>Outcome</Th>
                <Th>Details</Th>
                <Th className="text-right">Entry</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.seq}>
                  <Td className="whitespace-nowrap">{formatDateTime(row.occurred_at)}</Td>
                  <Td>{row.actor_name ?? "System"}</Td>
                  <Td>
                    {describeAction(row.action)}
                    {row.target_type ? <span className="block text-xs text-muted">{humanize(row.target_type)}</span> : null}
                  </Td>
                  <Td className={row.outcome === "success" ? "" : "text-danger"}>{humanize(row.outcome)}</Td>
                  <Td className="max-w-sm">
                    <Details details={row.details} />
                  </Td>
                  <Td className="text-right font-mono text-xs">#{row.seq}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {query.hasNextPage ? (
            <Button variant="secondary" className="mt-3" onClick={() => void query.fetchNextPage()} loading={query.isFetchingNextPage}>
              Load older entries
            </Button>
          ) : null}
        </>
      ) : (
        <EmptyState icon={ScrollText} title="No activity recorded yet" />
      )}
    </>
  );
}
