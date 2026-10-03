"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { Globe } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Badge, Table, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/form";
import { Tooltip } from "@/components/ui/menu";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import type { SourceOut } from "@/lib/api/types";
import { CATEGORY_NAMES, formatDate } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { useConnectors } from "./collect-dialog";
import { ACCESS_STATUS } from "./labels";

export function AccessBadge({ status }: { status: string }) {
  const meta = ACCESS_STATUS[status];
  return (
    <Tooltip content={meta?.help ?? status}>
      <span tabIndex={0}>
        <Badge className={status === "captured" ? "" : "border-warning/50 text-warning"}>{meta?.label ?? status}</Badge>
      </span>
    </Tooltip>
  );
}

export function ReliabilityBadge({ value }: { value: string | null }) {
  if (!value) return <span className="text-subtle">—</span>;
  return (
    <Tooltip content="Source reliability (A–F) as assessed by an investigator">
      <span tabIndex={0} className="inline-grid h-5 w-5 place-items-center rounded-sm border border-border-strong font-mono text-[11px] font-semibold">
        {value}
      </span>
    </Tooltip>
  );
}

export function SourcesTable() {
  const { investigation: inv } = useInvestigation();
  const { data: connectors } = useConnectors(inv.id);
  const names = new Map((connectors ?? []).map((c) => [c.id, c.name]));
  const [category, setCategory] = useState("");
  const [access, setAccess] = useState("");
  const [domainDraft, setDomainDraft] = useState("");
  const [domain, setDomain] = useState("");
  const filters = { category, access, domain };
  const query = useInfiniteQuery({
    queryKey: qk.sources(inv.id, filters),
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/sources", {
          params: {
            path: { investigation_id: inv.id },
            query: {
              category: category ? [category] : undefined,
              access_status: access ? [access] : undefined,
              domain: domain || undefined,
              limit: 50,
              cursor: pageParam ?? undefined,
            },
          },
        }),
      ),
    getNextPageParam: (last) => (last.has_more ? (last.next_cursor ?? null) : null),
  });
  const rows: SourceOut[] = query.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <div className="space-y-4">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setDomain(domainDraft.trim().toLowerCase());
        }}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Category</span>
          <Select value={category} onChange={(e) => setCategory(e.target.value)} className="w-56">
            <option value="">All categories</option>
            {Object.entries(CATEGORY_NAMES).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </Select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Access</span>
          <Select value={access} onChange={(e) => setAccess(e.target.value)} className="w-44">
            <option value="">Any</option>
            {Object.entries(ACCESS_STATUS).map(([key, meta]) => (
              <option key={key} value={key}>
                {meta.label}
              </option>
            ))}
          </Select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Domain</span>
          <Input value={domainDraft} onChange={(e) => setDomainDraft(e.target.value)} placeholder="example.org" className="w-48" />
        </label>
        <Button type="submit" variant="secondary">
          Apply
        </Button>
      </form>
      {query.isPending ? (
        <LoadingBlock />
      ) : query.error ? (
        <QueryError error={query.error} retry={() => void query.refetch()} />
      ) : rows.length ? (
        <>
          <Table caption="Sources">
            <thead>
              <tr>
                <Th>Source</Th>
                <Th>Title</Th>
                <Th>Category</Th>
                <Th>Connector</Th>
                <Th>Access</Th>
                <Th>Reliability</Th>
                <Th className="text-right">Evidence</Th>
                <Th>Captured</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((source) => (
                <tr key={source.id} className="hover:bg-surface-2/60">
                  <Td className="whitespace-nowrap">
                    <Link href={`${path(inv.id, "sources")}/${source.id}`} className="inline-flex items-center gap-1.5 text-primary underline underline-offset-2 hover:decoration-2">
                      <Globe className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden />
                      <span className="font-mono text-xs">{source.label}</span>
                    </Link>
                    <span className="block text-xs text-muted">{source.host}</span>
                  </Td>
                  <Td className="max-w-sm">
                    <span className="line-clamp-2">{source.title ?? "Untitled"}</span>
                    {source.publisher ? <span className="block text-xs text-muted">{source.publisher}</span> : null}
                  </Td>
                  <Td>{CATEGORY_NAMES[source.category] ?? source.category}</Td>
                  <Td>{names.get(source.connector_id) ?? source.connector_id}</Td>
                  <Td>
                    <AccessBadge status={source.access_status} />
                  </Td>
                  <Td>
                    <ReliabilityBadge value={source.reliability} />
                  </Td>
                  <Td className="text-right tabular">{source.evidence_count ?? 0}</Td>
                  <Td className="whitespace-nowrap">{formatDate(source.last_captured_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {query.hasNextPage ? (
            <Button variant="secondary" onClick={() => void query.fetchNextPage()} loading={query.isFetchingNextPage}>
              Load more
            </Button>
          ) : null}
        </>
      ) : (
        <EmptyState icon={Globe} title="No sources yet">
          Collect public sources, pivot from an image clue, or add a source manually.
        </EmptyState>
      )}
    </div>
  );
}
