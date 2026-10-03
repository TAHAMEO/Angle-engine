"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { FilePlus2, FileSearch } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import type { FindingRow } from "@/lib/api/types";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { EvidenceDrawer, EvidenceItemsTable } from "./evidence-items";
import { FilterBar } from "./filter-bar";
import { FindingDrawer } from "./finding-drawer";
import { FindingsTable } from "./findings-table";
import { parseFilters, toQuery, writeFilters, type FindingFilters } from "./filters";
import { NewFindingDialog } from "./new-finding-dialog";

export function EvidencePage() {
  const { investigation: inv, can } = useInvestigation();
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const filters = useMemo(() => parseFilters(new URLSearchParams(params.toString())), [params]);
  const [keyword, setKeyword] = useState("");
  const [creating, setCreating] = useState(false);
  const findingId = params.get("finding");
  const evidenceId = params.get("evidence");
  const tab = params.get("tab") === "items" ? "items" : "findings";

  const navigate = (next: URLSearchParams) => router.replace(`${pathname}${next.size ? `?${next.toString()}` : ""}`, { scroll: false });
  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    navigate(next);
  };
  const applyFilters = (value: FindingFilters) => navigate(writeFilters(new URLSearchParams(params.toString()), value));

  const query = useInfiniteQuery({
    queryKey: qk.findings(inv.id, { ...filters, keyword }),
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/findings", {
          params: { path: { investigation_id: inv.id }, query: { ...toQuery(filters, keyword), limit: 50, cursor: pageParam ?? undefined } },
        }),
      ),
    getNextPageParam: (last) => (last.has_more ? (last.next_cursor ?? null) : null),
  });
  const rows: FindingRow[] = query.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <PageHeader
        title="Evidence"
        description="Every claim with its chain: Source → Finding → Evidence → Timestamp → Confidence → Verification status. Statuses are set only by people, with a justification."
        actions={
          can("content:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <FilePlus2 className="h-4 w-4" aria-hidden /> Record a finding
            </Button>
          ) : undefined
        }
      />
      <Tabs
        label="Evidence views"
        value={tab}
        onValueChange={(value) => setParam("tab", value === "items" ? "items" : null)}
        tabs={[
          {
            value: "findings",
            label: "Findings",
            content: (
              <div className="space-y-4">
                <FilterBar filters={filters} onChange={applyFilters} keyword={keyword} onKeyword={setKeyword} />
                {query.isPending ? (
                  <LoadingBlock />
                ) : query.error ? (
                  <QueryError error={query.error} retry={() => void query.refetch()} />
                ) : rows.length ? (
                  <>
                    <p className="text-sm text-muted" role="status">
                      Showing {rows.length}
                      {query.hasNextPage ? "+" : ""} finding{rows.length === 1 ? "" : "s"}
                    </p>
                    <FindingsTable rows={rows} selectedId={findingId} onOpen={(id) => setParam("finding", id)} />
                    {query.hasNextPage ? (
                      <Button variant="secondary" onClick={() => void query.fetchNextPage()} loading={query.isFetchingNextPage}>
                        Load more
                      </Button>
                    ) : null}
                  </>
                ) : (
                  <EmptyState icon={FileSearch} title="No findings match">
                    Findings are created from image analysis, collected sources, accepted AI proposals (as AI hypotheses) or recorded by hand.
                  </EmptyState>
                )}
              </div>
            ),
          },
          { value: "items", label: "Evidence items", content: <EvidenceItemsTable onOpen={(id) => setParam("evidence", id)} /> },
        ]}
      />
      <FindingDrawer
        findingId={findingId}
        onClose={() => setParam("finding", null)}
        onOpenEvidence={(id) => {
          const next = new URLSearchParams(params.toString());
          next.delete("finding");
          next.set("evidence", id);
          navigate(next);
        }}
      />
      <EvidenceDrawer
        evidenceId={evidenceId}
        onClose={() => setParam("evidence", null)}
        onOpenFinding={(id) => {
          const next = new URLSearchParams(params.toString());
          next.delete("evidence");
          next.set("finding", id);
          navigate(next);
        }}
      />
      {can("content:write") ? <NewFindingDialog open={creating} onOpenChange={setCreating} onCreated={(id) => setParam("finding", id)} /> : null}
    </>
  );
}
