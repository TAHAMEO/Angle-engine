"use client";

import { useQuery } from "@tanstack/react-query";
import { Ban, FolderSearch, Search } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { CATEGORY_LABELS } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { Badge, Table, Tabs, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/form";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import type { S } from "@/lib/api/types";
import { formatDateTime, humanize } from "@/lib/format";
import { qk } from "@/lib/query/keys";

import { InvestigationTable } from "./investigation-table";
import { STATUS_FILTERS } from "./labels";

function InvestigationList() {
  const router = useRouter();
  const params = useSearchParams();
  const status = params.get("status") ?? "";
  // The free-text search stays in memory only, so investigation titles never land in browser history.
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.investigations({ status, q, limit: 100 }),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations", {
          params: {
            query: { status: status ? [status as S<"InvestigationStatus">] : undefined, q: q || undefined, limit: 100 },
          },
        }),
      ),
  });
  return (
    <div className="space-y-4">
      <form
        role="search"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setQ(draft.trim());
        }}
      >
        <label className="min-w-56 flex-1 space-y-1 text-sm">
          <span className="font-medium">Search by reference or title</span>
          <Input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="AE-2026-000123 or a title word" />
        </label>
        <label className="space-y-1 text-sm">
          <span className="font-medium">Status</span>
          <Select
            value={status}
            onChange={(event) => {
              const next = new URLSearchParams(params);
              if (event.target.value) next.set("status", event.target.value);
              else next.delete("status");
              router.replace(`/investigations?${next.toString()}`);
            }}
            className="w-44"
          >
            {STATUS_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </label>
        <Button type="submit" variant="secondary">
          <Search className="h-4 w-4" aria-hidden /> Search
        </Button>
      </form>
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.length ? (
        <InvestigationTable items={data} caption="Investigations" />
      ) : (
        <EmptyState icon={FolderSearch} title="No investigations match" />
      )}
    </div>
  );
}

function RefusedRequests() {
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["me", "policy-decisions", "refuse"],
    queryFn: () => unwrap(api.GET("/api/v1/me/policy-decisions", { params: { query: { decision: "refuse" } } })),
  });
  if (isPending) return <LoadingBlock />;
  if (error) return <QueryError error={error} retry={() => void refetch()} />;
  if (!data?.length) {
    return (
      <EmptyState icon={Ban} title="No refused requests">
        Requests that Angel Engine refused under the acceptable-use policy appear here, with the reason. The refused text itself is not shown.
      </EmptyState>
    );
  }
  return (
    <Table caption="Refused requests">
      <thead>
        <tr>
          <Th>When</Th>
          <Th>Where</Th>
          <Th>Concern</Th>
          <Th>Explanation</Th>
          <Th>Review</Th>
        </tr>
      </thead>
      <tbody>
        {data.map((decision) => (
          <tr key={decision.id}>
            <Td className="whitespace-nowrap">{formatDateTime(decision.created_at)}</Td>
            <Td>{humanize(decision.surface)}</Td>
            <Td>
              <div className="flex flex-wrap gap-1">
                {decision.categories.map((c) => (
                  <Badge key={c}>{CATEGORY_LABELS[c] ?? humanize(c)}</Badge>
                ))}
              </div>
            </Td>
            <Td className="max-w-md text-muted">{decision.rationale}</Td>
            <Td>{decision.review_outcome ? humanize(decision.review_outcome) : "—"}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function InvestigationHistory() {
  return (
    <>
      <PageHeader
        title="Investigation history"
        description="Investigations you are a member of, and requests that were refused under the acceptable-use policy."
        actions={
          <Button asChild variant="primary">
            <Link href="/investigations/new">New investigation</Link>
          </Button>
        }
      />
      <Tabs
        label="Investigation history"
        tabs={[
          { value: "investigations", label: "Investigations", content: <InvestigationList /> },
          { value: "refused", label: "Refused requests", content: <RefusedRequests /> },
        ]}
      />
    </>
  );
}
