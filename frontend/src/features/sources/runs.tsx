"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, CheckCircle2, ListChecks, Square, XCircle } from "lucide-react";
import { useState } from "react";

import { ExternalLink } from "@/components/security/external-link";
import { Button } from "@/components/ui/button";
import { Badge, Table, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock, Spinner } from "@/components/ui/feedback";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { RunOut } from "@/lib/api/types";
import { formatDateTime, humanize, relative } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { useSession } from "@/lib/session";

import { useConnectors } from "./collect-dialog";
import { INPUT_TYPES, RUN_ACTIVE, RUN_STATUS } from "./labels";

/** Search-engine results are transient leads: only pages you select are captured and stored. */
function LeadsDialog({ run, open, onOpenChange }: { run: RunOut; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const { data, isPending, error } = useQuery({
    queryKey: ["investigations", inv.id, "leads", run.id],
    enabled: open,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/collection-runs/{run_id}/leads", {
          params: { path: { investigation_id: inv.id, run_id: run.id } },
        }),
      ),
    gcTime: 0,
  });
  const capture = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/captures", {
          params: { path: { investigation_id: inv.id } },
          body: { urls: [...selected] },
        }),
      ),
    onSuccess: (runs) => {
      onOpenChange(false);
      setSelected(new Set());
      void client.invalidateQueries({ queryKey: qk.runs(inv.id) });
      toast(`Capturing ${runs.length} page${runs.length === 1 ? "" : "s"}`, { description: "Pages are fetched only where robots.txt allows.", tone: "success" });
    },
    onError: (e) => toast("Capture did not start", { description: messageOf(e), tone: "danger" }),
  });
  const toggle = (url: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(url)) next.delete(url);
      else if (next.size < 20) next.add(url);
      return next;
    });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Search leads"
      description={`Leads are not stored and expire ${run.leads_expire_at ? relative(run.leads_expire_at) : "soon"}. Select up to 20 pages to capture as sources.`}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button variant="primary" disabled={!selected.size} loading={capture.isPending} onClick={() => capture.mutate()}>
            Capture {selected.size || ""} selected
          </Button>
        </>
      }
    >
      {isPending ? <Spinner /> : error ? <QueryError error={error} /> : null}
      {data && !data.length ? <EmptyState title="No leads (they may have expired)" /> : null}
      <ul className="space-y-2">
        {data?.map((lead) => (
          <li key={lead.url} className="flex gap-2.5 rounded-md border border-border p-3 text-sm">
            <input
              type="checkbox"
              className="mt-1 h-4 w-4 accent-[var(--primary)]"
              checked={selected.has(lead.url)}
              onChange={() => toggle(lead.url)}
              aria-label={`Select ${lead.title}`}
            />
            <div className="min-w-0 space-y-0.5">
              <p className="font-medium">{lead.title}</p>
              <ExternalLink href={lead.url} className="text-xs" />
              {lead.publisher ? <p className="text-xs text-muted">{lead.publisher}</p> : null}
              {lead.snippet ? <p className="text-[13px] text-muted">{lead.snippet}</p> : null}
            </div>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

function RunActions({ run }: { run: RunOut }) {
  const { investigation: inv, can } = useInvestigation();
  const { data: session } = useSession();
  const client = useQueryClient();
  const [leadsOpen, setLeadsOpen] = useState(false);
  const params = { path: { investigation_id: inv.id, run_id: run.id } };
  const act = useMutation({
    mutationFn: async (action: "cancel" | "approve" | "reject") => {
      if (action === "cancel") return unwrap(api.POST("/api/v1/investigations/{investigation_id}/collection-runs/{run_id}/cancel", { params }));
      if (action === "approve") return unwrap(api.POST("/api/v1/investigations/{investigation_id}/collection-runs/{run_id}/approve", { params, body: null }));
      return unwrap(api.POST("/api/v1/investigations/{investigation_id}/collection-runs/{run_id}/reject", { params, body: null }));
    },
    onSuccess: (_, action) => {
      void client.invalidateQueries({ queryKey: qk.runs(inv.id) });
      toast(action === "cancel" ? "Run cancelled" : action === "approve" ? "Run approved" : "Run rejected");
    },
    onError: (e) => toast("The action failed", { description: messageOf(e), tone: "danger" }),
  });
  const supervisor = session?.user?.role === "supervisor" && !run.requested_by_me;
  return (
    <div className="flex flex-wrap justify-end gap-1">
      {run.has_leads ? (
        <>
          <Button size="sm" variant="outline" onClick={() => setLeadsOpen(true)}>
            <ListChecks className="h-3.5 w-3.5" aria-hidden /> Leads
          </Button>
          <LeadsDialog run={run} open={leadsOpen} onOpenChange={setLeadsOpen} />
        </>
      ) : null}
      {RUN_ACTIVE.has(run.status) && can("content:write") ? (
        <Button size="sm" variant="ghost" onClick={() => act.mutate("cancel")} loading={act.isPending}>
          <Square className="h-3.5 w-3.5" aria-hidden /> Cancel
        </Button>
      ) : null}
      {run.status === "pending_review" && supervisor ? (
        <>
          <Button size="sm" variant="outline" onClick={() => act.mutate("approve")}>
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> Approve
          </Button>
          <Button size="sm" variant="ghost" onClick={() => act.mutate("reject")}>
            <XCircle className="h-3.5 w-3.5" aria-hidden /> Reject
          </Button>
        </>
      ) : null}
    </div>
  );
}

export function RunsPanel() {
  const { investigation: inv } = useInvestigation();
  const { data: connectors } = useConnectors(inv.id);
  const names = new Map((connectors ?? []).map((c) => [c.id, c.name]));
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.runs(inv.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/collection-runs", {
          params: { path: { investigation_id: inv.id } },
          headers: BACKGROUND,
        }),
      ),
    refetchInterval: (query) => (query.state.data?.some((run) => RUN_ACTIVE.has(run.status)) ? 2000 : false),
  });
  if (isPending) return <LoadingBlock />;
  if (error) return <QueryError error={error} retry={() => void refetch()} />;
  if (!data?.length) return <EmptyState icon={Ban} title="No collection runs yet" />;
  return (
    <Table caption="Collection runs">
      <thead>
        <tr>
          <Th>Started</Th>
          <Th>Connector</Th>
          <Th>Query</Th>
          <Th>Status</Th>
          <Th className="text-right">Records</Th>
          <Th className="text-right">References</Th>
          <Th><span className="sr-only">Actions</span></Th>
        </tr>
      </thead>
      <tbody>
        {data.map((run) => (
          <tr key={run.id}>
            <Td className="whitespace-nowrap">{formatDateTime(run.created_at)}</Td>
            <Td>{names.get(run.connector_id) ?? run.connector_id}</Td>
            <Td className="max-w-xs">
              <span className="font-mono text-[13px] break-all">{run.query}</span>
              <span className="block text-xs text-muted">{INPUT_TYPES[run.input_type] ?? humanize(run.input_type)}</span>
            </Td>
            <Td>
              <span className="inline-flex items-center gap-1.5">
                {RUN_ACTIVE.has(run.status) ? <Spinner className="h-3.5 w-3.5" label="Running" /> : null}
                {RUN_STATUS[run.status] ?? humanize(run.status)}
              </span>
              {run.error_code ? <span className="block text-xs text-danger">{humanize(run.error_code)}</span> : null}
              {run.warnings.map((w) => (
                <Badge key={w} className="mt-1 border-warning/50 text-warning">
                  {humanize(w)}
                </Badge>
              ))}
            </Td>
            <Td className="text-right tabular">{run.records_count}</Td>
            <Td className="text-right tabular">{run.references_count}</Td>
            <Td>
              <RunActions run={run} />
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
