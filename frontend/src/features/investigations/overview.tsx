"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, ImagePlus, Search } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, DefinitionList } from "@/components/ui/data";
import { LoadingBlock } from "@/components/ui/feedback";
import { Checkbox } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { InvestigationStatus, QueryError } from "@/features/common/states";
import { MiniGraph, MiniTimeline, RecentFindings, StatTiles, StatusBreakdown, WarningsList } from "@/features/dashboard/overview-widgets";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { formatDateTime } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { LAWFUL_BASES, PURPOSE_CATEGORIES, SUBJECT_TYPES } from "./labels";
import { LifecycleActions } from "./lifecycle-actions";
import { TeamCard } from "./team-card";

export function useDashboard(id: string) {
  return useQuery({
    queryKey: qk.dashboard(id),
    queryFn: () => unwrap(api.GET("/api/v1/investigations/{investigation_id}/dashboard", { params: { path: { investigation_id: id } } })),
  });
}

function AboutCard() {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const toggleAi = useMutation({
    mutationFn: (enabled: boolean) =>
      unwrap(
        api.PATCH("/api/v1/investigations/{investigation_id}", {
          params: { path: { investigation_id: inv.id }, header: { "if-match": `"${inv.version}"` } },
          body: { ai_enabled: enabled },
        }),
      ),
    onSuccess: (detail) => {
      client.setQueryData(qk.investigation(inv.id), detail);
      toast(detail.ai_enabled ? "Assistant turned on" : "Assistant turned off");
    },
    onError: (error) => toast("Could not change the setting", { description: messageOf(error), tone: "danger" }),
  });
  return (
    <Card>
      <CardHeader title="Purpose and legal basis" description="Recorded at creation and screened by the acceptable-use policy." />
      <div className="space-y-4 p-4">
        <p className="text-sm leading-relaxed whitespace-pre-line">{inv.purpose}</p>
        <DefinitionList
          items={[
            ["Purpose category", PURPOSE_CATEGORIES[inv.purpose_category] ?? inv.purpose_category],
            ["Lawful basis", LAWFUL_BASES[inv.lawful_basis] ?? inv.lawful_basis],
            ["Authorization reference", inv.authorization_ref ?? "—"],
            ["Jurisdiction", inv.jurisdiction ?? "—"],
            ["Subject type", SUBJECT_TYPES[inv.subject_type]?.label ?? inv.subject_type],
            ["Owner", inv.owner_name ?? "—"],
            ["Reviewed", inv.reviewed_at ? formatDateTime(inv.reviewed_at) : "—"],
          ]}
        />
        {can("investigation:manage") ? (
          <Checkbox
            label="Allow the AI assistant in this investigation"
            description="Evidence excerpts are sent to the configured AI provider when someone asks the assistant."
            checked={inv.ai_enabled}
            disabled={toggleAi.isPending}
            onChange={(event) => toggleAi.mutate(event.target.checked)}
          />
        ) : null}
      </div>
    </Card>
  );
}

export function InvestigationOverview() {
  const { investigation: inv, can } = useInvestigation();
  const { data, error, isPending, refetch } = useDashboard(inv.id);
  const writable = can("content:write");
  return (
    <>
      <PageHeader
        eyebrow={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{inv.ref}</span>
            <InvestigationStatus status={inv.status} />
            <span>Created {formatDateTime(inv.created_at)}</span>
          </span>
        }
        title={inv.title}
        description={inv.description ?? undefined}
        actions={<LifecycleActions />}
      />
      {writable ? (
        <div className="mb-6 flex flex-wrap gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={path(inv.id, "images")}>
              <ImagePlus className="h-4 w-4" aria-hidden /> Analyze an image
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href={`${path(inv.id, "sources")}?collect=1`}>
              <Search className="h-4 w-4" aria-hidden /> Collect public sources
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href={path(inv.id, "reports")}>
              <FileText className="h-4 w-4" aria-hidden /> Build a report
            </Link>
          </Button>
        </div>
      ) : null}
      {isPending ? (
        <LoadingBlock label="Loading overview" />
      ) : error || !data ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : (
        <div className="space-y-6">
          <WarningsList warnings={data.warnings} />
          <StatTiles stats={data.stats} />
          {Object.values(data.jobs).some((n) => n > 0) ? (
            <p role="status" className="text-sm text-muted">
              Background work: {Object.entries(data.jobs).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k.replaceAll("_", " ")}`).join(" · ")}
            </p>
          ) : null}
          <div className="grid gap-6 xl:grid-cols-3">
            <div className="space-y-6 xl:col-span-2">
              <RecentFindings rows={data.recent_findings} investigationId={inv.id} />
              <MiniGraph graph={data.graph} investigationId={inv.id} />
            </div>
            <div className="space-y-6">
              <StatusBreakdown byStatus={data.stats.by_status} investigationId={inv.id} />
              <MiniTimeline events={data.timeline} investigationId={inv.id} />
            </div>
          </div>
          <div className="grid gap-6 xl:grid-cols-2">
            <AboutCard />
            <TeamCard />
          </div>
        </div>
      )}
    </>
  );
}
