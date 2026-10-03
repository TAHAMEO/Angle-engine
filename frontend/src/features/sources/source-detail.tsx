"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Save } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { ProvenanceBadge } from "@/components/provenance/badges";
import { ExternalLink } from "@/components/security/external-link";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, DefinitionList } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Field, Input, Select } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { NotesPanel } from "@/features/notes/notes-panel";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { EvidenceOut, S } from "@/lib/api/types";
import { CATEGORY_NAMES, formatDate, formatDateTime, humanize } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { useConnectors } from "./collect-dialog";
import { ACCESS_STATUS, RELIABILITY } from "./labels";
import { AccessBadge } from "./sources-table";

type Reliability = NonNullable<S<"SourcePatch">["reliability"]>;

function Annotate({ source }: { source: S<"SourceDetail"> }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [reliability, setReliability] = useState(source.reliability ?? "");
  const [publisher, setPublisher] = useState(source.publisher ?? "");
  const [group, setGroup] = useState(source.ownership_group ?? "");
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PATCH("/api/v1/investigations/{investigation_id}/sources/{source_id}", {
          params: { path: { investigation_id: inv.id, source_id: source.id } },
          body: {
            reliability: reliability ? (reliability as Reliability) : null,
            clear_reliability: !reliability,
            publisher: publisher.trim() || null,
            ownership_group: group.trim() || null,
          },
        }),
      ),
    onSuccess: () => {
      toast("Source updated", { tone: "success" });
      void client.invalidateQueries({ queryKey: qk.source(inv.id, source.id) });
      void client.invalidateQueries({ queryKey: qk.sources(inv.id) });
    },
    onError: (e) => toast("Could not update the source", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate();
      }}
    >
      <Field label="Reliability">
        {(props) => (
          <Select {...props} value={reliability} onChange={(e) => setReliability(e.target.value)}>
            <option value="">Not assessed</option>
            {Object.entries(RELIABILITY).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label="Publisher">{(props) => <Input {...props} value={publisher} onChange={(e) => setPublisher(e.target.value)} />}</Field>
      <Field label="Ownership group" hint="Sources in the same group count as one origin when judging corroboration.">
        {(props) => <Input {...props} value={group} onChange={(e) => setGroup(e.target.value)} />}
      </Field>
      <Button type="submit" variant="secondary" size="sm" loading={save.isPending}>
        <Save className="h-4 w-4" aria-hidden /> Save
      </Button>
    </form>
  );
}

export function EvidenceExcerpt({ item }: { item: EvidenceOut }) {
  const { investigation: inv } = useInvestigation();
  return (
    <li className="space-y-1.5 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <Link href={`${path(inv.id, "evidence")}?tab=items&evidence=${item.id}`} className="font-mono text-xs font-semibold text-primary hover:underline">
          {item.label}
        </Link>
        <ProvenanceBadge provenance={item.provenance} size="sm" />
        <span className="text-xs text-muted">
          {humanize(item.evidence_type)} · captured {formatDateTime(item.captured_at)}
          {item.published_at ? ` · published ${formatDate(item.published_at)}` : ""}
        </span>
      </div>
      {item.excerpt_hidden ? (
        <p className="text-muted italic">Hidden: flagged as sensitive ({item.sensitivity_flags.map(humanize).join(", ")}).</p>
      ) : item.excerpt ? (
        <blockquote className="border-l-2 border-border-strong pl-3 whitespace-pre-line">{item.excerpt}</blockquote>
      ) : null}
    </li>
  );
}

export function SourceDetailView() {
  const { investigation: inv, can } = useInvestigation();
  const { sourceId } = useParams<{ sourceId: string }>();
  const { data: connectors } = useConnectors(inv.id);
  const { data: source, error, isPending, refetch } = useQuery({
    queryKey: qk.source(inv.id, sourceId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/sources/{source_id}", {
          params: { path: { investigation_id: inv.id, source_id: sourceId } },
        }),
      ),
  });
  if (isPending) return <LoadingBlock />;
  if (error || !source) return <QueryError error={error} retry={() => void refetch()} />;
  const evidence = source.evidence as unknown as EvidenceOut[];
  const connector = connectors?.find((c) => c.id === source.connector_id);
  return (
    <>
      <PageHeader
        eyebrow={
          <Link href={path(inv.id, "sources")} className="inline-flex items-center gap-1 hover:underline">
            <ArrowLeft className="h-3 w-3" aria-hidden /> Sources
          </Link>
        }
        title={
          <span>
            <span className="font-mono">{source.label}</span> <span className="text-base font-normal text-muted">{source.title ?? source.host}</span>
          </span>
        }
      />
      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <Card>
            <CardHeader title="Captured evidence from this source" description="The captured copy is what Angel Engine stored — read it here instead of visiting the live page." />
            <div className="p-4">
              {evidence.length ? (
                <ul className="space-y-2">
                  {evidence.map((item) => (
                    <EvidenceExcerpt key={item.id} item={item} />
                  ))}
                </ul>
              ) : (
                <EmptyState title="No evidence stored" className="py-6">
                  {ACCESS_STATUS[source.access_status]?.help}
                </EmptyState>
              )}
            </div>
          </Card>
          <Card>
            <CardHeader title="Notes" />
            <div className="p-4">
              <NotesPanel targetType="source" targetId={source.id} />
            </div>
          </Card>
        </div>
        <div className="space-y-6">
          <Card>
            <CardHeader title="Source record" />
            <div className="space-y-4 p-4">
              {source.access_status !== "captured" ? <Alert tone="warning">{ACCESS_STATUS[source.access_status]?.help}</Alert> : null}
              <DefinitionList
                items={[
                  ["Live page", <ExternalLink key="u" href={source.url} />],
                  ["Archived copy", source.archived_url ? <ExternalLink key="a" href={source.archived_url}>Internet Archive</ExternalLink> : "—"],
                  ["Domain", source.registrable_domain],
                  ["Category", CATEGORY_NAMES[source.category] ?? source.category],
                  ["Collected by", connector?.name ?? source.connector_id],
                  ["Access", <AccessBadge key="s" status={source.access_status} />],
                  ["Published", formatDate(source.published_at)],
                  ["First captured", formatDateTime(source.first_captured_at)],
                  ["Last captured", formatDateTime(source.last_captured_at)],
                ]}
              />
              <p className="text-xs text-muted">Opening the live page reveals your IP address to that site.</p>
            </div>
          </Card>
          {can("content:write") ? (
            <Card>
              <CardHeader title="Assessment" />
              <div className="p-4">
                <Annotate source={source} />
              </div>
            </Card>
          ) : null}
        </div>
      </div>
    </>
  );
}
