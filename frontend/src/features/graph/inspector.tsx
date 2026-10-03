"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { CitationChip, ProvenanceBadge, STATUS, VerificationStatusBadge, type Status } from "@/components/provenance/badges";
import { Button } from "@/components/ui/button";
import { Card, DefinitionList } from "@/components/ui/data";
import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Checkbox, Field, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { ConflictError, messageOf } from "@/lib/api/errors";
import { formatDateTime, humanize } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";

import { ENTITY_LABELS, REL_LABELS, type EdgeSupport, type GraphEdge, type GraphNode } from "./types";

interface RelationshipDetail extends GraphEdge {
  from_entity: GraphNode | null;
  to_entity: GraphNode | null;
  allowed_transitions: string[];
  failed_preconditions: Record<string, string[]>;
  history: { from_status: string | null; to_status: string; justification: string | null; created_at: string }[];
}

function SupportList({ support }: { support: EdgeSupport[] }) {
  const { investigation: inv } = useInvestigation();
  if (!support.length) return <p className="text-sm text-muted">No supporting evidence.</p>;
  return (
    <ul className="space-y-1.5">
      {support.map((s) => (
        <li key={`${s.evidence_id}-${s.stance}`} className="flex flex-wrap items-center gap-1.5 text-sm">
          <Link href={`${path(inv.id, "evidence")}?tab=items&evidence=${s.evidence_id}`}>
            <CitationChip label={s.evidence_label} />
          </Link>
          <span className={s.stance === "contradicts" ? "text-st-contradicted" : s.stance === "supports" ? "text-st-confirmed" : "text-muted"}>
            {humanize(s.stance)}
          </span>
          {s.source_id ? (
            <Link href={`${path(inv.id, "sources")}/${s.source_id}`} className="text-xs text-primary hover:underline">
              {s.source_label} · {s.host}
            </Link>
          ) : (
            <span className="text-xs text-muted">image analysis</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function TransitionDialog({ rel, open, onOpenChange }: { rel: RelationshipDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const options = rel.allowed_transitions.filter((s) => s !== rel.verification_status);
  const [target, setTarget] = useState(options[0] ?? "");
  const [justification, setJustification] = useState("");
  const [attested, setAttested] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const change = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/relationships/{relationship_id}/transitions", {
          params: { path: { investigation_id: inv.id, relationship_id: rel.id } },
          body: {
            to_status: target as Status,
            justification: justification.trim(),
            evidence_ids: rel.evidence.filter((s) => s.stance !== "context").map((s) => s.evidence_id),
            independence_attested: attested,
          },
        }),
      ),
    onSuccess: () => {
      onOpenChange(false);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast("Relationship status recorded", { tone: "success" });
    },
    onError: (e) => setProblem(e instanceof ConflictError ? [e.message, ...(e.failedPreconditions[target] ?? [])].join(" ") : messageOf(e)),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Change relationship status"
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={change.isPending}
            disabled={!target || justification.trim().length < 20 || (target === "corroborated" && !attested)}
            onClick={() => change.mutate()}
          >
            Record decision
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {problem ? <Alert tone="danger">{problem}</Alert> : null}
        {options.length ? (
          <Field label="New status">
            {(props) => (
              <Select {...props} value={target} onChange={(e) => setTarget(e.target.value)}>
                {options.map((s) => (
                  <option key={s} value={s}>
                    {STATUS[s as Status]?.label ?? s}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <Alert tone="info">No status change is possible right now.</Alert>
        )}
        {Object.entries(rel.failed_preconditions).map(([status, reasons]) =>
          reasons.length ? (
            <p key={status} className="text-[13px] text-muted">
              <span className="font-medium">{STATUS[status as Status]?.label ?? status}:</span> {reasons.join(" ")}
            </p>
          ) : null,
        )}
        <Field label="Justification" required hint="At least 20 characters. The supporting evidence is cited automatically.">
          {(props) => <Textarea {...props} rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} />}
        </Field>
        {target === "corroborated" ? (
          <Checkbox label="I checked that the supporting sources are independent" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
        ) : null}
      </div>
    </Dialog>
  );
}

function EdgeInspector({ id }: { id: string }) {
  const { investigation: inv, can } = useInvestigation();
  const [open, setOpen] = useState(false);
  const { data, error, isPending } = useQuery({
    queryKey: ["investigations", inv.id, "relationship", id],
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/relationships/{relationship_id}", {
          params: { path: { investigation_id: inv.id, relationship_id: id } },
        }),
      ) as Promise<unknown> as Promise<RelationshipDetail>,
  });
  if (isPending) return <LoadingBlock />;
  if (error || !data) return <QueryError error={error} />;
  return (
    <div className="space-y-4">
      <p className="flex flex-wrap items-center gap-1.5 text-sm">
        <span className="font-medium">{data.from_entity?.name}</span>
        <ArrowRight className="h-3.5 w-3.5 text-muted" aria-hidden />
        <span className="font-mono text-xs text-muted">{REL_LABELS[data.rel_type] ?? data.rel_type}</span>
        <ArrowRight className="h-3.5 w-3.5 text-muted" aria-hidden />
        <span className="font-medium">{data.to_entity?.name}</span>
      </p>
      <div className="flex flex-wrap gap-1.5">
        <VerificationStatusBadge status={data.verification_status} size="sm" />
        <ProvenanceBadge provenance={data.provenance} size="sm" />
      </div>
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Supporting sources</h3>
        <SupportList support={data.evidence} />
      </section>
      {data.history.length ? (
        <section className="space-y-1.5">
          <h3 className="text-sm font-semibold">History</h3>
          <ul className="space-y-1 text-xs text-muted">
            {data.history.map((h, i) => (
              <li key={i}>
                {formatDateTime(h.created_at)}: {h.from_status ? `${humanize(h.from_status)} → ` : ""}
                {humanize(h.to_status)}
                {h.justification ? ` — “${h.justification}”` : ""}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {can("finding:verify") ? (
        <>
          <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
            Change status
          </Button>
          <TransitionDialog rel={data} open={open} onOpenChange={setOpen} />
        </>
      ) : null}
    </div>
  );
}

function NodeInspector({ id }: { id: string }) {
  const { investigation: inv } = useInvestigation();
  const { data, error, isPending } = useQuery({
    queryKey: ["investigations", inv.id, "entity", id],
    queryFn: () =>
      unwrap(api.GET("/api/v1/investigations/{investigation_id}/entities/{entity_id}", { params: { path: { investigation_id: inv.id, entity_id: id } } })),
  });
  if (isPending) return <LoadingBlock />;
  if (error || !data) return <QueryError error={error} />;
  const mentions = (data.mentions as unknown as { evidence_id: string; label: string }[]) ?? [];
  return (
    <div className="space-y-4">
      <p className="text-base font-medium">{data.name}</p>
      <DefinitionList
        items={[
          ["Type", ENTITY_LABELS[data.type] ?? data.type],
          ["Country", data.country ?? "—"],
          ["Location level", data.location_level ? humanize(data.location_level) : "—"],
          ["Public role basis", data.public_role_basis ?? "—"],
          ["Created by", humanize(data.created_via)],
          ["Relationships", data.relationship_count ?? 0],
        ]}
      />
      {data.type === "public_figure" ? (
        <Alert tone="info">Public figures appear only in their public role. Angel Engine records no private details about people.</Alert>
      ) : null}
      <section className="space-y-1.5">
        <h3 className="text-sm font-semibold">Mentioned in</h3>
        {mentions.length ? (
          <div className="flex flex-wrap gap-1">
            {mentions.map((m) => (
              <Link key={m.evidence_id} href={`${path(inv.id, "evidence")}?tab=items&evidence=${m.evidence_id}`}>
                <CitationChip label={m.label} />
              </Link>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">No evidence mentions recorded.</p>
        )}
      </section>
    </div>
  );
}

export function GraphInspector({ selection, onClose }: { selection: { kind: "node" | "edge"; id: string } | null; onClose: () => void }) {
  if (!selection) {
    return (
      <Card className="p-4 text-sm text-muted">
        Select an entity or a relationship to see its details and the sources that support it. Keyboard: Tab to an element, then press Enter.
      </Card>
    );
  }
  return (
    <Card className="p-4" aria-live="polite">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold">{selection.kind === "edge" ? "Relationship" : "Entity"}</h2>
        <Button size="icon" variant="ghost" aria-label="Close details" onClick={onClose}>
          <X className="h-4 w-4" aria-hidden />
        </Button>
      </div>
      {selection.kind === "edge" ? <EdgeInspector id={selection.id} /> : <NodeInspector id={selection.id} />}
    </Card>
  );
}
