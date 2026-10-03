"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, CircleSlash, FilePlus2, Search, Sparkles } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { ProvenanceBadge } from "@/components/provenance/badges";
import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/data";
import { EmptyState, Spinner } from "@/components/ui/feedback";
import { Field, Select, Textarea } from "@/components/ui/form";
import { Tooltip } from "@/components/ui/menu";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import type { ClueOut, ImageDetail } from "@/lib/api/types";
import { humanize } from "@/lib/format";
import { newIdempotencyKey } from "@/lib/ids";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { CLUE_LABELS, CLUE_SOURCES } from "./status";

function PivotDialog({ clue, open, onOpenChange }: { clue: ClueOut; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [connectorId, setConnectorId] = useState(clue.pivots[0]?.connector_id ?? "");
  const [note, setNote] = useState("");
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const option = clue.pivots.find((p) => p.connector_id === connectorId);
  const pivot = useMutation({
    mutationFn: (acknowledge: boolean) =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/images/{image_id}/clues/{clue_id}/pivot", {
          params: { path: { investigation_id: inv.id, image_id: clue.image_id, clue_id: clue.id } },
          body: { connector_id: connectorId, purpose_note: note || null, acknowledge_policy_notices: acknowledge },
        }),
      ),
    onSuccess: (run) => {
      onOpenChange(false);
      setPolicy(null);
      void client.invalidateQueries({ queryKey: qk.runs(inv.id) });
      toast(run.status === "pending_review" ? "Search sent for supervisor review" : "Collection started", {
        description: `${option?.name ?? "Connector"}: results appear under Sources.`,
        tone: "success",
      });
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError || error instanceof PolicyAcknowledgementError) setPolicy(error.policy);
      else toast("The search did not start", { description: messageOf(error), tone: "danger" });
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Search public sources for this clue"
      description={
        <>
          <span className="font-mono">{clue.value}</span> — nothing is searched until you choose a connector and start it.
        </>
      }
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={pivot.isPending} disabled={!connectorId || Boolean(option?.needs_purpose_note && note.trim().length < 10)} onClick={() => pivot.mutate(false)}>
            <Search className="h-4 w-4" aria-hidden /> Start search
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Connector">
          {(props) => (
            <Select {...props} value={connectorId} onChange={(event) => setConnectorId(event.target.value)}>
              {clue.pivots.map((p) => (
                <option key={p.connector_id} value={p.connector_id}>
                  {p.name} ({humanize(p.input_type)})
                </option>
              ))}
            </Select>
          )}
        </Field>
        {option?.needs_purpose_note ? (
          <Field label="Why do you need this lookup?" required hint="Username lookups need a recorded purpose (at least 10 characters).">
            {(props) => <Textarea {...props} rows={2} value={note} onChange={(event) => setNote(event.target.value)} />}
          </Field>
        ) : null}
        {policy ? <PolicyDecisionPanel policy={policy} onAcknowledge={policy.decision === "warn" ? () => pivot.mutate(true) : undefined} acknowledging={pivot.isPending} /> : null}
      </div>
    </Dialog>
  );
}

function ClueRow({ clue, canWrite }: { clue: ClueOut; canWrite: boolean }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [pivotOpen, setPivotOpen] = useState(false);
  const promote = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/images/{image_id}/clues/{clue_id}/promote", {
          params: { path: { investigation_id: inv.id, image_id: clue.image_id, clue_id: clue.id } },
          body: {},
        }),
      ),
    onSuccess: (result) => {
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast(`Recorded as ${result.evidence_label} and ${result.finding_label}`, {
        description: "The finding starts as unverified until a person verifies it.",
        tone: "success",
      });
    },
    onError: (error) => toast("Could not record the clue", { description: messageOf(error), tone: "danger" }),
  });
  const searchable = clue.pivots.length > 0;
  return (
    <li className="flex flex-col gap-2 rounded-md border border-border p-3 sm:flex-row sm:items-start">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge>{CLUE_LABELS[clue.type] ?? humanize(clue.type)}</Badge>
          <ProvenanceBadge provenance={clue.provenance} size="sm" />
          {clue.platform ? <Badge>{clue.platform}</Badge> : null}
        </div>
        <p className="font-mono text-[13px] break-all">{clue.value}</p>
        <p className="text-xs text-muted">
          {CLUE_SOURCES[clue.source] ?? humanize(clue.source)} · confidence {clue.confidence}
          {clue.confidence_basis ? ` (${clue.confidence_basis})` : ""}
          {clue.precision ? ` · precision: ${clue.precision}` : ""}
        </p>
      </div>
      {canWrite ? (
        <div className="flex shrink-0 flex-wrap gap-1.5">
          {clue.promoted_evidence_id ? (
            <Button asChild size="sm" variant="ghost">
              <Link href={`${path(inv.id, "evidence")}?tab=items&evidence=${clue.promoted_evidence_id}`}>
                <ArrowUpRight className="h-3.5 w-3.5" aria-hidden /> View evidence
              </Link>
            </Button>
          ) : (
            <Button size="sm" variant="outline" loading={promote.isPending} onClick={() => promote.mutate()}>
              <FilePlus2 className="h-3.5 w-3.5" aria-hidden /> Record as evidence
            </Button>
          )}
          {searchable ? (
            <Button size="sm" variant="outline" onClick={() => setPivotOpen(true)}>
              <Search className="h-3.5 w-3.5" aria-hidden /> Search sources
            </Button>
          ) : (
            <Tooltip content={clue.type === "object" || clue.type === "date" || clue.type === "exif_field" ? "This kind of clue is not searchable." : "No connector accepts this clue here."}>
              <span tabIndex={0} className="inline-flex h-8 items-center gap-1 px-2 text-[13px] text-subtle">
                <CircleSlash className="h-3.5 w-3.5" aria-hidden /> Not searchable
              </span>
            </Tooltip>
          )}
        </div>
      ) : null}
      {searchable ? <PivotDialog clue={clue} open={pivotOpen} onOpenChange={setPivotOpen} /> : null}
    </li>
  );
}

export function CluesPanel({ image }: { image: ImageDetail }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const { data, isPending } = useQuery({
    queryKey: qk.clues(inv.id, image.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/images/{image_id}/clues", {
          params: { path: { investigation_id: inv.id, image_id: image.id } },
        }),
      ),
  });
  const vision = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/assistant/requests", {
          params: { path: { investigation_id: inv.id }, header: { "idempotency-key": newIdempotencyKey() } },
          body: { task: "vision_clues", image_id: image.id },
        }),
      ),
    onSuccess: () => {
      toast("AI vision request sent", { description: "Suggested clues appear here as AI hypotheses when it completes." });
      window.setTimeout(() => void client.invalidateQueries({ queryKey: qk.clues(inv.id, image.id) }), 4000);
    },
    onError: (error) => toast("AI vision is not available for this image", { description: messageOf(error), tone: "danger" }),
  });
  const visionAllowed = inv.ai_enabled && image.reverse_search.allowed && can("content:write");
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        Clues are suggestions extracted from the image. Nothing is searched automatically — record a clue as evidence or start a search
        yourself.
      </p>
      {visionAllowed ? (
        <Button size="sm" variant="outline" loading={vision.isPending} onClick={() => vision.mutate()}>
          <Sparkles className="h-3.5 w-3.5" aria-hidden /> Suggest more clues with AI (logos, landmarks, signs)
        </Button>
      ) : null}
      {isPending ? (
        <Spinner />
      ) : data?.length ? (
        <ul className="space-y-2">
          {data.map((clue) => (
            <ClueRow key={clue.id} clue={clue} canWrite={can("content:write")} />
          ))}
        </ul>
      ) : (
        <EmptyState title="No clues found" />
      )}
    </div>
  );
}
