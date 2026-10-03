"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Ban, Link2, ListPlus, ShieldCheck, Trash2, Undo2 } from "lucide-react";
import { useState } from "react";

import { ConfidenceLevel, ProvenanceBadge, VerificationStatusBadge } from "@/components/provenance/badges";
import { ExternalLink } from "@/components/security/external-link";
import { Button } from "@/components/ui/button";
import { DefinitionList } from "@/components/ui/data";
import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Field, Textarea } from "@/components/ui/form";
import { Dialog, Sheet } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { NotesPanel } from "@/features/notes/notes-panel";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { EvidenceOut, FindingDetail } from "@/lib/api/types";
import { CATEGORY_NAMES, formatAtPrecision, formatDateTime, humanize } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { cn } from "@/lib/utils";

import { EvidencePicker, type PickedEvidence } from "./evidence-picker";
import { STANCES } from "./labels";
import { StatusChangeDialog } from "./status-change-dialog";

function useFinding(investigationId: string, findingId: string | null) {
  return useQuery({
    queryKey: qk.finding(investigationId, findingId ?? ""),
    enabled: Boolean(findingId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/findings/{finding_id}", {
          params: { path: { investigation_id: investigationId, finding_id: findingId ?? "" } },
        }),
      ),
  });
}

function ReasonDialog({
  open,
  onOpenChange,
  title,
  description,
  label,
  minLength,
  confirm,
  loading,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  label: string;
  minLength: number;
  confirm: string;
  loading: boolean;
  onSubmit: (text: string) => void;
}) {
  const [text, setText] = useState("");
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={loading} disabled={text.trim().length < minLength} onClick={() => onSubmit(text.trim())}>
            {confirm}
          </Button>
        </>
      }
    >
      <Field label={label} required hint={`At least ${minLength} characters.`}>
        {(props) => <Textarea {...props} rows={3} value={text} onChange={(e) => setText(e.target.value)} />}
      </Field>
    </Dialog>
  );
}

function LinkList({ finding, onOpenEvidence }: { finding: FindingDetail; onOpenEvidence: (id: string) => void }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const writable = can("content:write");
  const [dismissing, setDismissing] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [picked, setPicked] = useState<PickedEvidence[]>([]);
  const refresh = (updated: FindingDetail) => {
    client.setQueryData(qk.finding(inv.id, finding.id), updated);
    void client.invalidateQueries({ queryKey: qk.findings(inv.id) });
  };
  const linkParams = (linkId: string) => ({ path: { investigation_id: inv.id, finding_id: finding.id, link_id: linkId } });
  const toggle = useMutation({
    mutationFn: ({ linkId, value }: { linkId: string; value: boolean }) =>
      unwrap(api.PATCH("/api/v1/investigations/{investigation_id}/findings/{finding_id}/evidence-links/{link_id}", { params: linkParams(linkId), body: { directly_states: value } })),
    onSuccess: refresh,
    onError: (e) => toast("Could not update the link", { description: messageOf(e), tone: "danger" }),
  });
  const remove = useMutation({
    mutationFn: (linkId: string) =>
      unwrap(api.DELETE("/api/v1/investigations/{investigation_id}/findings/{finding_id}/evidence-links/{link_id}", { params: linkParams(linkId) })),
    onSuccess: refresh,
    onError: (e) => toast("Could not remove the link", { description: messageOf(e), tone: "danger" }),
  });
  const dismiss = useMutation({
    mutationFn: ({ linkId, reason }: { linkId: string; reason: string }) =>
      unwrap(api.POST("/api/v1/investigations/{investigation_id}/findings/{finding_id}/evidence-links/{link_id}/dismiss", { params: linkParams(linkId), body: { reason } })),
    onSuccess: (updated) => {
      setDismissing(null);
      refresh(updated);
      toast("Contradiction dismissed", { description: "The reason is kept in the finding's record." });
    },
    onError: (e) => toast("Could not dismiss", { description: messageOf(e), tone: "danger" }),
  });
  const add = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/findings/{finding_id}/evidence-links", {
          params: { path: { investigation_id: inv.id, finding_id: finding.id } },
          body: { links: picked.map(({ evidence_id, stance, directly_states }) => ({ evidence_id, stance, directly_states })) },
        }),
      ),
    onSuccess: (updated) => {
      setAdding(false);
      setPicked([]);
      refresh(updated);
    },
    onError: (e) => toast("Could not link the evidence", { description: messageOf(e), tone: "danger" }),
  });
  const linkedIds = finding.links.map((l) => String((l.evidence as { id: string }).id));
  return (
    <section aria-labelledby="links-heading" className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 id="links-heading" className="text-sm font-semibold">
          Evidence ({finding.links.length})
        </h3>
        {writable ? (
          <Button size="sm" variant="ghost" onClick={() => setAdding(true)}>
            <ListPlus className="h-3.5 w-3.5" aria-hidden /> Link evidence
          </Button>
        ) : null}
      </div>
      <ul className="space-y-2">
        {finding.links.map((link) => {
          const ev = link.evidence as unknown as EvidenceOut;
          return (
            <li key={link.id} className={cn("space-y-1.5 rounded-md border border-border p-3 text-sm", link.dismissed && "opacity-70")}>
              <div className="flex flex-wrap items-center gap-1.5">
                <button type="button" onClick={() => onOpenEvidence(ev.id)} className="font-mono text-xs font-semibold text-primary underline underline-offset-2 hover:decoration-2">
                  {ev.label}
                </button>
                <span className={cn("badge rounded-sm border px-1 text-[11px] font-medium", STANCES[link.stance]?.className)}>{STANCES[link.stance]?.label ?? link.stance}</span>
                {link.directly_states ? <span className="text-[11px] text-success">States it directly</span> : null}
                {link.dismissed ? <span className="text-[11px] text-muted">Dismissed</span> : null}
                <ProvenanceBadge provenance={ev.provenance} size="sm" />
              </div>
              {link.source ? (
                <p className="text-xs text-muted">
                  {link.source.label} · <ExternalLink href={link.source.url} className="text-xs" /> · captured {formatDateTime(ev.captured_at)}
                </p>
              ) : (
                <p className="text-xs text-muted">Captured {formatDateTime(ev.captured_at)}</p>
              )}
              {ev.excerpt_hidden ? (
                <p className="text-[13px] text-muted italic">Excerpt hidden (flagged as sensitive).</p>
              ) : ev.excerpt ? (
                <blockquote className="line-clamp-4 border-l-2 border-border-strong pl-2.5 text-[13px] whitespace-pre-line">{ev.excerpt}</blockquote>
              ) : null}
              {link.dismissed_reason ? <p className="text-xs text-muted">Dismissed: {link.dismissed_reason}</p> : null}
              {writable && !link.dismissed ? (
                <div className="flex flex-wrap gap-1 pt-1">
                  {link.stance === "supports" ? (
                    <Button size="sm" variant="ghost" onClick={() => toggle.mutate({ linkId: link.id, value: !link.directly_states })}>
                      <ShieldCheck className="h-3.5 w-3.5" aria-hidden /> {link.directly_states ? "Does not state it directly" : "States it directly"}
                    </Button>
                  ) : null}
                  {link.stance === "contradicts" ? (
                    <Button size="sm" variant="ghost" onClick={() => setDismissing(link.id)}>
                      <Ban className="h-3.5 w-3.5" aria-hidden /> Dismiss contradiction
                    </Button>
                  ) : null}
                  <Button size="sm" variant="ghost" onClick={() => remove.mutate(link.id)}>
                    <Trash2 className="h-3.5 w-3.5" aria-hidden /> Unlink
                  </Button>
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
      <ReasonDialog
        open={dismissing !== null}
        onOpenChange={(open) => !open && setDismissing(null)}
        title="Dismiss this contradiction"
        description="Explain why this source does not actually contradict the finding (for example a different definition or date basis)."
        label="Reason"
        minLength={10}
        confirm="Dismiss"
        loading={dismiss.isPending}
        onSubmit={(reason) => dismissing && dismiss.mutate({ linkId: dismissing, reason })}
      />
      <Dialog
        open={adding}
        onOpenChange={setAdding}
        className="max-w-2xl"
        title={`Link evidence to ${finding.label}`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setAdding(false)}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!picked.length} loading={add.isPending} onClick={() => add.mutate()}>
              <Link2 className="h-4 w-4" aria-hidden /> Link {picked.length || ""}
            </Button>
          </>
        }
      >
        <EvidencePicker value={picked} onChange={setPicked} exclude={linkedIds} />
      </Dialog>
    </section>
  );
}

function History({ finding }: { finding: FindingDetail }) {
  return (
    <section aria-labelledby="history-heading" className="space-y-2">
      <h3 id="history-heading" className="text-sm font-semibold">
        Provenance trail
      </h3>
      <ol className="space-y-2 border-l border-border pl-4">
        {finding.history.map((entry, index) => (
          <li key={index} className="relative text-sm">
            <span aria-hidden className="absolute top-1.5 -left-[1.3rem] h-2 w-2 rounded-full bg-border-strong" />
            <p className="flex flex-wrap items-center gap-1.5">
              {entry.from_status ? <VerificationStatusBadge status={entry.from_status} size="sm" /> : <span className="text-xs text-muted">Created as</span>}
              {entry.from_status ? <ArrowRight className="h-3 w-3 text-muted" aria-label="to" /> : null}
              <VerificationStatusBadge status={entry.to_status} size="sm" />
            </p>
            <p className="text-xs text-muted">
              {formatDateTime(entry.created_at)} ·{" "}
              {!entry.from_status
                ? entry.actor_name
                  ? `Recorded by ${entry.actor_name}`
                  : "Recorded automatically from collected evidence"
                : entry.automatic
                  ? "Automatic (its preconditions no longer held)"
                  : (entry.actor_name ?? "Former member")}
              {entry.evidence_ids.length ? ` · cites ${entry.evidence_ids.length} evidence item${entry.evidence_ids.length === 1 ? "" : "s"}` : ""}
            </p>
            {entry.justification ? <p className="mt-0.5 text-[13px]">“{entry.justification}”</p> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

export function FindingDrawer({ findingId, onClose, onOpenEvidence }: { findingId: string | null; onClose: () => void; onOpenEvidence: (id: string) => void }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const { data: finding, error, isPending, refetch } = useFinding(inv.id, findingId);
  const [statusOpen, setStatusOpen] = useState(false);
  const [retracting, setRetracting] = useState(false);
  const retract = useMutation({
    mutationFn: (justification: string) =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/findings/{finding_id}/retract", {
          params: { path: { investigation_id: inv.id, finding_id: findingId ?? "" }, header: { "if-match": `"${finding?.version ?? 0}"` } },
          body: { justification },
        }),
      ),
    onSuccess: (updated) => {
      setRetracting(false);
      client.setQueryData(qk.finding(inv.id, updated.id), updated);
      void client.invalidateQueries({ queryKey: qk.findings(inv.id) });
      toast(`${updated.label} retracted`);
    },
    onError: (e) => toast("Could not retract", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Sheet
      open={Boolean(findingId)}
      onOpenChange={(open) => !open && onClose()}
      className="sm:max-w-2xl"
      title={finding ? `Finding ${finding.label}` : "Finding"}
      description={finding ? CATEGORY_NAMES[finding.category] ?? humanize(finding.category) : undefined}
    >
      {isPending ? (
        <LoadingBlock />
      ) : error || !finding ? (
        <div className="p-5">
          <QueryError error={error} retry={() => void refetch()} />
        </div>
      ) : (
        <div className="space-y-6 p-5">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <VerificationStatusBadge status={finding.verification_status} />
              <ProvenanceBadge provenance={finding.provenance} />
              {finding.retracted ? <span className="text-xs text-muted">Retracted</span> : null}
            </div>
            <p className={cn("text-base leading-relaxed", finding.retracted && "text-muted line-through")}>{finding.statement}</p>
            {finding.provenance === "ai_hypothesis" ? (
              <Alert tone="info">This claim came from AI. It keeps its AI label permanently, even if people verify it.</Alert>
            ) : null}
            {finding.evidence_removed ? <Alert tone="warning">Evidence this finding relied on was deleted. Review its status.</Alert> : null}
            <div className="flex flex-wrap gap-2">
              {can("finding:verify") && !finding.retracted ? (
                <Button variant="primary" size="sm" onClick={() => setStatusOpen(true)}>
                  Change status
                </Button>
              ) : null}
              {can("content:write") && !finding.retracted ? (
                <Button variant="ghost" size="sm" onClick={() => setRetracting(true)}>
                  <Undo2 className="h-3.5 w-3.5" aria-hidden /> Retract
                </Button>
              ) : null}
            </div>
          </div>
          <DefinitionList
            items={[
              ["Source", finding.source ? `${finding.source.label} · ${finding.source.host}` : "—"],
              ["Confidence", <ConfidenceLevel key="c" confidence={finding.sensitive ? null : finding.confidence} />],
              ["Importance", finding.importance === "key" ? "Key finding" : "Normal"],
              ["Event time", finding.timestamps.event_time ? formatAtPrecision(finding.timestamps.event_time, finding.timestamps.event_precision) : "—"],
              ["Captured", formatDateTime(finding.timestamps.captured_at)],
              ["Published", formatDateTime(finding.timestamps.published_at)],
              ["Status changed", formatDateTime(finding.timestamps.status_changed_at)],
              ["Created", formatDateTime(finding.timestamps.created_at)],
            ]}
          />
          <LinkList finding={finding} onOpenEvidence={onOpenEvidence} />
          <History finding={finding} />
          <section aria-labelledby="finding-notes" className="space-y-2">
            <h3 id="finding-notes" className="text-sm font-semibold">
              Notes
            </h3>
            <NotesPanel targetType="finding" targetId={finding.id} />
          </section>
          {statusOpen ? <StatusChangeDialog finding={finding} open={statusOpen} onOpenChange={setStatusOpen} /> : null}
          <ReasonDialog
            open={retracting}
            onOpenChange={setRetracting}
            title={`Retract ${finding.label}?`}
            description="Retracted findings stay in the record (struck through) with your reason, and are excluded from reports."
            label="Reason"
            minLength={20}
            confirm="Retract"
            loading={retract.isPending}
            onSubmit={(text) => retract.mutate(text)}
          />
        </div>
      )}
    </Sheet>
  );
}
