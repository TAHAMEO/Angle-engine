"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CalendarClock, CalendarPlus, Trash2 } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { CitationChip, ProvenanceBadge, STATUS, VerificationStatusBadge } from "@/components/provenance/badges";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Tooltip } from "@/components/ui/menu";
import { ConfirmDialog, Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { EvidencePicker, type PickedEvidence } from "@/features/evidence/evidence-picker";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { EventOut, S } from "@/lib/api/types";
import { formatAtPrecision } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { DensityChart } from "./density-chart";
import { EVENT_KINDS, PRECISION_LABELS } from "./labels";

type Precision = NonNullable<S<"EventCreate">["precision"]>;
type Kind = NonNullable<S<"EventCreate">["kind"]>;
type EventStatus = S<"EventStatusIn">["to_status"];

function AddEventDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [title, setTitle] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [precision, setPrecision] = useState<Precision>("day");
  const [kind, setKind] = useState<Kind>("manual");
  const [description, setDescription] = useState("");
  const [links, setLinks] = useState<PickedEvidence[]>([]);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/timeline-events", {
          params: { path: { investigation_id: inv.id } },
          body: {
            title: title.trim(),
            occurred_start: new Date(`${start}T00:00:00Z`).toISOString(),
            occurred_end: end ? new Date(`${end}T00:00:00Z`).toISOString() : null,
            precision,
            kind,
            description: description.trim() || null,
            evidence_ids: links.map((l) => l.evidence_id),
          },
        }),
      ),
    onSuccess: () => {
      onOpenChange(false);
      setTitle("");
      setStart("");
      setEnd("");
      setDescription("");
      setLinks([]);
      void client.invalidateQueries({ queryKey: qk.timeline(inv.id) });
      toast("Event added", { tone: "success" });
    },
    onError: (e) => toast("The event was not added", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Add a timeline event"
      description="Every event cites at least one evidence item and records how precise its date is."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={title.trim().length < 3 || !start || !links.length} onClick={() => create.mutate()}>
            Add event
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Title" required>
          {(props) => <Input {...props} value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} />}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Date" required>{(props) => <Input {...props} type="date" value={start} onChange={(e) => setStart(e.target.value)} />}</Field>
          <Field label="End date (optional)">{(props) => <Input {...props} type="date" value={end} onChange={(e) => setEnd(e.target.value)} />}</Field>
          <Field label="Precision">
            {(props) => (
              <Select {...props} value={precision} onChange={(e) => setPrecision(e.target.value as Precision)}>
                {(["day", "month", "year", "approximate"] as const).map((p) => (
                  <option key={p} value={p}>
                    {PRECISION_LABELS[p]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Kind">
            {(props) => (
              <Select {...props} value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
                {Object.entries(EVENT_KINDS).map(([key, meta]) => (
                  <option key={key} value={key}>
                    {meta.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Field label="Description">{(props) => <Textarea {...props} rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">
            Evidence <span className="text-danger">*</span>
          </legend>
          <EvidencePicker value={links} onChange={setLinks} />
        </fieldset>
      </div>
    </Dialog>
  );
}

function EventStatusDialog({ event, onClose }: { event: EventOut | null; onClose: () => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [status, setStatus] = useState<EventStatus>("confirmed_by_source");
  const [justification, setJustification] = useState("");
  const change = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/timeline-events/{event_id}/status", {
          params: { path: { investigation_id: inv.id, event_id: event!.id } },
          body: { to_status: status, justification: justification.trim() },
        }),
      ),
    onSuccess: () => {
      onClose();
      setJustification("");
      void client.invalidateQueries({ queryKey: qk.timeline(inv.id) });
      toast("Event status recorded", { tone: "success" });
    },
    onError: (e) => toast("The status was not changed", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Dialog
      open={event !== null}
      onOpenChange={(open) => !open && onClose()}
      title="Change event status"
      description={event?.title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={change.isPending} disabled={justification.trim().length < 20} onClick={() => change.mutate()}>
            Record decision
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="New status">
          {(props) => (
            <Select {...props} value={status} onChange={(e) => setStatus(e.target.value as EventStatus)}>
              {(["confirmed_by_source", "unverified", "contradicted", "ai_hypothesis"] as const)
                .filter((s) => s !== event?.verification_status)
                .map((s) => (
                  <option key={s} value={s}>
                    {STATUS[s].label}
                  </option>
                ))}
            </Select>
          )}
        </Field>
        <Field label="Justification" required hint="At least 20 characters.">
          {(props) => <Textarea {...props} rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}

function EventItem({ event, onStatus, onDelete }: { event: EventOut; onStatus: () => void; onDelete: () => void }) {
  const { investigation: inv, can } = useInvestigation();
  const kind = EVENT_KINDS[event.kind];
  return (
    <li className="relative rounded-lg border border-border bg-surface p-3.5">
      <span
        aria-hidden
        className={`absolute top-4 -left-[1.62rem] h-3 w-3 rounded-full border-2 border-background ${event.verification_status === "contradicted" ? "bg-st-contradicted" : event.provenance === "ai_hypothesis" ? "bg-st-ai" : "bg-primary"}`}
      />
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[13px] font-semibold">{formatAtPrecision(event.occurred_start, event.precision)}</span>
        {event.occurred_end ? <span className="font-mono text-[13px] text-muted">– {formatAtPrecision(event.occurred_end, event.precision)}</span> : null}
        <Tooltip content={`Date precision: ${PRECISION_LABELS[event.precision] ?? event.precision}`}>
          <span tabIndex={0}>
            <Badge>{PRECISION_LABELS[event.precision] ?? event.precision}</Badge>
          </span>
        </Tooltip>
        <Badge>{kind?.label ?? event.kind}</Badge>
        {event.verification_status === "contradicted" ? (
          <span className="inline-flex items-center gap-1 text-xs text-st-contradicted">
            <AlertTriangle className="h-3 w-3" aria-hidden /> Contradicted
          </span>
        ) : null}
      </div>
      <p className="mt-1.5 font-medium">{event.title}</p>
      {event.description ? <p className="mt-1 text-sm text-muted">{event.description}</p> : null}
      <p className="mt-1 text-xs text-muted">Date basis: {kind?.basis ?? "Reported by the cited sources."}</p>
      {event.caveat ? <p className="mt-1 text-xs text-warning">{event.caveat}</p> : null}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <VerificationStatusBadge status={event.verification_status} size="sm" />
        <ProvenanceBadge provenance={event.provenance} size="sm" />
        {(event.evidence_labels ?? []).map((label, index) => (
          <Link key={label} href={`${path(inv.id, "evidence")}?tab=items&evidence=${event.evidence_ids[index]}`}>
            <CitationChip label={label} />
          </Link>
        ))}
        {event.finding_id ? (
          <Link href={`${path(inv.id, "evidence")}?finding=${event.finding_id}`} className="font-mono text-xs text-primary hover:underline">
            {event.finding_label ?? "Finding"}
          </Link>
        ) : null}
        {can("finding:verify") ? (
          <Button size="sm" variant="ghost" className="ml-auto" onClick={onStatus}>
            Change status
          </Button>
        ) : null}
        {can("content:write") && event.created_via === "manual" ? (
          <Button size="sm" variant="ghost" aria-label={`Delete event ${event.title}`} onClick={onDelete}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </Button>
        ) : null}
      </div>
    </li>
  );
}

export function TimelinePage() {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [range, setRange] = useState<{ from: string | null; to: string | null }>({ from: null, to: null });
  const [adding, setAdding] = useState(false);
  const [statusEvent, setStatusEvent] = useState<EventOut | null>(null);
  const [deleting, setDeleting] = useState<EventOut | null>(null);
  const filters = { kind, status };
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.timeline(inv.id, filters),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/timeline-events", {
          params: { path: { investigation_id: inv.id }, query: { kind: kind ? [kind] : undefined, status: status ? [status as S<"VerificationStatus">] : undefined } },
        }),
      ),
  });
  const remove = useMutation({
    mutationFn: (eventId: string) =>
      unwrap(api.DELETE("/api/v1/investigations/{investigation_id}/timeline-events/{event_id}", { params: { path: { investigation_id: inv.id, event_id: eventId } } })),
    onSuccess: () => {
      setDeleting(null);
      void client.invalidateQueries({ queryKey: qk.timeline(inv.id) });
    },
    onError: (e) => toast("Could not delete the event", { description: messageOf(e), tone: "danger" }),
  });
  const visible = useMemo(() => {
    const events = [...(data ?? [])].sort((a, b) => a.occurred_start.localeCompare(b.occurred_start));
    return events.filter((e) => {
      const day = e.occurred_start.slice(0, 10);
      return (!range.from || day >= range.from) && (!range.to || day <= range.to);
    });
  }, [data, range]);
  const groups = useMemo(() => {
    const out = new Map<string, EventOut[]>();
    for (const event of visible) {
      const key = new Date(event.occurred_start).toISOString().slice(0, 4);
      out.set(key, [...(out.get(key) ?? []), event]);
    }
    return [...out.entries()];
  }, [visible]);

  return (
    <>
      <PageHeader
        title="Timeline"
        description="Dated events from metadata, publications, archives and registries — each with its date precision, the basis of the date and the evidence behind it."
        actions={
          can("content:write") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <CalendarPlus className="h-4 w-4" aria-hidden /> Add event
            </Button>
          ) : undefined
        }
      />
      <div className="space-y-5">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Kind</span>
            <Select value={kind} onChange={(e) => setKind(e.target.value)} className="w-56">
              <option value="">All kinds</option>
              {Object.entries(EVENT_KINDS).map(([key, meta]) => (
                <option key={key} value={key}>
                  {meta.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Status</span>
            <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-48">
              <option value="">All statuses</option>
              {Object.entries(STATUS).map(([key, meta]) => (
                <option key={key} value={key}>
                  {meta.label}
                </option>
              ))}
            </Select>
          </label>
          {range.from || range.to ? (
            <p className="text-sm text-muted" role="status">
              Showing {range.from ?? "start"} to {range.to ?? "end"}
            </p>
          ) : null}
        </div>
        {isPending ? (
          <LoadingBlock />
        ) : error ? (
          <QueryError error={error} retry={() => void refetch()} />
        ) : data?.length ? (
          <>
            <DensityChart events={data} onRange={(from, to) => setRange({ from, to })} />
            {groups.map(([year, events]) => (
              <section key={year} aria-labelledby={`year-${year}`} className="space-y-2">
                <h2 id={`year-${year}`} className="text-sm font-semibold text-muted">
                  {year} <span className="font-normal">({events.length})</span>
                </h2>
                <ol className="relative space-y-2 pl-6 before:absolute before:top-2 before:bottom-2 before:left-1.5 before:w-px before:bg-border">
                  {events.map((event) => (
                    <EventItem key={event.id} event={event} onStatus={() => setStatusEvent(event)} onDelete={() => setDeleting(event)} />
                  ))}
                </ol>
              </section>
            ))}
          </>
        ) : (
          <Card className="p-4">
            <EmptyState icon={CalendarClock} title="No dated events yet">
              Capture times from image metadata, publication dates, first archive snapshots and registrations appear here automatically.
            </EmptyState>
          </Card>
        )}
      </div>
      {can("content:write") ? <AddEventDialog open={adding} onOpenChange={setAdding} /> : null}
      <EventStatusDialog event={statusEvent} onClose={() => setStatusEvent(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete this event?"
        description={deleting?.title}
        confirmLabel="Delete"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </>
  );
}
