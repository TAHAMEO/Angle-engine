"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Inbox, RotateCw, Save, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { describeAction } from "@/features/activity/activity-page";
import { NotFoundOrNoAccess, QueryError } from "@/features/common/states";
import { ConnectorCatalog } from "@/features/sources/connectors";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { formatDateTime, humanize } from "@/lib/format";

import { useRole } from "./admin-nav";

// ---------------------------------------------------------------------------------------------- connectors
export function AdminConnectors() {
  const role = useRole();
  const { data, isPending } = useQuery({ queryKey: ["admin", "connectors"], queryFn: () => unwrap(api.GET("/api/v1/connectors")), enabled: role === "admin" });
  if (role && role !== "admin") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Connectors"
        description="Which public-source connectors are ready. Keyed connectors (Brave Search, TinEye, Google Cloud Vision) are configured with server-side secrets."
      />
      <ConnectorCatalog connectors={data} loading={isPending} />
    </>
  );
}

// ---------------------------------------------------------------------------------------------- retention
const RETENTION_LABELS: Record<string, { label: string; unit: string }> = {
  image_original_hours: { label: "Uploaded image originals (default)", unit: "hours after analysis" },
  image_original_max_hours: { label: "Uploaded image originals (maximum per investigation)", unit: "hours" },
  draft_inactive_days: { label: "Inactive draft investigations", unit: "days" },
  refused_investigation_days: { label: "Refused investigation text", unit: "days" },
  closed_archive_days: { label: "Archive closed investigations after", unit: "days" },
  closed_delete_days: { label: "Delete closed investigations after", unit: "days" },
  ai_transcript_days: { label: "AI transcripts", unit: "days" },
  policy_text_days: { label: "Screened request text", unit: "days" },
  audit_days: { label: "Audit log", unit: "days" },
  abuse_report_days: { label: "Abuse reports", unit: "days" },
  export_hours: { label: "Report exports", unit: "hours" },
};

export function AdminRetention() {
  const role = useRole();
  const client = useQueryClient();
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "retention"],
    queryFn: () => unwrap(api.GET("/api/v1/admin/settings/retention")),
    enabled: role === "admin",
  });
  const [draft, setDraft] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PATCH("/api/v1/admin/settings/retention", {
          body: Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, v === "" ? null : Number(v)])) as Record<string, number>,
        }),
      ),
    onSuccess: (result) => {
      client.setQueryData(["admin", "retention"], result);
      setDraft({});
      toast("Retention settings saved", { tone: "success" });
    },
    onError: (e) => toast("Settings were not saved", { description: messageOf(e), tone: "danger" }),
  });
  if (role && role !== "admin") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Retention"
        description="Platform-wide retention periods. Purges run hourly; legal holds pause deletion. Leave a field empty to return to the default."
      />
      {isPending ? (
        <LoadingBlock />
      ) : error || !data ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate();
          }}
          className="space-y-4"
        >
          <Table caption="Retention settings" className="rounded-lg border border-border">
            <thead>
              <tr>
                <Th>Data</Th>
                <Th>Current</Th>
                <Th>Default</Th>
                <Th>Allowed</Th>
                <Th>New value</Th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.values).map(([key, value]) => {
                const meta = RETENTION_LABELS[key] ?? { label: humanize(key), unit: "" };
                const bounds = data.bounds[key] as unknown as [number, number] | undefined;
                return (
                  <tr key={key}>
                    <Td>
                      {meta.label}
                      {data.overridden.includes(key) ? <Badge className="ml-1.5">Overridden</Badge> : null}
                    </Td>
                    <Td className="tabular">
                      {value} {meta.unit}
                    </Td>
                    <Td className="tabular text-muted">{data.defaults[key]}</Td>
                    <Td className="tabular text-muted">{bounds ? `${bounds[0]}–${bounds[1]}` : "—"}</Td>
                    <Td>
                      <Input
                        type="number"
                        aria-label={`New value for ${meta.label}`}
                        className="h-8 w-28"
                        min={bounds?.[0]}
                        max={bounds?.[1]}
                        value={draft[key] ?? ""}
                        placeholder={String(value)}
                        onChange={(e) => setDraft((d) => ({ ...d, [key]: e.target.value }))}
                      />
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!Object.keys(draft).length}>
            <Save className="h-4 w-4" aria-hidden /> Save changes
          </Button>
        </form>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------------------------- abuse reports
type AbuseStatus = S<"AbuseStatus">;

function TriageDialog({ report, onClose }: { report: S<"AbuseReportOut"> | null; onClose: () => void }) {
  const client = useQueryClient();
  const [status, setStatus] = useState<AbuseStatus>("triaging");
  const [note, setNote] = useState("");
  const save = useMutation({
    mutationFn: () =>
      unwrap(api.PATCH("/api/v1/admin/abuse-reports/{report_id}", { params: { path: { report_id: report!.id } }, body: { status, triage_note: note.trim() || null } })),
    onSuccess: () => {
      onClose();
      setNote("");
      void client.invalidateQueries({ queryKey: ["admin", "abuse"] });
      toast("Report updated", { tone: "success" });
    },
    onError: (e) => toast("The report was not updated", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Dialog
      open={report !== null}
      onOpenChange={(open) => !open && onClose()}
      className="max-w-2xl"
      title="Triage report"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
            Save
          </Button>
        </>
      }
    >
      {report ? (
        <div className="space-y-4 text-sm">
          <p className="rounded-md border border-border bg-surface-2/50 p-3 whitespace-pre-line">{report.description}</p>
          <p className="text-muted">
            Category: {humanize(report.category)} · target: {report.target_ref ?? "—"} · contact: {report.contact ?? "none given"}
          </p>
          {report.triage_notes ? <p className="text-muted whitespace-pre-line">Earlier notes: {report.triage_notes}</p> : null}
          <Field label="Status">
            {(props) => (
              <Select {...props} value={status} onChange={(e) => setStatus(e.target.value as AbuseStatus)}>
                <option value="triaging">Triaging</option>
                <option value="actioned">Actioned</option>
                <option value="dismissed">Dismissed</option>
                <option value="new">New</option>
              </Select>
            )}
          </Field>
          <Field label="Triage note">{(props) => <Textarea {...props} rows={3} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
        </div>
      ) : null}
    </Dialog>
  );
}

export function AdminAbuseReports() {
  const role = useRole();
  const [status, setStatus] = useState<AbuseStatus | "">("new");
  const [open, setOpen] = useState<S<"AbuseReportOut"> | null>(null);
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "abuse", status],
    queryFn: () => unwrap(api.GET("/api/v1/admin/abuse-reports", { params: { query: { status: status || undefined } } })),
    enabled: role === "admin" || role === "supervisor",
  });
  if (role && role !== "admin" && role !== "supervisor") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Abuse reports"
        description="Reports from the public form and from users: people who believe they are targeted, data-removal requests, misuse and vulnerabilities."
      />
      <label className="mb-4 inline-flex items-center gap-2 text-sm">
        <span className="font-medium">Status</span>
        <Select value={status} onChange={(e) => setStatus(e.target.value as AbuseStatus | "")} className="h-8 w-40">
          <option value="">All</option>
          <option value="new">New</option>
          <option value="triaging">Triaging</option>
          <option value="actioned">Actioned</option>
          <option value="dismissed">Dismissed</option>
        </Select>
      </label>
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.length ? (
        <Table caption="Abuse reports" className="rounded-lg border border-border">
          <thead>
            <tr>
              <Th>Received</Th>
              <Th>Category</Th>
              <Th>Summary</Th>
              <Th>Status</Th>
              <Th><span className="sr-only">Open</span></Th>
            </tr>
          </thead>
          <tbody>
            {data.map((r) => (
              <tr key={r.id}>
                <Td className="whitespace-nowrap">{formatDateTime(r.created_at)}</Td>
                <Td>{humanize(r.category)}</Td>
                <Td className="max-w-md">
                  <span className="line-clamp-2">{r.description}</span>
                </Td>
                <Td>
                  <Badge>{humanize(r.status)}</Badge>
                </Td>
                <Td>
                  <Button size="sm" variant="secondary" onClick={() => setOpen(r)}>
                    Triage
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <EmptyState icon={Inbox} title="No reports" />
      )}
      <TriageDialog report={open} onClose={() => setOpen(null)} />
    </>
  );
}

// ---------------------------------------------------------------------------------------------- jobs
export function AdminJobs() {
  const role = useRole();
  const client = useQueryClient();
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "jobs", "dead"],
    queryFn: () => unwrap(api.GET("/api/v1/admin/jobs", { params: { query: { status: "dead" } } })),
    enabled: role === "admin",
  });
  const requeue = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/api/v1/admin/jobs/{job_id}/requeue", { params: { path: { job_id: id } } })),
    onSuccess: () => {
      toast("Job requeued");
      void client.invalidateQueries({ queryKey: ["admin", "jobs"] });
    },
    onError: (e) => toast("Could not requeue", { description: messageOf(e), tone: "danger" }),
  });
  if (role && role !== "admin") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader title="Failed jobs" description="Background jobs that failed permanently. Errors are recorded without content. Dead jobs are kept for 30 days." />
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.length ? (
        <Table caption="Failed jobs" className="rounded-lg border border-border">
          <thead>
            <tr>
              <Th>Job</Th>
              <Th>Queue</Th>
              <Th>Attempts</Th>
              <Th>Last error</Th>
              <Th>Finished</Th>
              <Th><span className="sr-only">Requeue</span></Th>
            </tr>
          </thead>
          <tbody>
            {data.map((job) => (
              <tr key={job.id}>
                <Td className="font-mono text-xs">{job.kind}</Td>
                <Td>{job.queue}</Td>
                <Td className="tabular">{job.attempts}</Td>
                <Td className="max-w-sm text-xs text-muted">{job.last_error ?? "—"}</Td>
                <Td className="whitespace-nowrap">{formatDateTime(job.finished_at)}</Td>
                <Td>
                  <Button size="sm" variant="secondary" loading={requeue.isPending && requeue.variables === job.id} onClick={() => requeue.mutate(job.id)}>
                    <RotateCw className="h-3.5 w-3.5" aria-hidden /> Requeue
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <EmptyState icon={CheckCircle2} title="No failed jobs" />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------------------------- audit log
export function AuditLog() {
  const role = useRole();
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [before, setBefore] = useState<number | null>(null);
  const allowed = role === "admin" || role === "auditor";
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "audit", action, outcome, before],
    enabled: allowed,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/audit-events", {
          params: { query: { action: action || undefined, outcome: outcome || undefined, before_seq: before ?? undefined, limit: 100 } },
        }),
      ),
  });
  const verify = useMutation({ mutationFn: () => unwrap(api.GET("/api/v1/audit-events/verify")) });
  if (role && !allowed) return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Audit log"
        description="A hash-chained, append-only record of security-relevant actions. It never contains evidence content, secrets or raw IP addresses."
        actions={
          <Button variant="secondary" loading={verify.isPending} onClick={() => verify.mutate()}>
            <ShieldCheck className="h-4 w-4" aria-hidden /> Verify chain
          </Button>
        }
      />
      {verify.data ? (
        verify.data.ok ? (
          <Alert tone="success" title="Chain verified" className="mb-4">
            {verify.data.checked} entries checked up to #{verify.data.last_seq}. No tampering detected.
          </Alert>
        ) : (
          <Alert tone="danger" title="Chain verification failed" className="mb-4">
            First broken entry: #{verify.data.first_broken_seq}. {verify.data.reason}
          </Alert>
        )
      ) : verify.error ? (
        <Alert tone="danger" className="mb-4">
          <ShieldAlert className="mr-1 inline h-4 w-4" aria-hidden />
          {messageOf(verify.error)}
        </Alert>
      ) : null}
      <form
        className="mb-4 flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setBefore(null);
          void refetch();
        }}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Action</span>
          <Input value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. auth.login" className="w-56" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Outcome</span>
          <Select value={outcome} onChange={(e) => setOutcome(e.target.value)} className="w-40">
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="denied">Denied</option>
            <option value="failure">Failure</option>
          </Select>
        </label>
      </form>
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.items.length ? (
        <>
          <Table caption="Audit events" className="rounded-lg border border-border">
            <thead>
              <tr>
                <Th className="text-right">Entry</Th>
                <Th>When</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th>Outcome</Th>
                <Th>Target</Th>
                <Th>Hash</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.seq}>
                  <Td className="text-right font-mono text-xs">#{e.seq}</Td>
                  <Td className="whitespace-nowrap">{formatDateTime(e.occurred_at)}</Td>
                  <Td className="text-xs">
                    {e.actor_type === "user" ? <span className="font-mono">{e.actor_id?.slice(0, 8)}…</span> : humanize(e.actor_type)}
                    {e.actor_role ? <span className="block text-muted">{e.actor_role}</span> : null}
                  </Td>
                  <Td>
                    {describeAction(e.action)}
                    <span className="block font-mono text-[11px] text-muted">{e.action}</span>
                  </Td>
                  <Td className={e.outcome === "success" ? "" : "text-danger"}>{humanize(e.outcome)}</Td>
                  <Td className="text-xs text-muted">{e.target_type ? `${humanize(e.target_type)}` : "—"}</Td>
                  <Td className="font-mono text-[11px] text-muted">{e.row_hash.slice(0, 12)}…</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {data.next_before_seq ? (
            <Button variant="secondary" className="mt-3" onClick={() => setBefore(data.next_before_seq)}>
              Older entries
            </Button>
          ) : null}
        </>
      ) : (
        <EmptyState title="No audit events match" />
      )}
      <Card className="mt-6">
        <CardHeader title="About the audit log" />
        <p className="p-4 text-sm text-muted">
          Each entry&apos;s hash covers the previous entry, so editing or deleting any entry breaks the chain. The database refuses updates
          and deletes of audit rows, and the chain head is anchored daily outside the database.
        </p>
      </Card>
    </>
  );
}
