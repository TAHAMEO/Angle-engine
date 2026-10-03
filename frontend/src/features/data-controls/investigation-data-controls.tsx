"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Gavel, Save, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, DefinitionList } from "@/components/ui/data";
import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Field, Input, Textarea } from "@/components/ui/form";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { RetentionOut } from "@/lib/api/types";
import { formatDateTime, relative } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

function RetentionForm({ retention }: { retention: RetentionOut }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const [hours, setHours] = useState(String(retention.image_original_retention_hours));
  const [days, setDays] = useState(String(retention.closed_retention_days));
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PUT("/api/v1/investigations/{investigation_id}/retention", {
          params: { path: { investigation_id: inv.id } },
          body: { image_original_retention_hours: Number(hours), closed_retention_days: Number(days) },
        }),
      ),
    onSuccess: (data) => {
      client.setQueryData(qk.retention(inv.id), data);
      toast("Retention updated", { tone: "success" });
    },
    onError: (e) => toast("Retention was not updated", { description: messageOf(e), tone: "danger" }),
  });
  const manage = can("investigation:manage");
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate();
      }}
    >
      <fieldset disabled={!manage} className="grid gap-4 sm:grid-cols-2">
        <Field label="Keep uploaded originals for (hours)" hint={`0–${retention.image_original_retention_max_hours} h after analysis. Previews and analysis results are kept.`}>
          {(props) => <Input {...props} type="number" min={0} max={retention.image_original_retention_max_hours} value={hours} onChange={(e) => setHours(e.target.value)} />}
        </Field>
        <Field label="Delete after closing (days)" hint={`Closed investigations are archived after ${retention.archive_after_days} days and deleted after this period, with notice.`}>
          {(props) => <Input {...props} type="number" min={1} value={days} onChange={(e) => setDays(e.target.value)} />}
        </Field>
      </fieldset>
      {manage ? (
        <Button type="submit" variant="secondary" loading={save.isPending}>
          <Save className="h-4 w-4" aria-hidden /> Save retention
        </Button>
      ) : (
        <p className="text-sm text-muted">Only the owner can change retention.</p>
      )}
    </form>
  );
}

function DangerZone() {
  const { investigation: inv } = useInvestigation();
  const router = useRouter();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const remove = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(
          api.POST("/api/v1/investigations/{investigation_id}/deletion", {
            params: { path: { investigation_id: inv.id } },
            body: { confirm_ref: confirm.trim(), reason: reason.trim() },
          }),
        ),
      ),
    onSuccess: () => {
      setOpen(false);
      client.removeQueries({ queryKey: ["investigations", inv.id] });
      void client.invalidateQueries({ queryKey: ["investigations"] });
      toast(`${inv.ref} deleted`, { description: "Its encryption keys were destroyed; remaining records are being purged.", tone: "success" });
      router.replace("/investigations");
    },
    onError: (e) => toast("The investigation was not deleted", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Card className="border-danger/50">
      <CardHeader title="Delete this investigation" description="Permanent. Use this when the investigation is no longer needed or was opened by mistake." />
      <div className="space-y-4 p-4 text-sm">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="font-medium">Deleted immediately</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-muted">
              <li>The investigation&apos;s encryption keys (crypto-shredding): evidence, images, notes, reports and AI transcripts become unreadable</li>
              <li>Uploaded files, previews and exports</li>
              <li>Memberships and pending jobs</li>
            </ul>
          </div>
          <div>
            <p className="font-medium">Retained</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-muted">
              <li>A tombstone with the reference and dates</li>
              <li>Audit-log entries (they never contain content)</li>
              <li>Encrypted backups until they expire with their key epoch</li>
            </ul>
          </div>
        </div>
        {inv.legal_hold ? <Alert tone="warning">A legal hold is in place. Deletion is blocked until an administrator lifts it.</Alert> : null}
        <Button variant="danger" disabled={inv.legal_hold} onClick={() => setOpen(true)}>
          <Trash2 className="h-4 w-4" aria-hidden /> Delete investigation
        </Button>
      </div>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Delete ${inv.ref} permanently?`}
        description={<p>This cannot be undone. Type the reference to confirm.</p>}
        confirmLabel="Delete permanently"
        confirmDisabled={confirm.trim().toUpperCase() !== inv.ref || reason.trim().length < 5}
        loading={remove.isPending}
        onConfirm={() => remove.mutate()}
      >
        <div className="space-y-3">
          <Field label={`Type ${inv.ref}`} required>
            {(props) => <Input {...props} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" className="font-mono" />}
          </Field>
          <Field label="Reason" required hint="Recorded in the audit log.">
            {(props) => <Textarea {...props} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />}
          </Field>
        </div>
      </ConfirmDialog>
    </Card>
  );
}

export function InvestigationDataControls() {
  const { investigation: inv, can } = useInvestigation();
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.retention(inv.id),
    queryFn: () => unwrap(api.GET("/api/v1/investigations/{investigation_id}/retention", { params: { path: { investigation_id: inv.id } } })),
  });
  return (
    <>
      <PageHeader
        title="Data controls"
        description="Retention, legal hold and deletion for this investigation. Collected content is encrypted with a key that belongs to this investigation alone."
      />
      {isPending ? (
        <LoadingBlock />
      ) : error || !data ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : (
        <div className="grid gap-6 xl:grid-cols-2">
          <Card>
            <CardHeader title="Retention" />
            <div className="space-y-4 p-4">
              <DefinitionList
                items={[
                  ["Uploaded originals", `Deleted ${data.image_original_retention_hours} h after analysis`],
                  ["After closing", `Archived after ${data.archive_after_days} days, deleted after ${data.closed_retention_days} days`],
                  [
                    "Deletion scheduled",
                    data.deletion_scheduled_for ? `${formatDateTime(data.deletion_scheduled_for)} (${relative(data.deletion_scheduled_for)})` : "Not scheduled (investigation is open)",
                  ],
                  [
                    "Legal hold",
                    data.legal_hold ? (
                      <span key="h" className="inline-flex items-center gap-1 text-warning">
                        <Gavel className="h-3.5 w-3.5" aria-hidden /> In place — deletion paused
                      </span>
                    ) : (
                      "None"
                    ),
                  ],
                ]}
              />
              <RetentionForm retention={data} />
            </div>
          </Card>
          <Card>
            <CardHeader title="Images" />
            <div className="space-y-3 p-4 text-sm">
              <p>
                Delete an image&apos;s files (original and preview) or the image with everything derived from it from the image&apos;s page. Both
                destroy the file keys.
              </p>
              <Button asChild variant="secondary" size="sm">
                <Link href={path(inv.id, "images")}>Go to images</Link>
              </Button>
              <p className="text-muted">
                Legal holds are placed by an administrator. Data-subject requests can be raised through the public{" "}
                <Link href="/report-abuse" className="text-primary hover:underline">
                  report form
                </Link>
                .
              </p>
            </div>
          </Card>
          {can("investigation:manage") || inv.role === "owner" ? (
            <div className="xl:col-span-2">
              <DangerZone />
            </div>
          ) : null}
        </div>
      )}
    </>
  );
}
