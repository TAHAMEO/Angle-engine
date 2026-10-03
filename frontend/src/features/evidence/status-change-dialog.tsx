"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { STATUS, VerificationStatusBadge, type Status } from "@/components/provenance/badges";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/feedback";
import { Checkbox, Field, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { ConflictError, PreconditionError, messageOf } from "@/lib/api/errors";
import type { FindingDetail } from "@/lib/api/types";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { cn } from "@/lib/utils";

import { PRECONDITION_HINTS, STANCES } from "./labels";

const TARGETS: Status[] = ["confirmed_by_source", "corroborated", "unverified", "contradicted", "ai_hypothesis"];

/**
 * A verification status is a human decision: it needs a justification, cites the evidence relied on, and is checked
 * against preconditions on the server. AI may suggest; it never submits this form.
 */
export function StatusChangeDialog({ finding, open, onOpenChange }: { finding: FindingDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const allowed = finding.allowed_transitions.filter((s) => s !== finding.verification_status);
  const [target, setTarget] = useState<Status | null>((allowed[0] as Status | undefined) ?? null);
  const [justification, setJustification] = useState("");
  const activeLinks = finding.links.filter((l) => !l.dismissed);
  const [evidenceIds, setEvidenceIds] = useState<Set<string>>(
    () => new Set(activeLinks.filter((l) => l.stance !== "context").map((l) => String((l.evidence as { id: string }).id))),
  );
  const [attested, setAttested] = useState(false);
  const [conflict, setConflict] = useState<string | null>(null);
  const change = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/findings/{finding_id}/transitions", {
          params: { path: { investigation_id: inv.id, finding_id: finding.id }, header: { "if-match": `"${finding.version}"` } },
          body: {
            to_status: target!,
            justification: justification.trim(),
            evidence_ids: [...evidenceIds],
            independence_attested: attested,
          },
        }),
      ),
    onSuccess: (updated) => {
      client.setQueryData(qk.finding(inv.id, finding.id), updated);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      onOpenChange(false);
      setJustification("");
      toast(`${finding.label} is now “${STATUS[updated.verification_status as Status]?.label ?? updated.verification_status}”`, {
        description: "Recorded in the finding's history and the audit log.",
        tone: "success",
      });
    },
    onError: (error) => {
      if (error instanceof PreconditionError) {
        setConflict("Someone changed this finding while you were editing. Close this dialog to load the latest version, then try again.");
        void client.invalidateQueries({ queryKey: qk.finding(inv.id, finding.id) });
      } else if (error instanceof ConflictError) {
        const failed = error.failedPreconditions[target ?? ""] ?? [];
        setConflict([error.message, ...failed].join(" "));
      } else {
        toast("The status was not changed", { description: messageOf(error), tone: "danger" });
      }
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) setConflict(null);
      }}
      className="max-w-2xl"
      title={`Change verification status of ${finding.label}`}
      description={
        <span className="flex flex-wrap items-center gap-1.5">
          Current status: <VerificationStatusBadge status={finding.verification_status} size="sm" />
        </span>
      }
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
      <div className="space-y-5">
        {conflict ? <Alert tone="danger">{conflict}</Alert> : null}
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">New status</legend>
          {TARGETS.filter((s) => s !== finding.verification_status).map((status) => {
            const enabled = allowed.includes(status);
            const reasons = finding.failed_preconditions[status] ?? [];
            return (
              <label
                key={status}
                className={cn(
                  "flex gap-2.5 rounded-md border p-2.5 text-sm",
                  target === status ? "border-primary bg-primary/5" : "border-border",
                  enabled ? "cursor-pointer" : "cursor-not-allowed opacity-70",
                )}
              >
                <input
                  type="radio"
                  name="target-status"
                  className="mt-1 accent-[var(--primary)]"
                  disabled={!enabled}
                  checked={target === status}
                  onChange={() => setTarget(status)}
                />
                <span className="space-y-1">
                  <VerificationStatusBadge status={status} size="sm" />
                  <span className="block text-[13px] text-muted">{PRECONDITION_HINTS[status]}</span>
                  {!enabled && reasons.length ? (
                    <span className="block text-[13px] text-danger">Not available: {reasons.join(" ")}</span>
                  ) : null}
                </span>
              </label>
            );
          })}
        </fieldset>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Evidence relied on</legend>
          {activeLinks.length ? (
            <ul className="max-h-48 space-y-1.5 overflow-y-auto">
              {activeLinks.map((link) => {
                const ev = link.evidence as { id: string; label: string; excerpt?: string | null };
                return (
                  <li key={link.id}>
                    <label className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1 h-4 w-4 accent-[var(--primary)]"
                        checked={evidenceIds.has(ev.id)}
                        onChange={(event) =>
                          setEvidenceIds((current) => {
                            const next = new Set(current);
                            if (event.target.checked) next.add(ev.id);
                            else next.delete(ev.id);
                            return next;
                          })
                        }
                      />
                      <span className="min-w-0">
                        <span className="font-mono text-xs font-semibold">{ev.label}</span>{" "}
                        <span className={cn("rounded-sm border px-1 text-[11px]", STANCES[link.stance]?.className)}>{STANCES[link.stance]?.label}</span>
                        {link.source ? <span className="ml-1 text-xs text-muted">{link.source.host}</span> : null}
                        {ev.excerpt ? <span className="line-clamp-2 block text-[13px] text-muted">{ev.excerpt}</span> : null}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="text-sm text-muted">No evidence is linked to this finding.</p>
          )}
        </fieldset>
        <Field label="Justification" required hint={`${justification.trim().length} / 20 characters minimum. Explain why the cited evidence supports this status.`}>
          {(props) => <Textarea {...props} rows={3} maxLength={4000} value={justification} onChange={(event) => setJustification(event.target.value)} />}
        </Field>
        {target === "corroborated" ? (
          <Checkbox
            label="I checked that these sources are independent"
            description="They are not copies of one another, do not cite each other, and are not owned by the same publisher."
            checked={attested}
            onChange={(event) => setAttested(event.target.checked)}
          />
        ) : null}
        {inv.restricted_mode ? (
          <p className="text-xs text-muted">Restricted mode: promotions to confirmed or corroborated must be made by a supervisor who did not create the finding.</p>
        ) : null}
      </div>
    </Dialog>
  );
}
