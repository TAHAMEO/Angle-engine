"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/feedback";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { ValidationError, messageOf } from "@/lib/api/errors";
import { CATEGORY_NAMES } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";

import { EvidencePicker, type PickedEvidence } from "./evidence-picker";

type Origin = "source_reported" | "observed" | "analyst_inference" | "external_ai";
type Precision = "exact" | "minute" | "hour" | "day" | "month" | "year" | "approximate";

export function NewFindingDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (open: boolean) => void; onCreated: (id: string) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [statement, setStatement] = useState("");
  const [category, setCategory] = useState("analysis");
  const [origin, setOrigin] = useState<Origin>("source_reported");
  const [importance, setImportance] = useState<"key" | "normal">("normal");
  const [sensitive, setSensitive] = useState(false);
  const [confidence, setConfidence] = useState<"" | "low" | "moderate" | "high">("");
  const [basis, setBasis] = useState("");
  const [eventDate, setEventDate] = useState("");
  const [precision, setPrecision] = useState<Precision>("day");
  const [links, setLinks] = useState<PickedEvidence[]>([]);
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/findings", {
          params: { path: { investigation_id: inv.id } },
          body: {
            statement: statement.trim(),
            category,
            provenance: origin === "external_ai" ? undefined : origin,
            from_external_ai: origin === "external_ai",
            importance,
            sensitive,
            confidence: !sensitive && confidence ? confidence : null,
            confidence_basis: !sensitive && confidence ? basis.trim() || null : null,
            event_time: eventDate ? new Date(`${eventDate}T00:00:00Z`).toISOString() : null,
            event_precision: eventDate ? precision : null,
            links: links.map(({ evidence_id, stance, directly_states }) => ({ evidence_id, stance, directly_states })),
          },
        }),
      ),
    onSuccess: (finding) => {
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast(`${finding.label} created`, { description: "New findings start as unverified (or AI hypothesis).", tone: "success" });
      onOpenChange(false);
      setStatement("");
      setLinks([]);
      onCreated(finding.id);
    },
    onError: (e) => setError(e instanceof ValidationError ? e.fieldErrors.map((f) => f.msg).join(" ") || e.message : messageOf(e)),
  });
  const needsEvidence = origin !== "external_ai" && links.length === 0;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Record a finding"
      description="A finding is a claim backed by evidence. Its provenance never changes; its verification status is decided later, by people."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={statement.trim().length < 10 || needsEvidence} onClick={() => create.mutate()}>
            Create finding
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {error ? <Alert tone="danger">{error}</Alert> : null}
        <Field label="Statement" required hint="One specific, checkable claim (10–2,000 characters). Do not assert anyone's identity.">
          {(props) => <Textarea {...props} rows={3} maxLength={2000} value={statement} onChange={(e) => setStatement(e.target.value)} />}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Where does it come from?">
            {(props) => (
              <Select {...props} value={origin} onChange={(e) => setOrigin(e.target.value as Origin)}>
                <option value="source_reported">Reported by a source</option>
                <option value="observed">Observed directly (e.g. image analysis)</option>
                <option value="analyst_inference">My inference from the evidence</option>
                <option value="external_ai">An external AI tool (labelled AI hypothesis)</option>
              </Select>
            )}
          </Field>
          <Field label="Category">
            {(props) => (
              <Select {...props} value={category} onChange={(e) => setCategory(e.target.value)}>
                {Object.entries(CATEGORY_NAMES).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Importance">
            {(props) => (
              <Select {...props} value={importance} onChange={(e) => setImportance(e.target.value as "key" | "normal")}>
                <option value="normal">Normal</option>
                <option value="key">Key finding</option>
              </Select>
            )}
          </Field>
          <Field label="Confidence" hint={sensitive ? "Not used for sensitive findings." : "Analytical confidence with a stated basis."}>
            {(props) => (
              <Select {...props} disabled={sensitive} value={confidence} onChange={(e) => setConfidence(e.target.value as typeof confidence)}>
                <option value="">Not stated</option>
                <option value="low">Low</option>
                <option value="moderate">Moderate</option>
                <option value="high">High</option>
              </Select>
            )}
          </Field>
        </div>
        {confidence && !sensitive ? (
          <Field label="Basis for the confidence">
            {(props) => <Input {...props} value={basis} onChange={(e) => setBasis(e.target.value)} placeholder="e.g. two registry records agree" />}
          </Field>
        ) : null}
        <Checkbox
          label="Sensitive finding"
          description="Hidden from AI context; never given a confidence level."
          checked={sensitive}
          onChange={(e) => setSensitive(e.target.checked)}
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Event date (optional)">{(props) => <Input {...props} type="date" value={eventDate} onChange={(e) => setEventDate(e.target.value)} />}</Field>
          <Field label="Date precision">
            {(props) => (
              <Select {...props} value={precision} disabled={!eventDate} onChange={(e) => setPrecision(e.target.value as Precision)}>
                <option value="day">Day</option>
                <option value="month">Month</option>
                <option value="year">Year</option>
                <option value="approximate">Approximate</option>
              </Select>
            )}
          </Field>
        </div>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">
            Evidence {origin !== "external_ai" ? <span className="text-danger">*</span> : null}
          </legend>
          <p className="text-[13px] text-muted">Every finding except an AI hypothesis must cite at least one evidence item.</p>
          <EvidencePicker value={links} onChange={setLinks} />
        </fieldset>
      </div>
    </Dialog>
  );
}
