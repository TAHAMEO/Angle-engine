"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { PolicyRefusalError, ValidationError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import { CATEGORY_NAMES } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";

/** Record an excerpt from a public page the investigator read themselves (e.g. via a manual search link). */
export function ManualCaptureDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [url, setUrl] = useState("");
  const [title, setTitle] = useState("");
  const [publisher, setPublisher] = useState("");
  const [published, setPublished] = useState("");
  const [category, setCategory] = useState("websites");
  const [excerpt, setExcerpt] = useState("");
  const [statement, setStatement] = useState("");
  const [direct, setDirect] = useState(false);
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/evidence", {
          params: { path: { investigation_id: inv.id } },
          body: {
            url: url.trim(),
            title: title.trim() || null,
            publisher: publisher.trim() || null,
            published_at: published ? new Date(`${published}T00:00:00Z`).toISOString() : null,
            category,
            excerpt: excerpt.trim(),
            statement: statement.trim() || null,
            directly_states: direct,
          },
        }),
      ),
    onSuccess: (result) => {
      onOpenChange(false);
      setUrl("");
      setTitle("");
      setPublisher("");
      setPublished("");
      setExcerpt("");
      setStatement("");
      setDirect(false);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      const redacted = Object.values(result.evidence.redaction_counts).reduce((a, b) => a + b, 0);
      toast(result.created ? `Saved as ${result.evidence.label}` : `Already recorded as ${result.evidence.label}`, {
        description: redacted ? `${redacted} sensitive item(s) were redacted before storage.` : undefined,
        tone: "success",
      });
    },
    onError: (e) => {
      if (e instanceof PolicyRefusalError) setPolicy(e.policy);
      else if (e instanceof ValidationError) setError(e.fieldErrors.map((f) => f.msg).join(" ") || messageOf(e));
      else setError(messageOf(e));
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Add a source manually"
      description="Paste an excerpt from a public page you read yourself. It is redacted for sensitive data and stored encrypted, with your name as the collector."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={!url.trim() || excerpt.trim().length < 10} onClick={() => save.mutate()}>
            Save evidence
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <Field label="Public URL" required>
          {(props) => <Input {...props} type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" />}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Page title">{(props) => <Input {...props} value={title} onChange={(e) => setTitle(e.target.value)} />}</Field>
          <Field label="Publisher">{(props) => <Input {...props} value={publisher} onChange={(e) => setPublisher(e.target.value)} />}</Field>
          <Field label="Published on">{(props) => <Input {...props} type="date" value={published} onChange={(e) => setPublished(e.target.value)} />}</Field>
          <Field label="Category">
            {(props) => (
              <Select {...props} value={category} onChange={(e) => setCategory(e.target.value)}>
                {Object.entries(CATEGORY_NAMES)
                  .filter(([key]) => !["image_analysis", "analysis"].includes(key))
                  .map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
              </Select>
            )}
          </Field>
        </div>
        <Field label="Excerpt" required hint="Quote the relevant passage exactly (at least 10 characters).">
          {(props) => <Textarea {...props} rows={5} value={excerpt} onChange={(e) => setExcerpt(e.target.value)} />}
        </Field>
        <Field label="Finding (optional)" hint="A claim this excerpt supports. It is created as unverified.">
          {(props) => <Textarea {...props} rows={2} value={statement} onChange={(e) => setStatement(e.target.value)} />}
        </Field>
        {statement.trim() ? <Checkbox label="The excerpt states this claim directly" checked={direct} onChange={(e) => setDirect(e.target.checked)} /> : null}
        {policy ? <PolicyDecisionPanel policy={policy} /> : null}
      </div>
    </Dialog>
  );
}
