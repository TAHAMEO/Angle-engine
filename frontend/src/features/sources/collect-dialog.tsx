"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink as ExternalIcon, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { ExternalLink } from "@/components/security/external-link";
import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/data";
import { Alert, Spinner } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import type { ConnectorOut, S } from "@/lib/api/types";
import { newIdempotencyKey } from "@/lib/ids";
import { useInvestigation } from "@/lib/investigation";
import type { CollectPrefill } from "@/lib/prefill";
import { qk } from "@/lib/query/keys";

import { INPUT_TYPES } from "./labels";

type InputType = S<"RunIn">["input_type"];

export function useConnectors(investigationId: string) {
  return useQuery({
    queryKey: qk.connectors(investigationId),
    queryFn: () =>
      unwrap(api.GET("/api/v1/investigations/{investigation_id}/connectors", { params: { path: { investigation_id: investigationId } } })),
    staleTime: 5 * 60_000,
  });
}

function ManualLinks({ query }: { query: string }) {
  const { investigation: inv } = useInvestigation();
  const { data, isFetching } = useQuery({
    queryKey: ["investigations", inv.id, "manual-links", query],
    enabled: query.trim().length >= 2,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/manual-search-links", {
          params: { path: { investigation_id: inv.id }, query: { q: query } },
        }),
      ),
  });
  if (query.trim().length < 2) return null;
  return (
    <details className="rounded-md border border-border p-3 text-sm">
      <summary className="cursor-pointer font-medium">Search it yourself (manual search links)</summary>
      <p className="mt-2 text-[13px] text-muted">
        Angel Engine never scrapes search engines. These links open the search in a new tab; the site will see your IP address. Add anything
        relevant with &quot;Add a source manually&quot;.
      </p>
      {isFetching ? <Spinner /> : null}
      <ul className="mt-2 space-y-1">
        {data?.map((link) => (
          <li key={link.url}>
            <ExternalLink href={link.url}>{link.label}</ExternalLink>
          </li>
        ))}
      </ul>
    </details>
  );
}

export function CollectDialog({
  open,
  onOpenChange,
  prefill,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  prefill?: CollectPrefill | null;
}) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const { data: connectors, isPending } = useConnectors(inv.id);
  const [inputType, setInputType] = useState<InputType>("keyword");
  const [query, setQuery] = useState("");
  const [connectorId, setConnectorId] = useState("");
  const [note, setNote] = useState("");
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);

  useEffect(() => {
    if (open && prefill) {
      // A one-shot hand-over from another page (accepted AI suggestion, lawful alternative).
      /* eslint-disable react-hooks/set-state-in-effect */
      setQuery(prefill.query);
      if (prefill.input_type && prefill.input_type in INPUT_TYPES) setInputType(prefill.input_type as InputType);
      if (prefill.connector_id) setConnectorId(prefill.connector_id);
      /* eslint-enable react-hooks/set-state-in-effect */
    }
  }, [open, prefill]);

  const candidates = (connectors ?? []).filter((c) => c.input_types.includes(inputType));
  const selected: ConnectorOut | undefined = candidates.find((c) => c.id === connectorId) ?? candidates.find((c) => c.available_here);
  const run = useMutation({
    mutationFn: (acknowledge: boolean) =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/collection-runs", {
          params: { path: { investigation_id: inv.id }, header: { "idempotency-key": newIdempotencyKey() } },
          body: {
            connector_id: selected!.id,
            input_type: inputType,
            query: query.trim(),
            purpose_note: note.trim() || null,
            acknowledge_policy_notices: acknowledge,
          },
        }),
      ),
    onSuccess: (result) => {
      setPolicy(null);
      onOpenChange(false);
      setQuery("");
      setNote("");
      void client.invalidateQueries({ queryKey: qk.runs(inv.id) });
      toast(result.status === "pending_review" ? "Sent to a supervisor for review" : "Collection started", {
        description:
          result.status === "pending_review"
            ? "Person-oriented lookups in restricted mode need approval before they run."
            : "Results appear in Sources and Evidence as they arrive.",
        tone: "success",
      });
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError || error instanceof PolicyAcknowledgementError) setPolicy(error.policy);
      else toast("Collection did not start", { description: messageOf(error), tone: "danger" });
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Collect public sources"
      description="Every query is screened by the acceptable-use policy and recorded. Only registered connectors that use official APIs or pages that allow automated access are used."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={run.isPending}
            disabled={!selected?.available_here || !query.trim() || Boolean(selected?.needs_purpose_note && note.trim().length < 10)}
            onClick={() => run.mutate(false)}
          >
            <Play className="h-4 w-4" aria-hidden /> Start collection
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-[12rem_1fr]">
          <Field label="Input type">
            {(props) => (
              <Select
                {...props}
                value={inputType}
                onChange={(event) => {
                  setInputType(event.target.value as InputType);
                  setConnectorId("");
                  setPolicy(null);
                }}
              >
                {Object.entries(INPUT_TYPES).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Query" required hint="For example a company name, a domain or a public URL. Never a private person's details.">
            {(props) => (
              <Input
                {...props}
                value={query}
                maxLength={500}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPolicy(null);
                }}
                autoComplete="off"
              />
            )}
          </Field>
        </div>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Connector</legend>
          {isPending ? <Spinner /> : null}
          {!isPending && !candidates.length ? <p className="text-sm text-muted">No connector accepts this input type.</p> : null}
          <ul className="grid max-h-72 gap-2 overflow-y-auto sm:grid-cols-2">
            {candidates.map((connector) => {
              const chosen = selected?.id === connector.id;
              return (
                <li key={connector.id}>
                  <label
                    className={`flex h-full cursor-pointer gap-2.5 rounded-md border p-2.5 text-sm ${chosen ? "border-primary bg-primary/5" : "border-border"} ${connector.available_here ? "" : "cursor-not-allowed opacity-60"}`}
                  >
                    <input
                      type="radio"
                      name="connector"
                      className="mt-1 accent-[var(--primary)]"
                      checked={chosen}
                      disabled={!connector.available_here}
                      onChange={() => setConnectorId(connector.id)}
                    />
                    <span className="min-w-0">
                      <span className="flex flex-wrap items-center gap-1.5 font-medium">
                        {connector.name}
                        {connector.requires_key ? <Badge>API key</Badge> : null}
                      </span>
                      <span className="block text-xs text-muted">{connector.category_label}</span>
                      {!connector.available_here && connector.reason ? (
                        <span className="block text-xs text-warning">{connector.reason}</span>
                      ) : connector.needs_approval ? (
                        <span className="block text-xs text-primary">Needs supervisor approval in restricted mode</span>
                      ) : null}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        </fieldset>
        {selected?.needs_purpose_note ? (
          <Field label="Why do you need this lookup?" required hint="Recorded with the run (at least 10 characters).">
            {(props) => <Textarea {...props} rows={2} value={note} onChange={(event) => setNote(event.target.value)} />}
          </Field>
        ) : null}
        {selected ? (
          <p className="flex items-start gap-1.5 text-xs text-muted">
            <ExternalIcon className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
            <span>
              {selected.terms_note}{" "}
              <ExternalLink href={selected.docs_url} showHost>
                Documentation
              </ExternalLink>
            </span>
          </p>
        ) : null}
        {policy ? (
          <PolicyDecisionPanel
            policy={policy}
            onAcknowledge={policy.decision === "warn" ? () => run.mutate(true) : undefined}
            acknowledging={run.isPending}
            onUseAlternative={(alternative) => {
              if (alternative.template) setQuery(alternative.template);
              if (alternative.connector_id) setConnectorId(alternative.connector_id);
              setPolicy(null);
            }}
          />
        ) : null}
        {inv.restricted_mode ? (
          <Alert tone="warning">Restricted mode: only news, company, government and document sources run without approval.</Alert>
        ) : null}
        <ManualLinks query={query} />
      </div>
    </Dialog>
  );
}
