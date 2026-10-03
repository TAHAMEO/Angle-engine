"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, History, ListChecks, Loader2, Send, Sparkles, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { CitationChip, ProvenanceBadge } from "@/components/provenance/badges";
import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { useAssistantDrawer } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Alert, EmptyState, Spinner } from "@/components/ui/feedback";
import { Field, Select, Textarea } from "@/components/ui/form";
import { Badge, Tabs } from "@/components/ui/data";
import { Sheet } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import type { InteractionOut, ProposalOut } from "@/lib/api/types";
import { formatDateTime, humanize } from "@/lib/format";
import { newIdempotencyKey } from "@/lib/ids";
import { path, useInvestigation } from "@/lib/investigation";
import { setCollectPrefill } from "@/lib/prefill";
import { qk } from "@/lib/query/keys";

type Task =
  | "chat"
  | "summarize"
  | "compare"
  | "check_conclusion"
  | "contradictions"
  | "gaps"
  | "suggest_queries"
  | "extract"
  | "timeline";

const TASKS: { value: Task; label: string; help: string; input?: "question" | "conclusion" | "topic" }[] = [
  { value: "chat", label: "Ask a question", help: "Answered only from this investigation's evidence, with citations.", input: "question" },
  { value: "summarize", label: "Summarize the evidence", help: "A cited summary, optionally focused on a topic.", input: "topic" },
  { value: "compare", label: "Compare sources", help: "Where sources agree and differ, with citations.", input: "topic" },
  {
    value: "check_conclusion",
    label: "Check a conclusion",
    help: "Tests a conclusion against the evidence. If the evidence does not support it, the assistant says so.",
    input: "conclusion",
  },
  { value: "contradictions", label: "Find contradictions", help: "Proposes possible conflicts between sources for you to review." },
  { value: "gaps", label: "Find evidence gaps", help: "What is missing to support the current findings." },
  { value: "suggest_queries", label: "Suggest lawful searches", help: "Search ideas, each re-screened by the acceptable-use policy." },
  { value: "extract", label: "Extract entities and relationships", help: "Proposals you can accept into the graph as AI hypotheses." },
  { value: "timeline", label: "Propose timeline events", help: "Dated events from the evidence, as proposals." },
];

const TERMINAL = new Set(["completed", "failed", "refused", "cancelled"]);

function useInteraction(investigationId: string, interactionId: string | null) {
  return useQuery({
    queryKey: qk.interaction(investigationId, interactionId ?? ""),
    enabled: Boolean(interactionId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/assistant/requests/{interaction_id}", {
          params: { path: { investigation_id: investigationId, interaction_id: interactionId ?? "" } },
          headers: BACKGROUND,
        }),
      ),
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && !TERMINAL.has(data.status) ? (data.poll_after_ms ?? 1000) : false;
    },
  });
}

function ProposalCard({ proposal, investigationId, canWrite }: { proposal: ProposalOut; investigationId: string; canWrite: boolean }) {
  const client = useQueryClient();
  const router = useRouter();
  const payload = proposal.payload as Record<string, unknown>;
  const decide = useMutation({
    mutationFn: async (action: "accept" | "reject") => {
      const params = { path: { investigation_id: investigationId, proposal_id: proposal.id } };
      if (action === "accept") {
        return unwrap(api.POST("/api/v1/investigations/{investigation_id}/assistant/proposals/{proposal_id}/accept", { params }));
      }
      await unwrap(api.POST("/api/v1/investigations/{investigation_id}/assistant/proposals/{proposal_id}/reject", { params }));
      return null;
    },
    onSuccess: (result, action) => {
      void client.invalidateQueries({ queryKey: ["investigations", investigationId] });
      if (action === "reject") {
        toast("Proposal rejected");
        return;
      }
      const prefill = (result?.result as { prefill?: { query: string; input_type: string } } | undefined)?.prefill;
      if (prefill) {
        setCollectPrefill(prefill);
        router.push(`${path(investigationId, "sources")}?collect=1`);
        toast("Search prefilled", { description: "Review it and choose a connector before running it." });
      } else {
        toast("Added as an AI hypothesis", { description: "It stays labelled as AI output until a human verifies it.", tone: "success" });
      }
    },
    onError: (error) => toast("Could not save the decision", { description: messageOf(error), tone: "danger" }),
  });

  let summary: React.ReactNode;
  switch (proposal.kind) {
    case "entity":
      summary = (
        <>
          <span className="text-muted">{humanize(String(payload.type))}:</span> {String(payload.name)}
        </>
      );
      break;
    case "relationship": {
      const from = payload.from as { name: string } | undefined;
      const to = payload.to as { name: string } | undefined;
      summary = (
        <>
          {from?.name} <span className="font-mono text-xs text-muted">{String(payload.rel_type)}</span> {to?.name}
        </>
      );
      break;
    }
    case "timeline_event":
      summary = (
        <>
          <span className="font-mono text-xs text-muted">{String(payload.date).slice(0, 10)}</span> {String(payload.title)}
        </>
      );
      break;
    case "contradiction":
      summary = (
        <>
          {payload.aspect ? <span className="text-muted">{String(payload.aspect)}: </span> : null}
          {String(payload.description)}
        </>
      );
      break;
    case "gap":
      summary = (
        <>
          {String(payload.description)}
          {payload.why_it_matters ? <span className="block text-xs text-muted">{String(payload.why_it_matters)}</span> : null}
        </>
      );
      break;
    case "query":
      summary = (
        <>
          <span className="font-mono text-[13px]">{String(payload.query)}</span>
          <span className="ml-1 text-xs text-muted">({humanize(String(payload.input_type))})</span>
          {payload.rationale ? <span className="block text-xs text-muted">{String(payload.rationale)}</span> : null}
        </>
      );
      break;
    default:
      summary = <span className="text-muted">{humanize(proposal.kind)}</span>;
  }

  return (
    <li className="space-y-2 rounded-md border border-dashed border-st-ai/50 bg-st-ai/5 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <ProvenanceBadge provenance="ai_hypothesis" size="sm" />
        <Badge>{humanize(proposal.kind)}</Badge>
        {proposal.status !== "pending" ? <Badge>{humanize(proposal.status)}</Badge> : null}
      </div>
      <p>{summary}</p>
      {proposal.evidence.length ? (
        <p className="flex flex-wrap items-center gap-1 text-xs text-muted">
          Cites{" "}
          {proposal.evidence.map((e) => (
            <CitationChip
              key={e.id}
              label={e.label}
              onClick={() => router.push(`${path(investigationId, "evidence")}?tab=items&evidence=${e.id}`)}
            />
          ))}
        </p>
      ) : null}
      {proposal.status === "pending" && canWrite ? (
        <div className="flex gap-2">
          <Button size="sm" variant="outline" loading={decide.isPending && decide.variables === "accept"} onClick={() => decide.mutate("accept")}>
            <Check className="h-3.5 w-3.5" aria-hidden /> {proposal.kind === "query" ? "Use this search" : proposal.kind === "gap" ? "Noted" : "Accept as hypothesis"}
          </Button>
          <Button size="sm" variant="ghost" loading={decide.isPending && decide.variables === "reject"} onClick={() => decide.mutate("reject")}>
            <X className="h-3.5 w-3.5" aria-hidden /> Reject
          </Button>
        </div>
      ) : null}
    </li>
  );
}

/** Renders the validated answer from structured segments — never as HTML. */
export function InteractionView({ interaction, investigationId, canWrite }: { interaction: InteractionOut; investigationId: string; canWrite: boolean }) {
  const router = useRouter();
  if (!TERMINAL.has(interaction.status)) {
    return (
      <div role="status" className="flex items-center gap-2 rounded-md border border-border p-3 text-sm text-muted">
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
        Reading {interaction.context_documents || "the"} evidence document{interaction.context_documents === 1 ? "" : "s"}…
      </div>
    );
  }
  if (interaction.expired) {
    return <Alert tone="info">This transcript was removed under the AI retention policy. Accepted proposals remain.</Alert>;
  }
  if (interaction.status === "failed") {
    return (
      <Alert tone="danger" title="The assistant could not answer">
        {interaction.error_code === "budget_exceeded"
          ? "The daily AI budget is used up. Try again tomorrow."
          : "The request failed. Try again later."}
      </Alert>
    );
  }
  const openEvidence = (id: string) => router.push(`${path(investigationId, "evidence")}?tab=items&evidence=${id}`);
  return (
    <article className="space-y-3" aria-label="Assistant answer">
      <div className="flex flex-wrap items-center gap-1.5">
        <ProvenanceBadge provenance="ai_hypothesis" size="sm" />
        {interaction.grounding_label ? <Badge>{interaction.grounding_label}</Badge> : null}
        {interaction.verdict ? <Badge className="border-primary/50 text-primary">Verdict: {humanize(interaction.verdict)}</Badge> : null}
      </div>
      <div className="space-y-2 text-sm leading-relaxed">
        {interaction.segments.map((segment, index) => {
          if (segment.kind === "notice") {
            return (
              <p key={index} role="note" className="rounded-md border border-warning/50 bg-warning-bg px-3 py-2 font-medium">
                {segment.text}
              </p>
            );
          }
          if (segment.kind === "uncited") {
            return (
              <p key={index} className="border-l-2 border-dashed border-st-ai/60 pl-2.5 text-muted italic">
                {segment.text}{" "}
                <span className="text-xs font-semibold text-st-ai not-italic">[{interaction.uncited_label ?? "Uncited AI commentary"}]</span>
              </p>
            );
          }
          return (
            <p key={index}>
              {segment.text}
              {segment.citations.length ? (
                <span className="ml-1 inline-flex flex-wrap gap-1 align-baseline">
                  {segment.citations.map((citation, n) => (
                    <CitationChip key={n} label={citation.label} title={`“${citation.cited_text}”`} onClick={() => openEvidence(citation.evidence_id)} />
                  ))}
                </span>
              ) : null}
            </p>
          );
        })}
      </div>
      {interaction.proposals.length ? (
        <section aria-label="Proposals" className="space-y-2">
          <h3 className="text-xs font-semibold tracking-wide text-muted uppercase">Proposals — nothing is saved until you accept</h3>
          <ul className="space-y-2">
            {interaction.proposals.map((proposal) => (
              <ProposalCard key={proposal.id} proposal={proposal} investigationId={investigationId} canWrite={canWrite} />
            ))}
          </ul>
        </section>
      ) : null}
      <p className="border-t border-border pt-2 text-xs text-muted">
        {interaction.provider_label ?? "AI"}
        {interaction.model ? ` · ${interaction.model}` : ""} · {formatDateTime(interaction.completed_at)}. AI output is a hypothesis
        — verify it against the cited evidence before relying on it.
      </p>
    </article>
  );
}

function AskPanel({ onCreated }: { onCreated: (interaction: InteractionOut) => void }) {
  const { investigation, can } = useInvestigation();
  const [task, setTask] = useState<Task>("chat");
  const [text, setText] = useState("");
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const meta = TASKS.find((t) => t.value === task)!;
  const submit = useMutation({
    mutationFn: async (acknowledge: boolean) => {
      const body = {
        task,
        acknowledge_policy_notices: acknowledge,
        question: meta.input === "question" ? text : undefined,
        conclusion: meta.input === "conclusion" ? text : undefined,
        topic: meta.input === "topic" && text ? text : undefined,
      };
      return unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/assistant/requests", {
          params: { path: { investigation_id: investigation.id }, header: { "idempotency-key": newIdempotencyKey() } },
          body,
        }),
      );
    },
    onSuccess: (interaction) => {
      setPolicy(null);
      setText("");
      onCreated(interaction);
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError || error instanceof PolicyAcknowledgementError) setPolicy(error.policy);
      else toast("The request was not sent", { description: messageOf(error), tone: "danger" });
    },
  });
  const needsText = meta.input === "question" || meta.input === "conclusion";
  if (!can("content:write")) {
    return <Alert tone="info">You can read assistant answers, but your role cannot send requests in this investigation.</Alert>;
  }
  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        submit.mutate(false);
      }}
    >
      <Field label="What should the assistant do?" hint={meta.help}>
        {(props) => (
          <Select
            {...props}
            value={task}
            onChange={(event) => {
              setTask(event.target.value as Task);
              setPolicy(null);
            }}
          >
            {TASKS.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {meta.input ? (
        <Field
          label={meta.input === "question" ? "Question" : meta.input === "conclusion" ? "Conclusion to check" : "Focus (optional)"}
          hint="Do not ask about private individuals, home addresses, faces or tracking — such requests are refused."
          required={needsText}
        >
          {(props) => (
            <Textarea {...props} rows={3} maxLength={2000} value={text} onChange={(event) => setText(event.target.value)} />
          )}
        </Field>
      ) : null}
      {policy ? (
        <PolicyDecisionPanel
          policy={policy}
          onAcknowledge={policy.decision === "warn" ? () => submit.mutate(true) : undefined}
          acknowledging={submit.isPending}
          onUseAlternative={(alternative) => {
            if (alternative.template) setText(alternative.template);
            setPolicy(null);
          }}
        />
      ) : null}
      <Button type="submit" variant="primary" loading={submit.isPending} disabled={needsText && text.trim().length < 3}>
        <Send className="h-4 w-4" aria-hidden /> Send
      </Button>
    </form>
  );
}

function HistoryPanel({ onOpen }: { onOpen: (id: string) => void }) {
  const { investigation } = useInvestigation();
  const { data, isPending } = useQuery({
    queryKey: qk.assistant(investigation.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/assistant/requests", {
          params: { path: { investigation_id: investigation.id } },
        }),
      ),
  });
  if (isPending) return <Spinner />;
  if (!data?.length) return <EmptyState icon={History} title="No requests yet" />;
  return (
    <ul className="divide-y divide-border rounded-md border border-border">
      {data.map((item) => (
        <li key={item.id}>
          <button type="button" onClick={() => onOpen(item.id)} className="flex w-full flex-col items-start gap-0.5 px-3 py-2 text-left text-sm hover:bg-surface-2">
            <span className="font-medium">{TASKS.find((t) => t.value === item.task)?.label ?? humanize(item.task)}</span>
            <span className="text-xs text-muted">
              {formatDateTime(item.created_at)} · {item.grounding_label ?? humanize(item.status)}
              {item.requested_by_me ? "" : " · by a teammate"}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function ProposalsPanel() {
  const { investigation, can } = useInvestigation();
  const { data, isPending } = useQuery({
    queryKey: qk.proposals(investigation.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/assistant/proposals", {
          params: { path: { investigation_id: investigation.id }, query: { status: "pending" } },
        }),
      ),
  });
  if (isPending) return <Spinner />;
  if (!data?.length) return <EmptyState icon={ListChecks} title="No pending proposals" />;
  return (
    <ul className="space-y-2">
      {data.map((proposal) => (
        <ProposalCard key={proposal.id} proposal={proposal} investigationId={investigation.id} canWrite={can("content:write")} />
      ))}
    </ul>
  );
}

export function AssistantDrawer() {
  const { open, setOpen } = useAssistantDrawer();
  const { investigation, can } = useInvestigation();
  const [current, setCurrent] = useState<string | null>(null);
  const [tab, setTab] = useState("ask");
  const { data: status } = useQuery({
    queryKey: ["assistant-status"],
    queryFn: () => unwrap(api.GET("/api/v1/assistant/status")),
    staleTime: 5 * 60_000,
    enabled: open,
  });
  const { data: interaction } = useInteraction(investigation.id, current);

  const unavailable = status && !status.available;
  return (
    <Sheet
      open={open}
      onOpenChange={setOpen}
      modal={false}
      className="sm:max-w-[30rem]"
      title={
        <span className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-st-ai" aria-hidden /> Assistant
          {status?.label ? <Badge className="font-normal text-muted">{status.label}</Badge> : null}
        </span>
      }
      description="Answers come only from this investigation's evidence and cite it. Uncited text is labelled; when the evidence is not enough, it says so."
    >
      <div className="space-y-4 p-5">
        {!investigation.ai_enabled ? (
          <Alert tone="info">The investigation owner turned the assistant off for this investigation.</Alert>
        ) : unavailable ? (
          <Alert tone="info" title="Assistant unavailable">
            No AI provider is configured. An administrator can add an Anthropic API key.
          </Alert>
        ) : (
          <Tabs
            label="Assistant"
            value={tab}
            onValueChange={setTab}
            tabs={[
              {
                value: "ask",
                label: (
                  <span className="inline-flex items-center gap-1.5">
                    <Bot className="h-3.5 w-3.5" aria-hidden /> Ask
                  </span>
                ),
                content: (
                  <div className="space-y-5">
                    <AskPanel onCreated={(created) => setCurrent(created.id)} />
                    {interaction ? (
                      <div aria-live="polite">
                        <InteractionView interaction={interaction} investigationId={investigation.id} canWrite={can("content:write")} />
                      </div>
                    ) : null}
                  </div>
                ),
              },
              {
                value: "history",
                label: "History",
                content: (
                  <HistoryPanel
                    onOpen={(id) => {
                      setCurrent(id);
                      setTab("ask");
                    }}
                  />
                ),
              },
              { value: "proposals", label: "Proposals", content: <ProposalsPanel /> },
            ]}
          />
        )}
      </div>
    </Sheet>
  );
}
