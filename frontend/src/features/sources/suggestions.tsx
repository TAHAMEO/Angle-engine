"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Lightbulb, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { formatDateTime, humanize } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

const KIND_HELP: Record<string, string> = {
  corroboration: "Independent sources appear to report the same thing.",
  contradiction: "Sources appear to disagree. Review before changing any status.",
  syndication: "These items look like copies of one original — they count as one origin.",
  duplicate: "These items appear to be duplicates.",
};

export function SuggestionsPanel() {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const { data, isPending } = useQuery({
    queryKey: qk.suggestions(inv.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/suggestions", {
          params: { path: { investigation_id: inv.id }, query: { status: "open" } },
        }),
      ),
  });
  const decide = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "accept" | "dismiss" }) => {
      const params = { path: { investigation_id: inv.id, suggestion_id: id } };
      return action === "accept"
        ? unwrap(api.POST("/api/v1/investigations/{investigation_id}/suggestions/{suggestion_id}/accept", { params, body: null }))
        : unwrap(api.POST("/api/v1/investigations/{investigation_id}/suggestions/{suggestion_id}/dismiss", { params, body: null }));
    },
    onSuccess: () => void client.invalidateQueries({ queryKey: ["investigations", inv.id] }),
    onError: (e) => toast("Could not save the decision", { description: messageOf(e), tone: "danger" }),
  });
  if (isPending) return <LoadingBlock />;
  if (!data?.length) {
    return (
      <EmptyState icon={Lightbulb} title="No open suggestions">
        Deterministic rules flag possible corroboration, contradictions and syndicated copies here. They never change a status by themselves.
      </EmptyState>
    );
  }
  return (
    <ul className="space-y-2">
      {data.map((suggestion) => (
        <li key={suggestion.id} className="flex flex-col gap-2 rounded-md border border-border p-3 sm:flex-row sm:items-start">
          <div className="min-w-0 flex-1 space-y-1 text-sm">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge>{humanize(suggestion.kind)}</Badge>
              <span className="text-xs text-muted">
                {formatDateTime(suggestion.created_at)} · rule {suggestion.rule_id}
              </span>
            </div>
            <p>{suggestion.message}</p>
            <p className="text-xs text-muted">{KIND_HELP[suggestion.kind]}</p>
          </div>
          {can("content:write") ? (
            <div className="flex shrink-0 gap-1.5">
              <Button size="sm" variant="outline" onClick={() => decide.mutate({ id: suggestion.id, action: "accept" })}>
                <Check className="h-3.5 w-3.5" aria-hidden /> Accept
              </Button>
              <Button size="sm" variant="ghost" onClick={() => decide.mutate({ id: suggestion.id, action: "dismiss" })}>
                <X className="h-3.5 w-3.5" aria-hidden /> Dismiss
              </Button>
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
