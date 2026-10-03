"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MessageSquarePlus, Trash2 } from "lucide-react";
import { useState } from "react";

import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { EmptyState, Spinner } from "@/components/ui/feedback";
import { Textarea } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import { formatDateTime } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

type Target = "investigation" | "image" | "finding" | "source" | "entity" | "evidence";

/** Analyst notes. Notes are screened by the acceptable-use policy and redacted before they are stored (encrypted). */
export function NotesPanel({ targetType, targetId }: { targetType: Target; targetId?: string }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const [body, setBody] = useState("");
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const key = qk.notes(inv.id, { targetType, targetId });
  const { data, isPending } = useQuery({
    queryKey: key,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/notes", {
          params: { path: { investigation_id: inv.id }, query: { target_type: targetType, target_id: targetId } },
        }),
      ),
  });
  const add = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/notes", {
          params: { path: { investigation_id: inv.id } },
          body: { body, target_type: targetType, target_id: targetId ?? null },
        }),
      ),
    onSuccess: (note) => {
      setBody("");
      setPolicy(null);
      const redacted = Object.values(note.redaction_counts ?? {}).reduce((a, b) => a + b, 0);
      toast("Note saved", redacted ? { description: `${redacted} sensitive item(s) were redacted.` } : {});
      void client.invalidateQueries({ queryKey: key });
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError) setPolicy(error.policy);
      else toast("The note was not saved", { description: messageOf(error), tone: "danger" });
    },
  });
  const remove = useMutation({
    mutationFn: (noteId: string) =>
      unwrap(api.DELETE("/api/v1/investigations/{investigation_id}/notes/{note_id}", { params: { path: { investigation_id: inv.id, note_id: noteId } } })),
    onSuccess: () => void client.invalidateQueries({ queryKey: key }),
    onError: (error) => toast("The note was not deleted", { description: messageOf(error), tone: "danger" }),
  });

  return (
    <div className="space-y-3">
      {isPending ? (
        <Spinner />
      ) : data?.length ? (
        <ul className="space-y-2">
          {data.map((note) => (
            <li key={note.id} className="rounded-md border border-border bg-surface-2/50 p-3 text-sm">
              <p className="whitespace-pre-line">{note.body}</p>
              <div className="mt-2 flex items-center justify-between text-xs text-muted">
                <span>
                  {note.author_name ?? "Former member"} · {formatDateTime(note.created_at)}
                </span>
                {note.is_author ? (
                  <Button size="sm" variant="ghost" aria-label="Delete note" onClick={() => remove.mutate(note.id)}>
                    <Trash2 className="h-3.5 w-3.5" aria-hidden />
                  </Button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState title="No notes yet" className="py-6" />
      )}
      {can("content:write") ? (
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            add.mutate();
          }}
        >
          <label className="block text-sm font-medium" htmlFor={`note-${targetType}-${targetId ?? "inv"}`}>
            Add a note
          </label>
          <Textarea
            id={`note-${targetType}-${targetId ?? "inv"}`}
            rows={3}
            maxLength={10000}
            value={body}
            onChange={(event) => setBody(event.target.value)}
            placeholder="Observations, next steps, caveats…"
          />
          {policy ? <PolicyDecisionPanel policy={policy} /> : null}
          <Button type="submit" size="sm" variant="secondary" loading={add.isPending} disabled={!body.trim()}>
            <MessageSquarePlus className="h-4 w-4" aria-hidden /> Save note
          </Button>
        </form>
      ) : null}
    </div>
  );
}
