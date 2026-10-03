"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Laptop, LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader } from "@/components/ui/data";
import { LoadingBlock } from "@/components/ui/feedback";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { formatDateTime, relative } from "@/lib/format";

export function SessionsSettings() {
  const client = useQueryClient();
  const { data, error, isPending, refetch } = useQuery({ queryKey: ["me", "sessions"], queryFn: () => unwrap(api.GET("/api/v1/me/sessions")) });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/api/v1/me/sessions/{session_id}", { params: { path: { session_id: id } } })),
    onSuccess: () => {
      toast("Session signed out");
      void client.invalidateQueries({ queryKey: ["me", "sessions"] });
    },
    onError: (e) => toast("Could not sign out the session", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Card>
      <CardHeader
        title="Active sessions"
        description="Sessions end after 30 minutes of inactivity or 12 hours at most. Only the browser family is recorded — never your IP address."
      />
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <div className="p-4">
          <QueryError error={error} retry={() => void refetch()} />
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {data?.map((session) => (
            <li key={session.id} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
              <Laptop className="h-5 w-5 text-muted" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="font-medium">
                  {session.ua_family ?? "Unknown browser"} {session.current ? <Badge className="ml-1 border-success/50 text-success">This session</Badge> : null}
                </p>
                <p className="text-xs text-muted">
                  Signed in {formatDateTime(session.created_at)} · last active {relative(session.last_seen_at)} · ends {relative(session.absolute_expires_at)}
                </p>
              </div>
              {!session.current ? (
                <Button size="sm" variant="secondary" loading={revoke.isPending && revoke.variables === session.id} onClick={() => revoke.mutate(session.id)}>
                  <LogOut className="h-3.5 w-3.5" aria-hidden /> Sign out
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
