"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, PackageOpen } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader } from "@/components/ui/data";
import { Spinner } from "@/components/ui/feedback";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { downloadFile } from "@/lib/download";
import { formatDateTime, humanize, relative } from "@/lib/format";

const KEY = ["me", "data-exports"] as const;

export function ExportMyData() {
  const client = useQueryClient();
  const { data, isPending } = useQuery({
    queryKey: KEY,
    queryFn: () => unwrap(api.GET("/api/v1/me/data-exports", { headers: BACKGROUND })),
    refetchInterval: (query) => (query.state.data?.some((x) => x.status === "pending") ? 1500 : false),
  });
  const request = useMutation({
    mutationFn: () => withReauth(() => unwrap(api.POST("/api/v1/me/data-exports"))),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: KEY });
      toast("Export requested", { description: "It is prepared in the background and can be downloaded once." });
    },
    onError: (e) => toast("The export was not requested", { description: messageOf(e), tone: "danger" }),
  });
  const download = async (id: string) => {
    try {
      await downloadFile(`/api/v1/me/data-exports/${id}/download`, "angel-engine-account-export.zip");
      void client.invalidateQueries({ queryKey: KEY });
    } catch (e) {
      toast("Download failed", { description: messageOf(e), tone: "danger" });
    }
  };
  return (
    <Card>
      <CardHeader
        title="Export my data"
        description="A ZIP of your account data: profile, sessions, attestations, acceptable-use decisions, memberships and your audit entries. Encrypted at rest; one download within 24 hours."
      />
      <div className="space-y-3 p-4">
        <Button variant="secondary" loading={request.isPending} onClick={() => request.mutate()}>
          <PackageOpen className="h-4 w-4" aria-hidden /> Request export
        </Button>
        {isPending ? <Spinner /> : null}
        {data?.length ? (
          <ul className="divide-y divide-border rounded-md border border-border">
            {data.map((x) => (
              <li key={x.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                <Badge>{humanize(x.status)}</Badge>
                <span className="text-muted">
                  Requested {formatDateTime(x.created_at)}
                  {x.status === "ready" ? ` · expires ${relative(x.expires_at)}` : ""}
                  {x.downloaded_at ? ` · downloaded ${formatDateTime(x.downloaded_at)}` : ""}
                </span>
                {x.status === "pending" ? <Spinner className="h-3.5 w-3.5" label="Preparing" /> : null}
                {x.status === "ready" ? (
                  <Button size="sm" variant="outline" className="ml-auto" onClick={() => void download(x.id)}>
                    <Download className="h-3.5 w-3.5" aria-hidden /> Download
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}
