"use client";

import { useQuery } from "@tanstack/react-query";

import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Markdown } from "@/components/ui/markdown";
import { api, unwrap } from "@/lib/api/client";

export function useLegalDocuments() {
  return useQuery({
    queryKey: ["legal", "current"],
    queryFn: () => unwrap(api.GET("/api/v1/legal/documents/current")),
    staleTime: 10 * 60_000,
  });
}

export function LegalDocument({ kind, title }: { kind: string | null; title: string }) {
  const { data, isPending, isError } = useLegalDocuments();
  const doc = data?.find((d) => d.kind === kind);
  return (
    <article className="w-full max-w-3xl space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">{doc?.title ?? title}</h1>
      {isPending ? <LoadingBlock /> : null}
      {isError || (!isPending && !doc) ? <Alert tone="danger">This document could not be found.</Alert> : null}
      {doc ? (
        <>
          <p className="text-sm text-muted">
            Version {doc.version} · effective {doc.effective} · SHA-256 <span className="font-mono">{doc.sha256.slice(0, 16)}</span>
          </p>
          <Markdown source={doc.body_markdown} />
        </>
      ) : null}
    </article>
  );
}
