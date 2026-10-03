"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Badge, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState, Spinner } from "@/components/ui/feedback";
import { Field, Textarea } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { ImageDetail } from "@/lib/api/types";
import { humanize } from "@/lib/format";
import { newIdempotencyKey } from "@/lib/ids";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { useSession } from "@/lib/session";

const RELATION: Record<string, string> = {
  identical: "Identical file",
  same_pixels: "Same pixels",
  near_duplicate: "Near-duplicate",
  similar: "Visually similar",
  crop: "Possible crop",
};

function SimilarImages({ image }: { image: ImageDetail }) {
  const { investigation: inv } = useInvestigation();
  const { data, isPending } = useQuery({
    queryKey: qk.similar(inv.id, image.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/images/{image_id}/similar", {
          params: { path: { investigation_id: inv.id, image_id: image.id } },
        }),
      ),
  });
  if (isPending) return <Spinner />;
  if (!data) return null;
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Duplicates in your investigations</h3>
      <p className="text-[13px] text-muted">
        Compared by perceptual hashes (pHash/dHash, crop-resistant) — not by faces. Only investigations you are a member of are searched.
      </p>
      {!data.cross_investigation.allowed && data.cross_investigation.reason ? (
        <p className="text-[13px] text-muted">Other investigations: {data.cross_investigation.reason}</p>
      ) : null}
      {data.matches.length ? (
        <Table caption="Similar images">
          <thead>
            <tr>
              <Th>Image</Th>
              <Th>Investigation</Th>
              <Th>Relation</Th>
              <Th className="text-right">pHash distance</Th>
            </tr>
          </thead>
          <tbody>
            {data.matches.map((match) => (
              <tr key={match.image_id}>
                <Td className="font-mono text-xs">
                  <Link href={`/investigations/${match.investigation_id}/images/${match.image_id}`} className="text-primary underline underline-offset-2 hover:decoration-2">
                    {match.label}
                  </Link>
                </Td>
                <Td className="font-mono text-xs">{match.same_investigation ? "This investigation" : match.investigation_ref}</Td>
                <Td>{RELATION[match.relation] ?? humanize(match.relation)}</Td>
                <Td className="text-right tabular">{match.phash_distance}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <EmptyState title="No duplicates found" className="py-6" />
      )}
    </div>
  );
}

function ApprovalForm({ image }: { image: ImageDetail }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [purpose, setPurpose] = useState("");
  const approve = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/images/{image_id}/reverse-search-approval", {
          params: { path: { investigation_id: inv.id, image_id: image.id } },
          body: { purpose },
        }),
      ),
    onSuccess: () => {
      toast("Approval recorded", { tone: "success" });
      void client.invalidateQueries({ queryKey: qk.image(inv.id, image.id) });
    },
    onError: (error) => toast("Approval was not recorded", { description: messageOf(error), tone: "danger" }),
  });
  return (
    <form
      className="space-y-2 rounded-md border border-border p-3"
      onSubmit={(event) => {
        event.preventDefault();
        approve.mutate();
      }}
    >
      <Field label="Supervisor approval: why is a public-occurrence search needed?" required hint="At least 30 characters. Recorded in the audit log.">
        {(props) => <Textarea {...props} rows={2} value={purpose} onChange={(event) => setPurpose(event.target.value)} />}
      </Field>
      <Button type="submit" size="sm" variant="secondary" loading={approve.isPending} disabled={purpose.trim().length < 30}>
        <ShieldCheck className="h-4 w-4" aria-hidden /> Approve search
      </Button>
    </form>
  );
}

function PublicOccurrences({ image }: { image: ImageDetail }) {
  const { investigation: inv, can } = useInvestigation();
  const { data: session } = useSession();
  const client = useQueryClient();
  const gate = image.reverse_search;
  const search = useMutation({
    mutationFn: (provider: "tineye" | "google_vision") =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/images/{image_id}/public-occurrence-search", {
          params: { path: { investigation_id: inv.id, image_id: image.id }, header: { "idempotency-key": newIdempotencyKey() } },
          body: { provider },
        }),
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: qk.runs(inv.id) });
      toast("Search started", { description: "Matches are added as sources with their crawl dates.", tone: "success" });
    },
    onError: (error) => toast("The search did not start", { description: messageOf(error), tone: "danger" }),
  });
  const isSupervisor = session?.user?.role === "supervisor";
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Where else is this image published?</h3>
      <p className="text-[13px] text-muted">
        Sends only the sanitized preview (faces and sensitive text blurred) to TinEye or Google Cloud Vision. Matching is by image
        fingerprint — never by face.
      </p>
      {gate.allowed ? (
        can("content:write") ? (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" loading={search.isPending && search.variables === "tineye"} onClick={() => search.mutate("tineye")}>
              <Globe className="h-4 w-4" aria-hidden /> Search with TinEye
            </Button>
            <Button size="sm" variant="outline" loading={search.isPending && search.variables === "google_vision"} onClick={() => search.mutate("google_vision")}>
              <Globe className="h-4 w-4" aria-hidden /> Search with Google Vision
            </Button>
          </div>
        ) : null
      ) : (
        <Alert tone="info" title="Not available for this image">
          {gate.reason}
          {gate.needs_approval && !gate.approved ? (
            <span className="block">
              {isSupervisor && !image.uploaded_by_me
                ? "As a supervisor who did not upload it, you can approve the search with a recorded purpose."
                : "A supervisor who did not upload the image must approve it with a recorded purpose."}
            </span>
          ) : null}
        </Alert>
      )}
      {gate.needs_approval && !gate.approved && isSupervisor && !image.uploaded_by_me ? <ApprovalForm image={image} /> : null}
      {gate.approved ? <Badge className="border-success/50 text-success">Approved by a supervisor</Badge> : null}
    </div>
  );
}

export function MatchesPanel({ image }: { image: ImageDetail }) {
  return (
    <div className="space-y-6">
      <SimilarImages image={image} />
      <PublicOccurrences image={image} />
    </div>
  );
}

export function LinkedPanel({ image }: { image: ImageDetail }) {
  const { investigation: inv } = useInvestigation();
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div>
        <h3 className="mb-2 text-sm font-semibold">Evidence from this image</h3>
        {image.evidence.length ? (
          <ul className="space-y-1">
            {image.evidence.map((item) => (
              <li key={item.id} className="text-sm">
                <Link href={`${path(inv.id, "evidence")}?tab=items&evidence=${item.id}`} className="font-mono text-primary underline underline-offset-2 hover:decoration-2">
                  {item.label}
                </Link>{" "}
                <span className="text-muted">{humanize(item.kind)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">None yet.</p>
        )}
      </div>
      <div>
        <h3 className="mb-2 text-sm font-semibold">Findings citing it</h3>
        {image.findings.length ? (
          <ul className="space-y-1">
            {image.findings.map((item) => (
              <li key={item.id} className="text-sm">
                <Link href={`${path(inv.id, "evidence")}?finding=${item.id}`} className="font-mono text-primary underline underline-offset-2 hover:decoration-2">
                  {item.label}
                </Link>{" "}
                <span className="text-muted">{item.verification_status ? humanize(item.verification_status) : ""}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">None yet.</p>
        )}
      </div>
    </div>
  );
}
