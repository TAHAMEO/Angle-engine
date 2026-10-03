"use client";

import { useQuery } from "@tanstack/react-query";
import { ImageOff, ImageIcon, ScanFace, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/shell/app-shell";
import { Badge } from "@/components/ui/data";
import { EmptyState, LoadingBlock, Spinner } from "@/components/ui/feedback";
import { QueryError } from "@/features/common/states";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import type { ImageOut } from "@/lib/api/types";
import { bytes, relative } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { cn } from "@/lib/utils";

import { IN_PROGRESS, previewUrl } from "./status";
import { ImageUpload } from "./upload";

function StatusPill({ image }: { image: ImageOut }) {
  const busy = IN_PROGRESS.has(image.status);
  const bad = ["infected", "scan_failed", "analysis_failed"].includes(image.status);
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs", bad ? "text-danger" : busy ? "text-primary" : "text-muted")}>
      {busy ? <Spinner className="h-3 w-3" label="In progress" /> : null}
      {image.status_label}
    </span>
  );
}

export function ImageCard({ image, investigationId }: { image: ImageOut; investigationId: string }) {
  return (
    <li className="overflow-hidden rounded-lg border border-border bg-surface">
      <Link href={`${path(investigationId, "images")}/${image.id}`} className="group block focus-visible:outline-offset-[-2px]">
        <div className="relative grid aspect-[4/3] place-items-center overflow-hidden bg-surface-3">
          {image.has_preview ? (
            // Only the sanitized, face-blurred preview is ever requested.
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={previewUrl(investigationId, image.id)}
              alt={`Sanitized preview of image ${image.label}`}
              loading="lazy"
              referrerPolicy="no-referrer"
              className="h-full w-full object-cover transition-transform group-hover:scale-[1.02]"
            />
          ) : (
            <ImageOff className="h-8 w-8 text-subtle" aria-hidden />
          )}
          {image.face_count > 0 ? (
            <span className="absolute top-2 left-2 inline-flex items-center gap-1 rounded bg-black/70 px-1.5 py-0.5 text-[11px] font-medium text-white">
              <ScanFace className="h-3 w-3" aria-hidden /> Face detected · blurred
            </span>
          ) : null}
        </div>
        <div className="space-y-1 p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-xs font-semibold">{image.label}</span>
            <StatusPill image={image} />
          </div>
          <p className="truncate text-sm">{image.filename ?? "Untitled image"}</p>
          <p className="text-xs text-muted">
            {image.width && image.height ? `${image.width}×${image.height} · ` : ""}
            {bytes(image.byte_size)} · {relative(image.created_at)}
          </p>
          <div className="flex flex-wrap gap-1">
            {image.metadata_availability ? <Badge>Metadata: {image.metadata_availability}</Badge> : null}
            {image.scan.degraded ? (
              <Badge className="border-warning/60 text-warning">
                <ShieldAlert className="h-3 w-3" aria-hidden /> Basic scan only
              </Badge>
            ) : null}
          </div>
        </div>
      </Link>
    </li>
  );
}

export function ImageList() {
  const { investigation: inv, can } = useInvestigation();
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.images(inv.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/images", {
          params: { path: { investigation_id: inv.id } },
          headers: BACKGROUND,
        }),
      ),
    refetchInterval: (query) => (query.state.data?.some((image) => IN_PROGRESS.has(image.status)) ? 2000 : false),
  });
  return (
    <>
      <PageHeader
        title="Image analysis"
        description="Non-biometric analysis only: file checks, metadata (location generalized to region), visible text, objects, perceptual hashes and duplicates. Faces are detected only to blur them — never identified."
      />
      <div className="space-y-8">
        {can("content:write") ? <ImageUpload investigationId={inv.id} /> : null}
        <section aria-labelledby="images-heading" className="space-y-3">
          <h2 id="images-heading" className="text-base font-semibold">
            Images {data ? <span className="text-muted">({data.length})</span> : null}
          </h2>
          {isPending ? (
            <LoadingBlock />
          ) : error ? (
            <QueryError error={error} retry={() => void refetch()} />
          ) : data?.length ? (
            <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
              {data.map((image) => (
                <ImageCard key={image.id} image={image} investigationId={inv.id} />
              ))}
            </ul>
          ) : (
            <EmptyState icon={ImageIcon} title="No images yet">
              Upload an image to extract metadata, visible text, objects and hashes, and to find duplicates in your investigations.
            </EmptyState>
          )}
        </section>
      </div>
    </>
  );
}
