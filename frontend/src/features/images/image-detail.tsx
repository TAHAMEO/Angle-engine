"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ImageOff, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

import { FACE_NOTICE, FaceNotice } from "@/components/security/notices";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card, Tabs } from "@/components/ui/data";
import { Alert, LoadingBlock, Spinner } from "@/components/ui/feedback";
import { Checkbox } from "@/components/ui/form";
import { Menu } from "@/components/ui/menu";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { QueryError } from "@/features/common/states";
import { NotesPanel } from "@/features/notes/notes-panel";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { ImageDetail } from "@/lib/api/types";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { CluesPanel } from "./clues";
import { LinkedPanel, MatchesPanel } from "./matches";
import { MetadataPanel, OverviewPanel, TextPanel, asOcr, type Box } from "./panels";
import { IN_PROGRESS, STAGE_LABELS, previewUrl } from "./status";

function Overlay({ boxes, className, label }: { boxes: { box: Box; title: string }[]; className: string; label: string }) {
  return (
    <div className="pointer-events-none absolute inset-0" aria-hidden data-overlay={label}>
      {boxes.map((item, index) => (
        <div
          key={index}
          title={item.title}
          className={`absolute rounded-[2px] border-2 ${className}`}
          style={{ left: `${item.box.x * 100}%`, top: `${item.box.y * 100}%`, width: `${item.box.w * 100}%`, height: `${item.box.h * 100}%` }}
        />
      ))}
    </div>
  );
}

function ImageViewer({ image, investigationId }: { image: ImageDetail; investigationId: string }) {
  const [showText, setShowText] = useState(false);
  const [showObjects, setShowObjects] = useState(false);
  const ocr = asOcr(image.ocr);
  const textBoxes = (ocr?.lines ?? []).map((line) => ({ box: line.box, title: line.text }));
  const objectBoxes = (image.objects as { label: string; score: number; box: Box }[]).map((o) => ({ box: o.box, title: o.label }));
  return (
    <Card className="overflow-hidden">
      <figure>
        <div className="relative grid min-h-48 place-items-center bg-surface-3">
          {image.has_preview ? (
            <div className="relative inline-block max-w-full">
              {/* Only the sanitized derivative is requested: faces and sensitive text are blurred server-side. */}
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={previewUrl(investigationId, image.id)}
                alt={`Sanitized preview of image ${image.label}${image.face_count ? " with faces blurred" : ""}`}
                referrerPolicy="no-referrer"
                className="block max-h-[70vh] w-auto max-w-full"
              />
              {showText ? <Overlay boxes={textBoxes} className="border-primary/90" label="text" /> : null}
              {showObjects ? <Overlay boxes={objectBoxes} className="border-warning/90 border-dashed" label="objects" /> : null}
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2 p-10 text-sm text-muted">
              <ImageOff className="h-8 w-8" aria-hidden />
              {IN_PROGRESS.has(image.status) ? "The preview appears after analysis." : "No preview is available (the file was deleted or analysis failed)."}
            </div>
          )}
        </div>
        <figcaption className="space-y-2 border-t border-border px-4 py-3 text-[13px] text-muted">
          <p>Sanitized preview: metadata stripped; faces and sensitive text are blurred. The original file is never displayed.</p>
          {image.has_preview && (textBoxes.length || objectBoxes.length) ? (
            <div className="flex flex-wrap gap-4">
              {textBoxes.length ? <Checkbox label="Outline recognized text" checked={showText} onChange={(e) => setShowText(e.target.checked)} /> : null}
              {objectBoxes.length ? (
                <Checkbox label={`Outline detected objects (${objectBoxes.length})`} checked={showObjects} onChange={(e) => setShowObjects(e.target.checked)} />
              ) : null}
            </div>
          ) : null}
        </figcaption>
      </figure>
    </Card>
  );
}

function AnalysisProgress({ image }: { image: ImageDetail }) {
  const progress = (image.progress ?? {}) as { stage?: string; done?: number; total?: number };
  return (
    <Alert tone="info" role="status" title={image.status_label}>
      <span className="inline-flex items-center gap-2">
        <Spinner className="h-4 w-4" label="Analysis in progress" />
        {progress.stage ? `Current stage: ${STAGE_LABELS[progress.stage] ?? progress.stage}` : "Scanning and analysis run in a sandbox without internet access."}
        {progress.total ? ` (${progress.done ?? 0}/${progress.total})` : ""}
      </span>
    </Alert>
  );
}

function DeleteMenu({ image }: { image: ImageDetail }) {
  const { investigation: inv } = useInvestigation();
  const router = useRouter();
  const client = useQueryClient();
  const [scope, setScope] = useState<"file" | "all" | null>(null);
  const remove = useMutation({
    mutationFn: (which: "file" | "all") =>
      withReauth(() =>
        unwrap(
          api.DELETE("/api/v1/investigations/{investigation_id}/images/{image_id}", {
            params: { path: { investigation_id: inv.id, image_id: image.id }, query: { scope: which } },
          }),
        ),
      ),
    onSuccess: (_, which) => {
      setScope(null);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast(which === "all" ? "Image and derived data deleted" : "Image files deleted", { tone: "success" });
      if (which === "all") router.push(path(inv.id, "images"));
    },
    onError: (error) => toast("Deletion failed", { description: messageOf(error), tone: "danger" }),
  });
  return (
    <>
      <Menu
        label="Delete"
        trigger={
          <Button variant="secondary">
            <Trash2 className="h-4 w-4" aria-hidden /> Delete
          </Button>
        }
        items={[
          { label: "Delete the files only (keep analysis results)", onSelect: () => setScope("file"), disabled: Boolean(image.files_deleted_at) },
          { label: "Delete the image and everything derived from it", onSelect: () => setScope("all"), danger: true },
        ]}
      />
      <ConfirmDialog
        open={scope !== null}
        onOpenChange={(open) => !open && setScope(null)}
        title={scope === "all" ? `Delete ${image.label} and its derived data?` : `Delete the files of ${image.label}?`}
        description={
          scope === "all" ? (
            <p>
              The original, the preview, hashes, analysis results, clues and evidence from this image are destroyed. Findings that relied on
              it are downgraded and flagged. This cannot be undone.
            </p>
          ) : (
            <p>The original and the preview are destroyed (their keys are erased). Analysis results, clues and evidence remain.</p>
          )
        }
        confirmLabel="Delete"
        loading={remove.isPending}
        onConfirm={() => scope && remove.mutate(scope)}
      />
    </>
  );
}

export function ImageDetailView() {
  const { investigation: inv, can } = useInvestigation();
  const { imageId } = useParams<{ imageId: string }>();
  const { data: image, error, isPending, refetch } = useQuery({
    queryKey: qk.image(inv.id, imageId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/images/{image_id}", {
          params: { path: { investigation_id: inv.id, image_id: imageId } },
          headers: BACKGROUND,
        }),
      ),
    refetchInterval: (query) => (query.state.data && IN_PROGRESS.has(query.state.data.status) ? 1500 : false),
  });
  if (isPending) return <LoadingBlock label="Loading image" />;
  if (error || !image) return <QueryError error={error} retry={() => void refetch()} />;
  const otherNotices = image.notices.filter((notice) => notice !== FACE_NOTICE);
  return (
    <>
      <PageHeader
        eyebrow={
          <Link href={path(inv.id, "images")} className="inline-flex items-center gap-1 hover:underline">
            <ArrowLeft className="h-3 w-3" aria-hidden /> Image analysis
          </Link>
        }
        title={
          <span>
            <span className="font-mono">{image.label}</span>
            {image.filename ? <span className="ml-2 text-base font-normal text-muted">{image.filename}</span> : null}
          </span>
        }
        actions={can("content:write") && image.status !== "deleted" ? <DeleteMenu image={image} /> : undefined}
      />
      <div className="space-y-4">
        {image.face_count > 0 ? <FaceNotice /> : null}
        {otherNotices.map((notice) => (
          <Alert key={notice} tone="info">
            {notice}
          </Alert>
        ))}
        {IN_PROGRESS.has(image.status) ? <AnalysisProgress image={image} /> : null}
        <div className="grid gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
          <div className="space-y-4">
            <ImageViewer image={image} investigationId={inv.id} />
          </div>
          <Card className="min-w-0 p-4">
            <Tabs
              label="Image analysis results"
              tabs={[
                { value: "overview", label: "Overview", content: <OverviewPanel image={image} /> },
                { value: "clues", label: "Clues", content: <CluesPanel image={image} /> },
                { value: "text", label: "Text", content: <TextPanel image={image} /> },
                { value: "metadata", label: "Metadata", content: <MetadataPanel image={image} /> },
                { value: "matches", label: "Matches", content: <MatchesPanel image={image} /> },
                { value: "linked", label: "Linked", content: <LinkedPanel image={image} /> },
                { value: "notes", label: "Notes", content: <NotesPanel targetType="image" targetId={image.id} /> },
              ]}
            />
          </Card>
        </div>
      </div>
    </>
  );
}
