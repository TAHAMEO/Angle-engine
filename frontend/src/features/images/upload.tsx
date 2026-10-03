"use client";

import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileWarning, ImageUp, Loader2, X } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { useDropzone, type FileRejection } from "react-dropzone";

import { UploadNotice } from "@/components/security/notices";
import { Button } from "@/components/ui/button";
import { uploadWithProgress } from "@/lib/api/client";
import { errorFor, messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { bytes } from "@/lib/format";
import { newIdempotencyKey } from "@/lib/ids";
import { path } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { cn } from "@/lib/utils";

import { ACCEPTED_TYPES, MAX_UPLOAD_BYTES } from "./status";

interface Item {
  key: string;
  name: string;
  size: number;
  progress: number;
  state: "uploading" | "done" | "duplicate" | "failed";
  message?: string;
  image?: S<"UploadOut">;
  abort?: AbortController;
}

function rejectionMessage(rejection: FileRejection): string {
  const code = rejection.errors[0]?.code;
  if (code === "file-too-large") return `Larger than ${bytes(MAX_UPLOAD_BYTES)}.`;
  if (code === "file-invalid-type") return "Not a supported image type (JPEG, PNG, GIF, WebP, TIFF or BMP).";
  return rejection.errors[0]?.message ?? "This file cannot be uploaded.";
}

export function ImageUpload({ investigationId }: { investigationId: string }) {
  const client = useQueryClient();
  const [items, setItems] = useState<Item[]>([]);
  const [announcement, setAnnouncement] = useState("");
  const counter = useRef(0);

  const update = (key: string, patch: Partial<Item>) =>
    setItems((current) => current.map((item) => (item.key === key ? { ...item, ...patch } : item)));

  const upload = async (file: File) => {
    const key = `${++counter.current}-${file.name}`;
    const abort = new AbortController();
    const item: Item = { key, name: file.name, size: file.size, progress: 0, state: "uploading", abort };
    setItems((current) => [item, ...current].slice(0, 20));
    try {
      const result = await uploadWithProgress(
        `/api/v1/investigations/${investigationId}/images`,
        file,
        {
          "Content-Type": file.type || "application/octet-stream",
          "Idempotency-Key": newIdempotencyKey(),
          // Only a sanitized basename is sent; the API stores it encrypted.
          "X-Filename": encodeURIComponent(file.name.split(/[\\/]/).pop()!.slice(0, 200)),
        },
        (fraction) => update(key, { progress: fraction }),
        abort.signal,
      );
      if (result.status >= 200 && result.status < 300) {
        const image = result.body as S<"UploadOut">;
        update(key, { state: image.duplicate ? "duplicate" : "done", progress: 1, image });
        setAnnouncement(`${file.name} uploaded. Scanning and analysis have started.`);
        void client.invalidateQueries({ queryKey: qk.images(investigationId) });
      } else {
        const error = errorFor(result.status, result.body);
        update(key, { state: "failed", message: messageOf(error) });
        setAnnouncement(`${file.name} was not uploaded: ${messageOf(error)}`);
      }
    } catch (error) {
      update(key, { state: "failed", message: error instanceof DOMException ? "Cancelled." : messageOf(error) });
    }
  };

  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    accept: ACCEPTED_TYPES,
    maxSize: MAX_UPLOAD_BYTES,
    multiple: true,
    noClick: true,
    noKeyboard: true,
    onDropAccepted: (files) => files.forEach((file) => void upload(file)),
    onDropRejected: (rejections) =>
      setItems((current) => [
        ...rejections.map((r) => ({
          key: `${++counter.current}-${r.file.name}`,
          name: r.file.name,
          size: r.file.size,
          progress: 0,
          state: "failed" as const,
          message: rejectionMessage(r),
        })),
        ...current,
      ]),
  });

  return (
    <section aria-labelledby="upload-heading" className="space-y-3">
      <h2 id="upload-heading" className="sr-only">
        Upload images
      </h2>
      <UploadNotice />
      <div
        {...getRootProps()}
        className={cn(
          "flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-8 text-center transition-colors",
          isDragActive ? "border-primary bg-primary/5" : "border-border-strong/60 bg-surface",
        )}
      >
        {/* The visible "Choose images" button opens this input; hide the duplicate control from assistive tech. */}
        <input {...getInputProps()} aria-label="Image files" aria-hidden="true" />
        <ImageUp className="h-8 w-8 text-muted" aria-hidden />
        <div className="space-y-1">
          <p className="font-medium">{isDragActive ? "Drop the images to upload them" : "Drag images here, or choose files"}</p>
          <p className="text-[13px] text-muted">
            JPEG, PNG, GIF, WebP, TIFF or BMP · up to {bytes(MAX_UPLOAD_BYTES)} each. Files are scanned for malware, analyzed in a sandbox
            and the original is deleted after analysis.
          </p>
        </div>
        <Button type="button" variant="primary" onClick={open}>
          Choose images
        </Button>
      </div>
      <p aria-live="polite" className="sr-only">
        {announcement}
      </p>
      {items.length ? (
        <ul className="space-y-1.5" aria-label="Uploads">
          {items.map((item) => (
            <li key={item.key} className="flex items-center gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm">
              {item.state === "uploading" ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-muted" aria-hidden />
              ) : item.state === "failed" ? (
                <FileWarning className="h-4 w-4 shrink-0 text-danger" aria-hidden />
              ) : (
                <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden />
              )}
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium">{item.name}</p>
                {item.state === "uploading" ? (
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-3" role="progressbar" aria-label={`Uploading ${item.name}`} aria-valuenow={Math.round(item.progress * 100)} aria-valuemin={0} aria-valuemax={100}>
                    <div className="h-full bg-primary transition-[width]" style={{ width: `${Math.round(item.progress * 100)}%` }} />
                  </div>
                ) : (
                  <p className={cn("text-xs", item.state === "failed" ? "text-danger" : "text-muted")}>
                    {item.state === "failed"
                      ? item.message
                      : item.state === "duplicate"
                        ? `Already uploaded as ${item.image?.label}.`
                        : `Uploaded as ${item.image?.label} — scanning and analysis started.`}
                  </p>
                )}
              </div>
              {item.image ? (
                <Link href={`${path(investigationId, "images")}/${item.image.id}`} className="text-[13px] text-primary hover:underline">
                  Open
                </Link>
              ) : null}
              {item.state === "uploading" ? (
                <Button size="icon" variant="ghost" aria-label={`Cancel upload of ${item.name}`} onClick={() => item.abort?.abort()}>
                  <X className="h-4 w-4" aria-hidden />
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
