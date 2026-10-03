import { ScanFace, ShieldCheck } from "lucide-react";

/** Required verbatim texts. Do not reword. */
export const FACE_NOTICE = "A face was detected in the image. Angel Engine does not perform facial identification.";
export const UPLOAD_NOTICE =
  "Upload only images you are legally authorized to investigate. Angel Engine does not perform facial identification.";
export const INSUFFICIENT = "Insufficient public evidence to establish this conclusion.";

export function FaceNotice({ className }: { className?: string }) {
  return (
    <div
      role="note"
      className={`flex items-start gap-2.5 rounded-lg border border-warning/50 bg-warning-bg px-3.5 py-2.5 text-sm ${className ?? ""}`}
    >
      <ScanFace className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <p className="font-medium">{FACE_NOTICE}</p>
    </div>
  );
}

export function UploadNotice({ className }: { className?: string }) {
  return (
    <div
      role="note"
      className={`flex items-start gap-2.5 rounded-lg border border-primary/40 bg-info-bg px-3.5 py-2.5 text-sm ${className ?? ""}`}
    >
      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
      <p className="font-medium">{UPLOAD_NOTICE}</p>
    </div>
  );
}
