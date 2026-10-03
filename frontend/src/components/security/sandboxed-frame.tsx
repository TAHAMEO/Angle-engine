/** Untrusted HTML (report previews) is only ever shown in a fully sandboxed frame from the API. */
export function SandboxedFrame({ src, title, className }: { src: string; title: string; className?: string }) {
  return (
    <iframe
      src={src}
      title={title}
      sandbox=""
      referrerPolicy="no-referrer"
      loading="lazy"
      className={className ?? "h-[70vh] w-full rounded-lg border border-border bg-white"}
    />
  );
}
