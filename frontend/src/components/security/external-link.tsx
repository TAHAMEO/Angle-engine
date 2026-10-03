import { ExternalLink as Icon } from "lucide-react";

import { cn } from "@/lib/utils";

/** Show the punycode hostname so look-alike domains are visible. */
export function displayHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Links to public sources: http(s) only, no referrer, no opener, never followed by crawlers. Opening a live page
 * reveals your IP address to that site — the captured copy in Angel Engine is the default way to read it.
 */
export function ExternalLink({
  href,
  children,
  className,
  showHost = true,
}: {
  href: string;
  children?: React.ReactNode;
  className?: string;
  showHost?: boolean;
}) {
  let safe: string | null = null;
  try {
    const url = new URL(href);
    if (url.protocol === "https:" || url.protocol === "http:") safe = url.toString();
  } catch {
    safe = null;
  }
  if (!safe) return <span className={cn("break-all", className)}>{children ?? href}</span>;
  return (
    <a
      href={safe}
      target="_blank"
      rel="noopener noreferrer nofollow"
      referrerPolicy="no-referrer"
      className={cn("inline-flex max-w-full items-baseline gap-1 break-all text-primary underline underline-offset-2 hover:decoration-2", className)}
      title="Opens the live page in a new tab — the site will see your IP address"
    >
      <span className="min-w-0">{children ?? (showHost ? displayHost(safe) : safe)}</span>
      <Icon className="h-3 w-3 shrink-0 self-center" aria-hidden />
      <span className="sr-only">(opens the live site in a new tab)</span>
    </a>
  );
}
