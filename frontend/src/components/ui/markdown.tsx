import Link from "next/link";
import { Fragment } from "react";

import { ExternalLink } from "@/components/security/external-link";

/**
 * Minimal Markdown → React renderer for trusted, repository-owned documents (legal texts). It never produces raw
 * HTML: headings, paragraphs, lists, quotes, emphasis, code and links only.
 */
const INLINE = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\))/g;

function inline(text: string, keyBase: string): React.ReactNode[] {
  return text.split(INLINE).map((part, index) => {
    const key = `${keyBase}-${index}`;
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={key}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("*") && part.endsWith("*") && part.length > 2) return <em key={key}>{part.slice(1, -1)}</em>;
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={key} className="rounded bg-surface-2 px-1 font-mono text-[0.9em]">
          {part.slice(1, -1)}
        </code>
      );
    }
    const link = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(part);
    if (link) {
      const [, label, href] = link;
      if (href!.startsWith("/")) {
        return (
          <Link key={key} href={href!} className="text-primary hover:underline">
            {label}
          </Link>
        );
      }
      return <ExternalLink key={key} href={href!} showHost={false}>{label}</ExternalLink>;
    }
    return <Fragment key={key}>{part}</Fragment>;
  });
}

export function Markdown({ source }: { source: string }) {
  const blocks: React.ReactNode[] = [];
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (!line.trim()) {
      i += 1;
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      const level = heading[1]!.length;
      const Tag = (["h2", "h2", "h3", "h4"] as const)[level - 1]!;
      blocks.push(
        <Tag key={i} className={level <= 2 ? "mt-8 text-lg font-semibold" : "mt-6 font-semibold"}>
          {inline(heading[2]!, `h${i}`)}
        </Tag>,
      );
      i += 1;
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i]!)) {
        items.push(lines[i]!.replace(/^\s*([-*]|\d+\.)\s+/, ""));
        i += 1;
      }
      const List = ordered ? "ol" : "ul";
      blocks.push(
        <List key={i} className={`${ordered ? "list-decimal" : "list-disc"} space-y-1 pl-6`}>
          {items.map((item, n) => (
            <li key={n}>{inline(item, `l${i}-${n}`)}</li>
          ))}
        </List>,
      );
      continue;
    }
    if (line.startsWith(">")) {
      const quote: string[] = [];
      while (i < lines.length && lines[i]!.startsWith(">")) {
        quote.push(lines[i]!.replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push(
        <blockquote key={i} className="border-l-2 border-border-strong pl-3 text-muted">
          {inline(quote.join(" "), `q${i}`)}
        </blockquote>,
      );
      continue;
    }
    const paragraph: string[] = [];
    while (i < lines.length && lines[i]!.trim() && !/^(#{1,4}\s|>|\s*([-*]|\d+\.)\s+)/.test(lines[i]!)) {
      paragraph.push(lines[i]!.trim());
      i += 1;
    }
    blocks.push(<p key={i}>{inline(paragraph.join(" "), `p${i}`)}</p>);
  }
  return <div className="space-y-3 text-sm leading-relaxed">{blocks}</div>;
}
