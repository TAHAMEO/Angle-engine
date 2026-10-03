import type { Metadata } from "next";

import { LegalDocument } from "@/features/public/legal-document";

const KINDS: Record<string, { kind: string; title: string }> = {
  terms: { kind: "terms", title: "Terms of Use" },
  privacy: { kind: "privacy", title: "Privacy Policy" },
  "acceptable-use": { kind: "acceptable_use", title: "Acceptable Use Policy" },
  "responsible-use": { kind: "responsible_use", title: "Responsible Use & Methodology" },
};

export async function generateMetadata({ params }: { params: Promise<{ doc: string }> }): Promise<Metadata> {
  const { doc } = await params;
  return { title: KINDS[doc]?.title ?? "Legal" };
}

export default async function LegalPage({ params }: { params: Promise<{ doc: string }> }) {
  const { doc } = await params;
  const entry = KINDS[doc];
  return <LegalDocument kind={entry?.kind ?? null} title={entry?.title ?? "Document not found"} />;
}
