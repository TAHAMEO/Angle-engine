import type { Metadata } from "next";

import { AcceptTerms } from "@/features/gates/accept-terms";

export const metadata: Metadata = { title: "Updated terms" };

export default function AcceptTermsPage() {
  return <AcceptTerms />;
}
