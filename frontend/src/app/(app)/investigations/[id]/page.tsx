import type { Metadata } from "next";

import { InvestigationOverview } from "@/features/investigations/overview";

export const metadata: Metadata = { title: "Investigation overview" };

export default function InvestigationPage() {
  return <InvestigationOverview />;
}
