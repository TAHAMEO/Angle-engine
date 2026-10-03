import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingBlock } from "@/components/ui/feedback";
import { InvestigationHistory } from "@/features/investigations/history";

export const metadata: Metadata = { title: "Investigation history" };

export default function InvestigationsPage() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <InvestigationHistory />
    </Suspense>
  );
}
