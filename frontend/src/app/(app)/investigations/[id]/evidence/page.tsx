import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingBlock } from "@/components/ui/feedback";
import { EvidencePage } from "@/features/evidence/evidence-page";

export const metadata: Metadata = { title: "Evidence · Angel Engine" };

export default function Page() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <EvidencePage />
    </Suspense>
  );
}
