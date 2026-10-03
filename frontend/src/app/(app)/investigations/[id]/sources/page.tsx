import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingBlock } from "@/components/ui/feedback";
import { SourcesPage } from "@/features/sources/sources-page";

export const metadata: Metadata = { title: "Sources · Angel Engine" };

export default function Page() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <SourcesPage />
    </Suspense>
  );
}
