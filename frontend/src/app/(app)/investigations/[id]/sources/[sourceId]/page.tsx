import type { Metadata } from "next";

import { SourceDetailView } from "@/features/sources/source-detail";

export const metadata: Metadata = { title: "Source" };

export default function Page() {
  return <SourceDetailView />;
}
