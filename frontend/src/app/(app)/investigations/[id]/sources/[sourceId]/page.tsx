import type { Metadata } from "next";

import { SourceDetailView } from "@/features/sources/source-detail";

export const metadata: Metadata = { title: "Source · Angel Engine" };

export default function Page() {
  return <SourceDetailView />;
}
