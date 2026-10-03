import type { Metadata } from "next";

import { GraphPage } from "@/features/graph/graph-page";

export const metadata: Metadata = { title: "Relationship graph · Angel Engine" };

export default function Page() {
  return <GraphPage />;
}
