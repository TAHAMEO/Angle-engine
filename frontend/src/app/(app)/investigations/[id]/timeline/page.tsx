import type { Metadata } from "next";

import { TimelinePage } from "@/features/timeline/timeline-page";

export const metadata: Metadata = { title: "Timeline · Angel Engine" };

export default function Page() {
  return <TimelinePage />;
}
