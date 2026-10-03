import type { Metadata } from "next";

import { ReviewQueue } from "@/features/reviews/review-queue";

export const metadata: Metadata = { title: "Reviews" };

export default function Page() {
  return <ReviewQueue />;
}
