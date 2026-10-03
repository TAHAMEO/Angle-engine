import type { Metadata } from "next";

import { ReviewQueue } from "@/features/reviews/review-queue";

export const metadata: Metadata = { title: "Reviews · Angel Engine" };

export default function Page() {
  return <ReviewQueue />;
}
