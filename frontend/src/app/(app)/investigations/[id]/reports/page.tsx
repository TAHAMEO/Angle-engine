import type { Metadata } from "next";

import { ReportsList } from "@/features/reports/reports-list";

export const metadata: Metadata = { title: "Reports · Angel Engine" };

export default function Page() {
  return <ReportsList />;
}
