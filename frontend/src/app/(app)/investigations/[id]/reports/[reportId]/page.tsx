import type { Metadata } from "next";

import { ReportBuilder } from "@/features/reports/report-builder";

export const metadata: Metadata = { title: "Report" };

export default function Page() {
  return <ReportBuilder />;
}
