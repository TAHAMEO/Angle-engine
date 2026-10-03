import type { Metadata } from "next";

import { ReportAbuseForm } from "@/features/public/report-abuse";

export const metadata: Metadata = { title: "Report abuse" };

export default function ReportAbusePage() {
  return <ReportAbuseForm />;
}
