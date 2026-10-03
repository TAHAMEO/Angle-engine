import type { Metadata } from "next";

import { AdminAbuseReports } from "@/features/admin/other";

export const metadata: Metadata = { title: "Abuse reports · Angel Engine" };

export default function Page() {
  return <AdminAbuseReports />;
}
