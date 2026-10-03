import type { Metadata } from "next";

import { AdminJobs } from "@/features/admin/other";

export const metadata: Metadata = { title: "Failed jobs · Angel Engine" };

export default function Page() {
  return <AdminJobs />;
}
