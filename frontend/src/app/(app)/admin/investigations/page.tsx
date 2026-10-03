import type { Metadata } from "next";

import { AdminInvestigations } from "@/features/admin/investigations";

export const metadata: Metadata = { title: "Investigations (administration)" };

export default function Page() {
  return <AdminInvestigations />;
}
