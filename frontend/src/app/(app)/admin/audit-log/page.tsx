import type { Metadata } from "next";

import { AuditLog } from "@/features/admin/other";

export const metadata: Metadata = { title: "Audit log · Angel Engine" };

export default function Page() {
  return <AuditLog />;
}
