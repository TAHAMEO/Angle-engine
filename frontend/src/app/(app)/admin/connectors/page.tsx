import type { Metadata } from "next";

import { AdminConnectors } from "@/features/admin/other";

export const metadata: Metadata = { title: "Connectors" };

export default function Page() {
  return <AdminConnectors />;
}
