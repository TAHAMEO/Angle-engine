import type { Metadata } from "next";

import { AdminRetention } from "@/features/admin/other";

export const metadata: Metadata = { title: "Retention · Angel Engine" };

export default function Page() {
  return <AdminRetention />;
}
