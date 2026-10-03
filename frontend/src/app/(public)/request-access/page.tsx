import type { Metadata } from "next";

import { RequestAccessForm } from "@/features/public/request-access";

export const metadata: Metadata = { title: "Request access" };

export default function RequestAccessPage() {
  return <RequestAccessForm />;
}
