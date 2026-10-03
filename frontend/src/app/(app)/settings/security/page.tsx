import type { Metadata } from "next";

import { SecuritySettings } from "@/features/settings/security";

export const metadata: Metadata = { title: "Security settings · Angel Engine" };

export default function Page() {
  return <SecuritySettings />;
}
