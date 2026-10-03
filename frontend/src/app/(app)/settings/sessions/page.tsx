import type { Metadata } from "next";

import { SessionsSettings } from "@/features/settings/sessions";

export const metadata: Metadata = { title: "Sessions settings" };

export default function Page() {
  return <SessionsSettings />;
}
