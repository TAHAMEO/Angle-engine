import type { Metadata } from "next";

import { AppearanceSettings } from "@/features/settings/appearance";

export const metadata: Metadata = { title: "Appearance settings · Angel Engine" };

export default function Page() {
  return <AppearanceSettings />;
}
