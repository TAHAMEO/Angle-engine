import type { Metadata } from "next";

import { AccountDataControls } from "@/features/data-controls/account-data-controls";

export const metadata: Metadata = { title: "Privacy & data controls" };

export default function Page() {
  return <AccountDataControls />;
}
