import type { Metadata } from "next";

import { InvestigationDataControls } from "@/features/data-controls/investigation-data-controls";

export const metadata: Metadata = { title: "Data controls · Angel Engine" };

export default function Page() {
  return <InvestigationDataControls />;
}
