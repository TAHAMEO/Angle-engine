import type { Metadata } from "next";

import { NewInvestigationWizard } from "@/features/investigations/new-investigation-wizard";

export const metadata: Metadata = { title: "New investigation" };

export default function NewInvestigationPage() {
  return <NewInvestigationWizard />;
}
