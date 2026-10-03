import type { Metadata } from "next";

import { MfaSetup } from "@/features/gates/mfa-setup";

export const metadata: Metadata = { title: "Set up multi-factor authentication" };

export default function MfaSetupPage() {
  return <MfaSetup />;
}
