import type { Metadata } from "next";

import { ProfileSettings } from "@/features/settings/profile";

export const metadata: Metadata = { title: "Profile settings · Angel Engine" };

export default function Page() {
  return <ProfileSettings />;
}
