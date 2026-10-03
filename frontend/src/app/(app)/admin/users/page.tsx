import type { Metadata } from "next";

import { AdminUsers } from "@/features/admin/users";

export const metadata: Metadata = { title: "Users · Angel Engine" };

export default function Page() {
  return <AdminUsers />;
}
