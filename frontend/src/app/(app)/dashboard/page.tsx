import type { Metadata } from "next";

import { WorkspaceDashboard } from "@/features/dashboard/workspace-dashboard";

export const metadata: Metadata = { title: "Dashboard · Angel Engine" };

export default function DashboardPage() {
  return <WorkspaceDashboard />;
}
