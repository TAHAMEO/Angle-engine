import type { Metadata } from "next";

import { WorkspaceDashboard } from "@/features/dashboard/workspace-dashboard";

export const metadata: Metadata = { title: "Dashboard" };

export default function DashboardPage() {
  return <WorkspaceDashboard />;
}
