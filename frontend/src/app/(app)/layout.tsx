"use client";

import { AppShell } from "@/components/shell/app-shell";
import { SessionGate } from "@/lib/session";

export default function AuthenticatedLayout({ children }: { children: React.ReactNode }) {
  return <SessionGate>{(session) => <AppShell session={session}>{children}</AppShell>}</SessionGate>;
}
