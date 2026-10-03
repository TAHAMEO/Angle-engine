"use client";

import {
  Activity,
  ClipboardCheck,
  FilePlus2,
  FileSearch,
  FileText,
  Globe,
  History,
  ImageIcon,
  LayoutDashboard,
  Network,
  ScrollText,
  Settings,
  ShieldCheck,
  CalendarClock,
  UserCog,
  Gauge,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import type { User } from "@/lib/api/types";
import { cn } from "@/lib/utils";

export interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  match?: (path: string) => boolean;
}

export function investigationNav(id: string): NavItem[] {
  const base = `/investigations/${id}`;
  return [
    { href: base, label: "Overview", icon: Gauge, match: (p) => p === base },
    { href: `${base}/images`, label: "Image Analysis", icon: ImageIcon },
    { href: `${base}/sources`, label: "Sources", icon: Globe },
    { href: `${base}/evidence`, label: "Evidence", icon: FileSearch },
    { href: `${base}/timeline`, label: "Timeline", icon: CalendarClock },
    { href: `${base}/graph`, label: "Relationship Graph", icon: Network },
    { href: `${base}/reports`, label: "Reports", icon: FileText },
    { href: `${base}/activity`, label: "Activity", icon: Activity },
    { href: `${base}/data-controls`, label: "Data controls", icon: ShieldCheck },
  ];
}

export const WORKSPACE_NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/investigations/new", label: "New Investigation", icon: FilePlus2 },
  {
    href: "/investigations",
    label: "Investigation History",
    icon: History,
    match: (p) => p === "/investigations",
  },
];

export function governanceNav(user: User): NavItem[] {
  const items: NavItem[] = [
    { href: "/data-controls", label: "Privacy & Data Controls", icon: ShieldCheck, match: (p) => p === "/data-controls" },
    { href: "/settings/profile", label: "Settings", icon: Settings, match: (p) => p.startsWith("/settings") },
  ];
  if (user.role === "supervisor") items.push({ href: "/reviews", label: "Reviews", icon: ClipboardCheck });
  if (user.role === "admin") items.push({ href: "/admin/users", label: "Administration", icon: UserCog, match: (p) => p.startsWith("/admin") });
  if (user.role === "auditor") items.push({ href: "/admin/audit-log", label: "Audit log", icon: ScrollText, match: (p) => p.startsWith("/admin") });
  return items;
}

function NavLink({ item, onNavigate }: { item: NavItem; onNavigate?: () => void }) {
  const path = usePathname();
  const active = item.match ? item.match(path) : path === item.href || path.startsWith(`${item.href}/`);
  const Icon = item.icon;
  return (
    <Link
      href={item.href}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex min-h-8 items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
        active ? "bg-primary/15 font-medium text-foreground" : "text-muted hover:bg-surface-2 hover:text-foreground",
      )}
    >
      <Icon className={cn("h-4 w-4 shrink-0", active ? "text-primary" : "")} aria-hidden />
      <span className="truncate">{item.label}</span>
    </Link>
  );
}

function Group({ title, items, onNavigate, empty }: { title: string; items: NavItem[]; onNavigate?: () => void; empty?: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="px-2.5 text-[11px] font-semibold tracking-wider text-subtle uppercase">{title}</p>
      {items.length ? (
        <ul className="space-y-0.5">
          {items.map((item) => (
            <li key={item.href}>
              <NavLink item={item} onNavigate={onNavigate} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="px-2.5 text-[13px] text-subtle">{empty}</p>
      )}
    </div>
  );
}

export function SidebarNav({
  user,
  investigationId,
  investigationRef,
  onNavigate,
}: {
  user: User;
  investigationId: string | null;
  investigationRef?: string | null;
  onNavigate?: () => void;
}) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-6 p-3">
      <Group title="Workspace" items={WORKSPACE_NAV} onNavigate={onNavigate} />
      <Group
        title={investigationRef ? `Investigation ${investigationRef}` : "Active investigation"}
        items={investigationId ? investigationNav(investigationId) : []}
        onNavigate={onNavigate}
        empty="Open an investigation to see its images, sources, evidence, timeline, graph and reports."
      />
      <Group title="Governance" items={governanceNav(user)} onNavigate={onNavigate} />
    </nav>
  );
}
