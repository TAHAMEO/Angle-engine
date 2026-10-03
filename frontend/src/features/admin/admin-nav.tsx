"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import type { User } from "@/lib/api/types";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";

const ADMIN = [
  { href: "/admin/users", label: "Users" },
  { href: "/admin/investigations", label: "Investigations" },
  { href: "/admin/connectors", label: "Connectors" },
  { href: "/admin/retention", label: "Retention" },
  { href: "/admin/abuse-reports", label: "Abuse reports" },
  { href: "/admin/jobs", label: "Failed jobs" },
  { href: "/admin/audit-log", label: "Audit log" },
];

export function AdminNav() {
  const pathname = usePathname();
  const { data } = useSession();
  const role = (data?.user as User | undefined)?.role;
  const items =
    role === "admin"
      ? ADMIN
      : ADMIN.filter((i) => (role === "supervisor" ? i.href === "/admin/abuse-reports" : i.href === "/admin/audit-log"));
  return (
    <nav aria-label="Administration" className="flex gap-1 overflow-x-auto border-b border-border">
      {items.map((item) => {
        const active = pathname.startsWith(item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm whitespace-nowrap",
              active ? "border-primary font-medium text-foreground" : "border-transparent text-muted hover:text-foreground",
            )}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

export function useRole(): string | undefined {
  const { data } = useSession();
  return (data?.user as User | undefined)?.role;
}
