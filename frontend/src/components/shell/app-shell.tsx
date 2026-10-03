"use client";

import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { ChevronsUpDown, LogOut, Menu as MenuIcon, Moon, Search, Settings, Sparkles, Sun, UserRound } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";

import { Button } from "@/components/ui/button";
import { Menu, Popover, Tooltip } from "@/components/ui/menu";
import { Dialog, Sheet } from "@/components/ui/overlay";
import { ReauthDialogHost } from "@/features/auth/reauth";
import { api, unwrap } from "@/lib/api/client";
import { useSessionClock } from "@/lib/api/session";
import type { Session, User } from "@/lib/api/types";
import { useInvestigationDetail, useInvestigationId } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { fetchSession, useSignOut } from "@/lib/session";
import { cn } from "@/lib/utils";

import { SidebarNav, canUseInvestigations, governanceNav, investigationNav, workspaceNav } from "./sidebar";

// ------------------------------------------------------------------------------------------- assistant
const AssistantContext = createContext<{ open: boolean; setOpen: (open: boolean) => void }>({
  open: false,
  setOpen: () => undefined,
});
export const useAssistantDrawer = () => useContext(AssistantContext);

// ------------------------------------------------------------------------------------------- pieces
export function SkipLink() {
  return (
    <a
      href="#main"
      className="sr-only z-[70] rounded-md bg-primary px-3 py-2 text-primary-fg focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
    >
      Skip to main content
    </a>
  );
}

function Brand() {
  return (
    <Link href="/dashboard" className="flex items-center gap-2 rounded-md px-1 font-semibold tracking-tight">
      <span aria-hidden className="grid h-7 w-7 place-items-center rounded-md bg-primary/15 text-primary">
        <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7l7-4z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      </span>
      <span>Angel Engine</span>
    </Link>
  );
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  // false during SSR/hydration, true afterwards — avoids a theme-icon mismatch without a setState-in-effect.
  const mounted = useSyncExternalStore(
    () => () => undefined,
    () => true,
    () => false,
  );
  const dark = mounted ? resolvedTheme === "dark" : true;
  return (
    <Tooltip content={dark ? "Switch to light theme" : "Switch to dark theme"}>
      <Button variant="ghost" size="icon" aria-label={dark ? "Switch to light theme" : "Switch to dark theme"} onClick={() => setTheme(dark ? "light" : "dark")}>
        {dark ? <Sun className="h-4 w-4" aria-hidden /> : <Moon className="h-4 w-4" aria-hidden />}
      </Button>
    </Tooltip>
  );
}

function InvestigationSwitcher({ currentId, currentRef }: { currentId: string | null; currentRef?: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const { data = [] } = useQuery({
    queryKey: qk.investigations({ limit: 50 }),
    queryFn: () => unwrap(api.GET("/api/v1/investigations", { params: { query: { limit: 50 } } })),
    enabled: open,
  });
  const go = (id: string) => {
    setOpen(false);
    const section = currentId ? pathname.split(`/investigations/${currentId}`)[1] ?? "" : "";
    const keep = section.split("/").slice(0, 2).join("/"); // keep the section, drop item ids
    router.push(`/investigations/${id}${keep}`);
  };
  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      className="w-[min(26rem,calc(100vw-2rem))] p-0"
      trigger={
        <Button variant="outline" size="sm" className="max-w-[16rem] justify-between" aria-label="Switch investigation">
          <span className="truncate font-mono text-xs">{currentRef ?? "Choose investigation"}</span>
          <ChevronsUpDown className="h-3.5 w-3.5 opacity-70" aria-hidden />
        </Button>
      }
    >
      <Command label="Investigations" className="text-sm">
        <Command.Input placeholder="Search by reference or title…" className="h-10 w-full border-b border-border bg-transparent px-3 outline-none" />
        <Command.List className="max-h-80 overflow-y-auto p-1">
          <Command.Empty className="px-3 py-6 text-center text-muted">No investigations found.</Command.Empty>
          {data.map((inv) => (
            <Command.Item
              key={inv.id}
              value={`${inv.ref} ${inv.title}`}
              onSelect={() => go(inv.id)}
              className="flex cursor-default flex-col gap-0.5 rounded-sm px-2.5 py-2 data-[selected=true]:bg-surface-2"
            >
              <span className="font-mono text-xs text-muted">{inv.ref}</span>
              <span className="truncate">{inv.title}</span>
            </Command.Item>
          ))}
        </Command.List>
      </Command>
    </Popover>
  );
}

function CommandPalette({ user, investigationId }: { user: User; investigationId: string | null }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const groups = [
    { heading: "Workspace", items: workspaceNav(user) },
    { heading: "Investigation", items: investigationId ? investigationNav(investigationId) : [] },
    { heading: "Governance", items: governanceNav(user) },
  ];
  const run = (href: string) => {
    setOpen(false);
    router.push(href);
  };
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)} className="hidden text-muted md:inline-flex" aria-label="Open command palette">
        <Search className="h-3.5 w-3.5" aria-hidden />
        <span>Go to…</span>
        <kbd className="rounded border border-border px-1 font-mono text-[10px]">Ctrl K</kbd>
      </Button>
      <Dialog open={open} onOpenChange={setOpen} title="Go to" className="max-w-md">
        <Command label="Command palette" className="text-sm">
          <Command.Input autoFocus placeholder="Type a page name…" className="mb-2 h-9 w-full rounded-md border border-border bg-surface-2 px-3 outline-none" />
          <Command.List className="max-h-80 overflow-y-auto">
            <Command.Empty className="px-3 py-6 text-center text-muted">Nothing matches.</Command.Empty>
            {groups.map((group) =>
              group.items.length ? (
                <Command.Group key={group.heading} heading={group.heading} className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-subtle">
                  {group.items.map((item) => (
                    <Command.Item key={item.href} value={`${group.heading} ${item.label}`} onSelect={() => run(item.href)} className="flex items-center gap-2 rounded-sm px-2 py-1.5 data-[selected=true]:bg-surface-2">
                      <item.icon className="h-4 w-4 text-muted" aria-hidden />
                      {item.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              ) : null,
            )}
          </Command.List>
        </Command>
      </Dialog>
    </>
  );
}

function UserMenu({ user }: { user: User }) {
  const router = useRouter();
  const signOut = useSignOut();
  return (
    <Menu
      label="Account"
      trigger={
        <Button variant="ghost" size="sm" aria-label={`Account: ${user.display_name}`}>
          <UserRound className="h-4 w-4" aria-hidden />
          <span className="hidden max-w-[10rem] truncate lg:inline">{user.display_name}</span>
        </Button>
      }
      items={[
        { label: <span className="text-xs text-muted">{user.email} · {user.role}</span>, onSelect: () => undefined, disabled: true },
        "separator",
        { label: <><Settings className="h-4 w-4" aria-hidden /> Settings</>, onSelect: () => router.push("/settings/profile") },
        { label: <><LogOut className="h-4 w-4" aria-hidden /> Sign out</>, onSelect: () => void signOut() },
      ]}
    />
  );
}

/** Warns two minutes before the idle timeout; "Stay signed in" makes a foreground request that slides it. */
function SessionExpiryModal() {
  const clock = useSessionClock();
  const signOut = useSignOut();
  const [now, setNow] = useState(() => Date.now());
  const [extending, setExtending] = useState(false);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const idleLeft = clock.idleDeadline ? Math.round((clock.idleDeadline - now) / 1000) : null;
  const absoluteLeft = clock.absoluteDeadline ? Math.round((clock.absoluteDeadline - now) / 1000) : null;
  const signedOut = useRef(false);
  useEffect(() => {
    if (!signedOut.current && ((idleLeft !== null && idleLeft <= 0) || (absoluteLeft !== null && absoluteLeft <= 0))) {
      signedOut.current = true;
      void signOut(idleLeft !== null && idleLeft <= 0 ? "idle" : "absolute");
    }
  }, [idleLeft, absoluteLeft, signOut]);
  const absoluteSoon = absoluteLeft !== null && absoluteLeft > 0 && absoluteLeft <= 300;
  const open = (idleLeft !== null && idleLeft > 0 && idleLeft <= 120) || absoluteSoon;
  const format = (seconds: number) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  return (
    <Dialog
      open={open}
      onOpenChange={() => undefined}
      title={absoluteSoon ? "Your session is about to end" : "Are you still there?"}
      description={
        absoluteSoon
          ? `For security, sessions end after 12 hours. You will be signed out in ${format(absoluteLeft ?? 0)}. Save your work.`
          : `You will be signed out in ${format(Math.max(idleLeft ?? 0, 0))} because of inactivity.`
      }
      footer={
        <>
          <Button variant="secondary" onClick={() => void signOut()}>
            Sign out now
          </Button>
          {!absoluteSoon ? (
            <Button
              variant="primary"
              loading={extending}
              onClick={async () => {
                setExtending(true);
                await fetchSession().catch(() => null);
                setExtending(false);
              }}
            >
              Stay signed in
            </Button>
          ) : null}
        </>
      }
    >
      <p aria-live="polite" className="text-sm text-muted">
        Unsaved form entries are lost when the session ends.
      </p>
    </Dialog>
  );
}

/** Move focus to the page heading after client-side navigation (screen-reader users hear the new page). */
function RouteFocusManager() {
  const pathname = usePathname();
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    const heading = document.querySelector<HTMLElement>("main h1");
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: false });
    }
  }, [pathname]);
  return null;
}

// ------------------------------------------------------------------------------------------- shell
export function AppShell({ session, children }: { session: Session; children: React.ReactNode }) {
  const user = session.user as User;
  const routeId = useInvestigationId();
  const activeId = canUseInvestigations(user) ? (routeId ?? user.last_active_investigation_id ?? null) : null;
  const { data: investigation } = useInvestigationDetail(activeId);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const ref = investigation?.ref ?? null;

  return (
    <AssistantContext.Provider value={{ open: assistantOpen, setOpen: setAssistantOpen }}>
      <SkipLink />
      <div className="flex min-h-screen flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-border bg-surface/95 px-3 backdrop-blur">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation" onClick={() => setMobileOpen(true)}>
            <MenuIcon className="h-5 w-5" aria-hidden />
          </Button>
          <Brand />
          {canUseInvestigations(user) ? (
            <div className="ml-2 hidden sm:block">
              <InvestigationSwitcher currentId={routeId} currentRef={routeId ? (ref ?? undefined) : undefined} />
            </div>
          ) : null}
          <div className="ml-auto flex items-center gap-1">
            <CommandPalette user={user} investigationId={activeId} />
            {routeId ? (
              <Button
                variant={assistantOpen ? "primary" : "ghost"}
                size="sm"
                aria-pressed={assistantOpen}
                onClick={() => setAssistantOpen(!assistantOpen)}
              >
                <Sparkles className="h-4 w-4" aria-hidden />
                <span className="hidden md:inline">Assistant</span>
              </Button>
            ) : null}
            <ThemeToggle />
            <UserMenu user={user} />
          </div>
        </header>
        <div className="flex min-h-0 flex-1">
          <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-64 shrink-0 overflow-y-auto border-r border-border bg-surface lg:block">
            <SidebarNav user={user} investigationId={activeId} investigationRef={ref} />
          </aside>
          <main id="main" className={cn("min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8", assistantOpen && "xl:pr-[30rem]")}>
            {children}
          </main>
        </div>
      </div>
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen} title="Navigation" side="left" className="max-w-xs">
        <SidebarNav user={user} investigationId={activeId} investigationRef={ref} onNavigate={() => setMobileOpen(false)} />
      </Sheet>
      <SessionExpiryModal />
      <ReauthDialogHost />
      <RouteFocusManager />
    </AssistantContext.Provider>
  );
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  eyebrow?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0 space-y-1">
        {eyebrow ? <div className="text-xs text-muted">{eyebrow}</div> : null}
        <h1 className="text-xl font-semibold tracking-tight outline-none sm:text-2xl">{title}</h1>
        {description ? <div className="max-w-3xl text-sm text-muted">{description}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}
