import { SettingsNav } from "@/features/settings/settings-nav";

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold tracking-tight outline-none sm:text-2xl">Settings</h1>
      <p className="mb-5 text-sm text-muted">Your account, security and appearance.</p>
      <SettingsNav />
      <div className="mt-6">{children}</div>
    </div>
  );
}
