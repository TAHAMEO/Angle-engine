import Link from "next/link";

export default function GatesLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-14 items-center border-b border-border px-4 sm:px-6">
        <Link href="/login" className="font-semibold tracking-tight">Angel Engine</Link>
      </header>
      <main id="main" className="flex flex-1 justify-center px-4 py-10">
        {children}
      </main>
    </div>
  );
}
