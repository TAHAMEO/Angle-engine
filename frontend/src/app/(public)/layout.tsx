import Link from "next/link";

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-14 items-center border-b border-border px-4 sm:px-6">
        <Link href="/login" className="flex items-center gap-2 font-semibold tracking-tight">
          <span aria-hidden className="grid h-7 w-7 place-items-center rounded-md bg-primary/15 text-primary">
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7l7-4z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </span>
          Angel Engine
        </Link>
      </header>
      <main id="main" className="flex flex-1 justify-center px-4 py-10 sm:py-16">
        {children}
      </main>
      <footer className="border-t border-border px-4 py-5 text-sm text-muted sm:px-6">
        <nav aria-label="Legal" className="flex flex-wrap gap-x-5 gap-y-2">
          <Link className="hover:text-foreground hover:underline" href="/legal/terms">Terms of Use</Link>
          <Link className="hover:text-foreground hover:underline" href="/legal/privacy">Privacy Policy</Link>
          <Link className="hover:text-foreground hover:underline" href="/legal/acceptable-use">Acceptable Use Policy</Link>
          <Link className="hover:text-foreground hover:underline" href="/legal/responsible-use">Responsible Use &amp; Methodology</Link>
          <Link className="hover:text-foreground hover:underline" href="/report-abuse">Report abuse</Link>
        </nav>
        <p className="mt-3 max-w-3xl text-xs">
          Investigate public evidence, verify sources, protect privacy, and never turn an AI inference into an identity
          claim. Angel Engine does not perform facial identification.
        </p>
      </footer>
    </div>
  );
}
