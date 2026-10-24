import { Download } from "lucide-react";

/** CSV of exactly what the report shows (same filters), downloaded with the session cookie. */
export function CsvLink({ href }: { href: string }) {
  return (
    <a
      href={href}
      download
      className="inline-flex h-8.5 shrink-0 items-center gap-2 rounded-md border border-border bg-surface-2 px-3.5 text-[13px] font-medium whitespace-nowrap text-fg hover:bg-surface-3"
    >
      <Download className="size-4" /> Export CSV
    </a>
  );
}
