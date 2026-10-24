import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import { LoaderCircle, Search } from "lucide-react";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover border-transparent",
  secondary: "bg-surface-2 text-fg border-border hover:bg-surface-3 hover:border-border-strong",
  ghost: "bg-transparent text-muted border-transparent hover:bg-surface-2 hover:text-fg",
  danger: "bg-danger text-white border-transparent hover:opacity-90",
};
const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[12.5px] gap-1.5",
  md: "h-8.5 px-3.5 text-[13px] gap-2",
};

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size; loading?: boolean; icon?: ReactNode }>(
  function Button({ variant = "secondary", size = "md", loading, icon, className, children, disabled, type = "button", ...rest }, ref) {
    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || loading}
        className={cx(
          "inline-flex shrink-0 items-center justify-center rounded-md border font-medium transition-colors select-none",
          "disabled:cursor-not-allowed disabled:opacity-45",
          variants[variant],
          sizes[size],
          className,
        )}
        {...rest}
      >
        {loading ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden /> : icon}
        {children}
      </button>
    );
  },
);

export function IconButton({ label, children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <Tip label={label}>
      <button
        type="button"
        aria-label={label}
        className={cx("inline-flex size-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-40", className)}
        {...rest}
      >
        {children}
      </button>
    </Tip>
  );
}

export function Tip({ label, children, side = "bottom" }: { label: ReactNode; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return (
    <Tooltip.Root delayDuration={300}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content side={side} sideOffset={6} className="z-50 max-w-xs rounded-md border border-border-strong bg-surface-3 px-2 py-1 text-[12px] text-fg shadow-panel">
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return (
    <input
      ref={ref}
      className={cx(
        "h-8.5 w-full rounded-md border border-border bg-surface px-2.5 text-[13px] text-fg placeholder:text-faint",
        "transition-colors hover:border-border-strong focus:border-accent focus:outline-none",
        className,
      )}
      {...rest}
    />
  );
});

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cx("h-8.5 rounded-md border border-border bg-surface px-2 text-[13px] text-fg hover:border-border-strong focus:border-accent focus:outline-none", className)}
      {...rest}
    >
      {children}
    </select>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="block text-[12.5px] font-medium text-muted">{label}</span>
      {children}
      {hint ? <span className="block text-[12px] text-faint">{hint}</span> : null}
    </label>
  );
}

export function Panel({ title, actions, children, className, bodyClassName }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string }) {
  return (
    <section className={cx("rounded-lg border border-border bg-surface", className)}>
      {title || actions ? (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-border px-4 py-2">
          <h2 className="text-[13px] font-semibold text-fg">{title}</h2>
          {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral" | "accent";
const tones: Record<Tone, string> = {
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  danger: "bg-danger-soft text-danger",
  info: "bg-info-soft text-info",
  neutral: "bg-neutral-soft text-muted",
  accent: "bg-accent-soft text-accent",
};
const dots: Record<Tone, string> = { ok: "bg-ok", warn: "bg-warn", danger: "bg-danger", info: "bg-info", neutral: "bg-neutral", accent: "bg-accent" };

export function Badge({ tone = "neutral", children, dot, className }: { tone?: Tone; children: ReactNode; dot?: boolean; className?: string }) {
  return (
    <span className={cx("inline-flex h-5.5 items-center gap-1.5 rounded px-1.5 text-[12px] font-medium whitespace-nowrap", tones[tone], className)}>
      {dot ? <span className={cx("size-1.5 rounded-full", dots[tone])} aria-hidden /> : null}
      {children}
    </span>
  );
}

export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return <span className={cx("inline-block size-2 shrink-0 rounded-full", dots[tone], pulse && "live-dot")} aria-hidden />;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-muted" role="status">
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      <span className="text-[13px]">{label}…</span>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon ? <div className="text-faint [&>svg]:size-7">{icon}</div> : null}
      <p className="font-medium text-fg">{title}</p>
      {children ? <div className="max-w-md text-[13px] text-muted">{children}</div> : null}
    </div>
  );
}

export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px] text-danger" role="alert">
      <span>{message}</span>
      {retry ? (
        <Button size="sm" variant="ghost" onClick={retry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-border-strong bg-surface-2 px-1 font-mono text-[11px] text-muted">{children}</kbd>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-[12.5px]", className)}>{children}</span>;
}

export function SearchInput({ value, onChange, placeholder, className, label }: { value: string; onChange: (v: string) => void; placeholder: string; className?: string; label?: string }) {
  return (
    <div className={cx("relative w-72", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-faint" aria-hidden />
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="pl-8" aria-label={label ?? placeholder} maxLength={200} />
    </div>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: ReactNode }[]; label: string }) {
  return (
    <div className="flex rounded-md border border-border bg-surface-2 p-0.5" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={cx("h-7 rounded px-2.5 text-[12.5px] font-medium whitespace-nowrap", value === o.value ? "bg-surface text-fg shadow-panel" : "text-muted hover:text-fg")}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Table toolbar row used above data tables. */
export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">{children}</div>;
}
