import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ChevronDown, LogOut, Moon, Search, Sun } from "lucide-react";
import { useAccount, useSession } from "../lib/session";
import { applyTheme, storedTheme, type Theme } from "../lib/theme";
import { visibleNavigation, type NavItem } from "./nav";
import { CommandPalette } from "./CommandPalette";
import { Kbd, Tip, cx } from "../components/ui";

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-4 py-4">
      <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
        <rect width="32" height="32" rx="7" className="fill-surface-3" />
        <path d="M9 9h6v6H9zM17 9h6v6h-6zM9 17h6v6H9z" className="fill-accent" />
        <path d="M17 17h6v6h-6z" className="fill-ok" />
      </svg>
      <div className="leading-tight">
        <div className="text-[14px] font-semibold tracking-tight text-fg">OpenRMM</div>
        <div className="text-[11px] text-faint">Self-hosted</div>
      </div>
    </div>
  );
}

function NavEntry({ item }: { item: NavItem }) {
  const Icon = item.icon;
  if (item.state !== "ready") {
    const soon = item.state === "soon";
    const tip = soon ? "Planned response capability — coming soon" : "Being rebuilt in the new interface";
    return (
      <Tip label={tip} side="right">
        <div className="flex h-8 cursor-default items-center gap-2.5 rounded-md px-2.5 text-faint" aria-disabled="true">
          <Icon className="size-4 shrink-0" aria-hidden />
          <span className="flex-1 truncate">{item.label}</span>
          {soon ? (
            <span className="rounded border border-border px-1 text-[10px] font-medium tracking-wide uppercase">Soon</span>
          ) : (
            <span className="size-1.5 rounded-full border border-faint" aria-label="Being rebuilt" />
          )}
        </div>
      </Tip>
    );
  }
  return (
    <NavLink
      to={item.to}
      end={item.to === "/"}
      className={({ isActive }) =>
        cx(
          "flex h-8 items-center gap-2.5 rounded-md px-2.5 font-medium transition-colors",
          isActive ? "bg-accent-soft text-fg" : "text-muted hover:bg-surface-2 hover:text-fg",
        )
      }
    >
      {({ isActive }) => (
        <>
          <Icon className={cx("size-4 shrink-0", isActive && "text-accent")} aria-hidden />
          <span className="truncate">{item.label}</span>
        </>
      )}
    </NavLink>
  );
}

function UserMenu({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  const account = useAccount();
  const { signOut } = useSession();
  const navigate = useNavigate();
  const itemClass = "flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-[13px] text-fg outline-none data-[highlighted]:bg-surface-2";
  return (
    <Menu.Root>
      <Menu.Trigger className="flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left hover:bg-surface-2">
        <span className="flex size-7 items-center justify-center rounded-full bg-accent-soft text-[12px] font-semibold text-accent uppercase">{account.username.slice(0, 1)}</span>
        <span className="min-w-0 flex-1 leading-tight">
          <span className="block truncate font-medium text-fg">{account.username}</span>
          <span className="block text-[11.5px] text-faint">{account.role === "owner" ? "Administrator" : "Technician"}</span>
        </span>
        <ChevronDown className="size-4 text-faint" aria-hidden />
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content side="top" align="start" sideOffset={6} className="z-50 min-w-52 rounded-md border border-border-strong bg-surface p-1 shadow-panel">
          <Menu.Item className={itemClass} onSelect={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </Menu.Item>
          <Menu.Separator className="my-1 h-px bg-border" />
          <Menu.Item
            className={itemClass}
            onSelect={() => {
              void signOut().then(() => navigate("/", { replace: true }));
            }}
          >
            <LogOut className="size-4" />
            Sign out
          </Menu.Item>
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  );
}

export function AppShell() {
  const account = useAccount();
  const [theme, setThemeState] = useState<Theme>(storedTheme);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const setTheme = (t: Theme) => {
    applyTheme(t);
    setThemeState(t);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const sections = visibleNavigation(account.permissions.owner, account.permissions.response);

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-surface">
        <Brand />
        <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 pb-4" aria-label="Main">
          {sections.map((s, i) => (
            <div key={s.title ?? i} className="space-y-0.5">
              {s.title ? <div className="px-2.5 pb-1 text-[11px] font-semibold tracking-wider text-faint uppercase">{s.title}</div> : null}
              {s.items.map((item) => (
                <NavEntry key={item.to} item={item} />
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-border p-2">
          <UserMenu theme={theme} setTheme={setTheme} />
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-13 shrink-0 items-center gap-3 border-b border-border bg-surface/60 px-6 backdrop-blur">
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex h-8.5 w-full max-w-md items-center gap-2 rounded-md border border-border bg-surface px-2.5 text-left text-muted transition-colors hover:border-border-strong"
          >
            <Search className="size-4" aria-hidden />
            <span className="flex-1">Search devices and pages</span>
            <Kbd>Ctrl K</Kbd>
          </button>
          <div className="flex-1" />
          <Tip label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
            <button
              type="button"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-fg"
              aria-label="Toggle theme"
            >
              {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
          </Tip>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} sections={sections} />
    </div>
  );
}

/** Standard page heading with optional actions on the right. */
export function PageHeader({ title, subtitle, actions }: { title: React.ReactNode; subtitle?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 pb-5">
      <div className="min-w-0 space-y-1">
        <h1 className="text-[20px] font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle ? <div className="text-[13px] text-muted">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}
