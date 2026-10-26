import type { LucideIcon } from "lucide-react";
import {
  Bell,
  Briefcase,
  ChartColumn,
  Crosshair,
  DatabaseBackup,
  HeartPulse,
  LayoutDashboard,
  Layers,
  Monitor,
  Package,
  Rocket,
  ScrollText,
  ServerCog,
  Settings,
  ShieldCheck,
  Users,
  Boxes,
} from "lucide-react";

/**
 * ready: built in the new interface.
 * rebuilding: existing capability whose screens are being rebuilt.
 * soon: planned capability (see ROADMAP.md); not yet implemented.
 */
export type NavState = "ready" | "rebuilding" | "soon";
export type NavItem = { label: string; to: string; icon: LucideIcon; state: NavState; ownerOnly?: boolean; permission?: "response" };
export type NavSection = { title?: string; ownerOnly?: boolean; items: NavItem[] };

export const navigation: NavSection[] = [
  {
    items: [
      { label: "Dashboard", to: "/", icon: LayoutDashboard, state: "ready" },
      { label: "Devices", to: "/devices", icon: Monitor, state: "ready" },
      { label: "Alerts", to: "/alerts", icon: Bell, state: "ready" },
    ],
  },
  {
    title: "Manage",
    items: [
      { label: "Scripts", to: "/scripts", icon: ScrollText, state: "ready", ownerOnly: true },
      { label: "Patching", to: "/patching", icon: ShieldCheck, state: "ready", ownerOnly: true },
      { label: "App deployment", to: "/deployments", icon: Package, state: "ready" },
      { label: "Health checks", to: "/health-checks", icon: HeartPulse, state: "ready" },
      { label: "Agent updates", to: "/agent-updates", icon: Rocket, state: "ready" },
    ],
  },
  {
    title: "Investigate",
    items: [
      { label: "Cases", to: "/cases", icon: Briefcase, state: "ready", permission: "response" },
      { label: "Hunting", to: "/hunting", icon: Crosshair, state: "ready", permission: "response" },
    ],
  },
  {
    title: "Reports",
    items: [
      { label: "Metrics", to: "/reports/metrics", icon: ChartColumn, state: "ready" },
      { label: "Software inventory", to: "/reports/software", icon: Boxes, state: "ready" },
    ],
  },
  {
    title: "Administration",
    ownerOnly: true,
    items: [
      { label: "Groups & policies", to: "/organization", icon: Layers, state: "ready" },
      { label: "Technicians", to: "/technicians", icon: Users, state: "ready" },
      { label: "Alert settings", to: "/settings/alerts", icon: Settings, state: "ready" },
      { label: "Server updates", to: "/server-updates", icon: ServerCog, state: "ready" },
      { label: "Backups", to: "/backups", icon: DatabaseBackup, state: "ready" },
    ],
  },
];

export function visibleNavigation(owner: boolean, response = false): NavSection[] {
  return navigation
    .filter((s) => owner || !s.ownerOnly)
    .map((s) => ({ ...s, items: s.items.filter((i) => owner || (!i.ownerOnly && (i.permission !== "response" || response))) }))
    .filter((s) => s.items.length > 0);
}
