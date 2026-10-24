// Pure input helpers shared by pages. No runtime imports, so `node --test`
// can load this module directly (see parse.test.ts).
import type { ScriptVersion } from "./types";

/** Lowercase slug for a new group or policy ID, unique among `taken`. */
export function slugify(name: string, taken: string[]): string {
  let base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 28);
  if (!/^[a-z]/.test(base)) base = `x-${base}`.replace(/-+$/, "");
  let id = base;
  for (let n = 2; taken.includes(id); n++) id = `${base}-${n}`;
  return id;
}

export function parseTags(text: string): string[] {
  return [...new Set(text.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean))].sort();
}

export const tagPattern = /^[a-z0-9][a-z0-9._-]{0,31}$/;

/** Unique KB numbers from free text ("KB5034441, 5034122"), without the KB prefix. */
export function parseKB(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map((s) => s.trim().replace(/^kb/i, "")).filter(Boolean))];
}

export function versionCompare(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
}

/** Windows FILETIME (100 ns ticks since 1601) as Unix seconds, if parseable. */
export function filetimeToUnix(start: string): number | null {
  try {
    const ticks = BigInt(start);
    const ms = ticks / 10000n - 11644473600000n;
    return ms > 0n ? Number(ms / 1000n) : null;
  } catch {
    return null;
  }
}

export function argumentsComplete(version: ScriptVersion | undefined, values: Record<string, string>): boolean {
  return !!version && version.definition.parameters.every((p) => !p.required || (values[p.name] ?? "") !== "");
}

/** Query string from the non-empty values only. */
export function reportQuery(values: Record<string, string>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(values)) if (v) p.set(k, v);
  return p.toString();
}
