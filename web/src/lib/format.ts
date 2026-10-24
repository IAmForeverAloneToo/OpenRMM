export function relativeTime(unixSeconds: number | null | undefined, nowMs: number = Date.now()): string {
  if (!unixSeconds) return "Never";
  const diff = Math.round(nowMs / 1000 - unixSeconds);
  if (diff < -5) return "in the future";
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
  return absoluteTime(unixSeconds);
}

export function absoluteTime(unixSeconds: number | null | undefined): string {
  if (!unixSeconds) return "Never";
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function utcTime(unixSeconds: number | null | undefined): string {
  if (!unixSeconds) return "Never";
  return new Date(unixSeconds * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function percent(v: number | null | undefined, digits = 0): string {
  if (v === null || v === undefined || Number.isNaN(v)) return "—";
  return `${v.toFixed(digits)}%`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function osLabel(os: string, version?: string, build?: number): string {
  const name = os === "windows" ? "Windows" : os;
  if (!version) return name;
  return build ? `${name} ${version} (build ${build})` : `${name} ${version}`;
}

const operationKinds: Record<string, string> = {
  services: "Service action",
  processes: "Process action",
  applications: "App deployment",
  "agent-upgrades": "Agent update",
  events: "Event log query",
  files: "File transfer",
  updates: "Windows Update",
  scripts: "Script run",
};

export function operationKind(kind: string): string {
  return operationKinds[kind] ?? kind;
}

const alertKinds: Record<string, string> = {
  offline: "Device offline",
  cpu: "High CPU",
  memory: "High memory",
  disk_space: "Low disk space",
  health: "Health check",
  agent_update: "Agent update failed",
};

export function alertTitle(kind: string, label?: string): string {
  if ((kind === "health" || kind === "agent_update") && label) return label;
  return alertKinds[kind] ?? kind;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

export function clock(minute: number): string {
  return `${String(Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`;
}

/** Maintenance windows are defined in UTC so they mean the same on every device. */
export function windowLabel(weekday: number, minute: number, duration: number): string {
  return `${weekdays[weekday]} ${clock(minute)}–${clock((minute + duration) % 1440)} UTC`;
}

export function short(hash: string, n = 12): string {
  return hash.length > n ? `${hash.slice(0, n)}…` : hash;
}

export function describeInterval(seconds: number): string {
  if (!seconds) return "Once";
  if (seconds % 86400 === 0) return seconds === 86400 ? "Daily" : `Every ${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? "Hourly" : `Every ${seconds / 3600} hours`;
  return `Every ${seconds / 60} minutes`;
}

function minutes(seconds: number) {
  return seconds % 3600 === 0 ? `${seconds / 3600} h` : `${Math.round(seconds / 60)} min`;
}

/** Plain-language description of what triggered an incident. */
export function triggerText(a: { kind: string; threshold: number; hold_seconds: number }, family: string): string {
  switch (family) {
    case "offline":
      return `No contact for ${minutes(a.hold_seconds)} after the connection timeout.`;
    case "disk_space":
      return `Free space on the system drive below ${a.threshold}% for ${minutes(a.hold_seconds)}.`;
    case "health":
      return `The required service was not running for ${minutes(a.hold_seconds)}.`;
    case "agent_update":
      return "An agent update failed, rolled back or could not be confirmed. Automatic updates are paused until you resume them on the Agent updates page.";
    default:
      return `${a.kind === "memory" ? "Memory" : "CPU"} use at or above ${a.threshold}% for ${minutes(a.hold_seconds)}.`;
  }
}
