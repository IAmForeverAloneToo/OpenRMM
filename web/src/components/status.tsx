import type { BitLockerSummary, DefenderSummary, DeviceStatus } from "../lib/types";
import { Badge, Tip, type Tone } from "./ui";

const deviceStatus: Record<DeviceStatus, { label: string; tone: Tone }> = {
  online: { label: "Online", tone: "ok" },
  offline: { label: "Offline", tone: "neutral" },
  awaiting_contact: { label: "Awaiting contact", tone: "info" },
  revoked: { label: "Revoked", tone: "danger" },
};

export function DeviceStatusBadge({ status }: { status: DeviceStatus }) {
  const s = deviceStatus[status] ?? { label: status, tone: "neutral" as Tone };
  return (
    <Badge tone={s.tone} dot>
      {s.label}
    </Badge>
  );
}

export function deviceStatusLabel(status: DeviceStatus): string {
  return deviceStatus[status]?.label ?? status;
}

const running = new Set(["staged", "queued", "dispatched", "running", "scanning", "installing", "verifying", "restarting"]);
const good = new Set(["succeeded", "completed", "ok", "installed", "approved_complete", "verified", "no_change"]);
const bad = new Set(["failed", "denied", "timed_out", "rolled_back", "recovery_required", "verification_failed"]);
const uncertain = new Set(["unknown", "interrupted"]);

export function operationTone(status: string): Tone {
  if (running.has(status)) return "info";
  if (good.has(status)) return "ok";
  if (bad.has(status)) return "danger";
  if (uncertain.has(status)) return "warn";
  return "neutral";
}

export function OperationStatus({ status }: { status: string }) {
  const label = status.replaceAll("_", " ");
  return (
    <Badge tone={operationTone(status)} dot>
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={severity === "critical" ? "danger" : "warn"}>{severity === "critical" ? "Critical" : "Warning"}</Badge>;
}

/** Collection state of a capability snapshot, shown beside its values. */
export function snapshotState(status: string, stale: boolean): { label: string; tone: Tone } | null {
  switch (status) {
    case "ok":
      return stale ? { label: "Stale", tone: "warn" } : null;
    case "failed":
      return { label: "Collection failed", tone: "danger" };
    case "disabled":
      return { label: "Disabled on device", tone: "neutral" };
    case "unsupported":
      return { label: "Not supported", tone: "neutral" };
    default:
      return { label: "Not reported", tone: "neutral" };
  }
}

// BitLocker on the operating system volume and Microsoft Defender.
export const bitLockerStates: Record<BitLockerSummary, { label: string; tone: Tone; hint: string }> = {
  on: { label: "On", tone: "ok", hint: "The operating system volume is encrypted and protected." },
  suspended: { label: "Suspended", tone: "warn", hint: "Encrypted, but protection is off: the key is stored in the clear until protection is resumed." },
  encrypting: { label: "Encrypting", tone: "info", hint: "Encryption of the operating system volume is in progress or paused." },
  off: { label: "Off", tone: "warn", hint: "The operating system volume is not encrypted." },
  not_installed: { label: "Not available", tone: "neutral", hint: "BitLocker is not available on this edition of Windows." },
  unknown: { label: "Unknown", tone: "neutral", hint: "BitLocker status could not be read." },
};
export const defenderStates: Record<DefenderSummary, { label: string; tone: Tone; hint: string }> = {
  on: { label: "On", tone: "ok", hint: "Microsoft Defender Antivirus is running with real-time protection." },
  real_time_off: { label: "Real-time off", tone: "warn", hint: "Defender is running, but real-time protection is off." },
  off: { label: "Off", tone: "danger", hint: "The Defender service or antivirus is turned off." },
  passive: { label: "Passive", tone: "neutral", hint: "Defender runs in passive mode, usually beside another antivirus product." },
  other_av: { label: "Other antivirus", tone: "neutral", hint: "Defender is off because another antivirus product is registered and enabled in Windows Security Center." },
  absent: { label: "Not installed", tone: "neutral", hint: "Microsoft Defender Antivirus is not installed." },
  unknown: { label: "Unknown", tone: "neutral", hint: "Defender status could not be read." },
};

export function SecurityBadge({ kind, value, stale }: { kind: "bitlocker" | "defender"; value: string | undefined; stale?: boolean }) {
  const s = value ? (kind === "bitlocker" ? bitLockerStates[value as BitLockerSummary] : defenderStates[value as DefenderSummary]) : undefined;
  if (!s) return <span className="text-faint">—</span>;
  const tone = s.tone === "ok" || s.tone === "neutral" ? null : s.tone;
  return (
    <Tip label={stale ? `${s.hint} Last known status: the report is old or the device is offline.` : s.hint}>
      <span className={stale ? "opacity-60" : undefined}>{tone ? <Badge tone={tone}>{s.label}</Badge> : <span className={s.tone === "ok" ? "text-muted" : "text-faint"}>{s.label}</span>}</span>
    </Tip>
  );
}
