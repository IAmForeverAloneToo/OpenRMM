import type { ReactNode } from "react";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { BitLockerVolume, DeviceDetail } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, Mono, Panel } from "../../components/ui";
import { SecurityBadge, snapshotState } from "../../components/status";

// BitLocker volumes, Microsoft Defender and the antivirus products
// Windows Security Center knows (part of the Inventory feature).

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[170px_1fr] gap-3 py-1.5 text-[12.5px]">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-fg">{children}</dd>
    </div>
  );
}

function Flag({ on, onLabel = "On", offLabel = "Off" }: { on: boolean; onLabel?: string; offLabel?: string }) {
  return on ? <span className="text-fg">{onLabel}</span> : <Badge tone="warn">{offLabel}</Badge>;
}

function When({ at }: { at: string }) {
  if (!at) return <span className="text-faint">Never</span>;
  const s = Date.parse(at) / 1000;
  return (
    <span title={absoluteTime(s)}>
      {relativeTime(s)} <span className="text-faint">· {absoluteTime(s)}</span>
    </span>
  );
}

const volumeTypes = { os: "Operating system", fixed: "Fixed data", removable: "Removable" };
const conversions: Record<BitLockerVolume["conversion"], string> = {
  fully_decrypted: "Not encrypted",
  fully_encrypted: "Encrypted",
  encrypting: "Encrypting",
  decrypting: "Decrypting",
  paused: "Paused",
  unknown: "Unknown",
};
const unavailable = { not_installed: "BitLocker is not available on this edition of Windows.", unavailable: "BitLocker status could not be read.", absent: "BitLocker is not installed." };

export function SecurityPanel({ d }: { d: DeviceDetail }) {
  const sec = d.security_status;
  const state = snapshotState(sec.status, sec.stale);
  if (!sec.data) {
    return (
      <Panel title="Security">
        <EmptyState title={state?.label ?? "Not reported"}>BitLocker and Defender status is reported with the Inventory feature every hour.</EmptyState>
      </Panel>
    );
  }
  const v = sec.data;
  const def = v.defender;
  const columns: Column<BitLockerVolume & { key: number }>[] = [
    { key: "drive", header: "Volume", sort: (b) => b.drive, cell: (b) => <Mono className="text-fg">{b.drive || "(no letter)"}</Mono> },
    { key: "type", header: "Type", sort: (b) => b.type, cell: (b) => <span className="text-muted">{volumeTypes[b.type]}</span> },
    {
      key: "protection",
      header: "Protection",
      sort: (b) => b.protection,
      cell: (b) =>
        b.protection === "on" ? <Badge tone="ok" dot>On</Badge> : b.protection === "off" ? <Badge tone={b.conversion === "fully_decrypted" ? "neutral" : "warn"}>Off</Badge> : <span className="text-faint">Unknown</span>,
    },
    {
      key: "conversion",
      header: "Encryption",
      sort: (b) => b.percent,
      cell: (b) => (
        <span className="text-muted">
          {conversions[b.conversion]}
          {b.conversion === "encrypting" || b.conversion === "decrypting" || b.conversion === "paused" ? <span className="tabular-nums"> · {b.percent.toFixed(0)}%</span> : null}
        </span>
      ),
    },
    { key: "method", header: "Method", sort: (b) => b.method, cell: (b) => <span className="text-muted">{b.method && b.method !== "none" ? b.method : "—"}</span> },
  ];
  return (
    <Panel
      title="Security"
      actions={
        <div className="flex items-center gap-2 text-[12px] text-muted">
          {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
          <span>snapshot {sec.snapshot_at ? relativeTime(sec.snapshot_at) : "never"}</span>
        </div>
      }
      bodyClassName="p-0"
    >
      <div className="grid gap-x-6 border-b border-border p-4 lg:grid-cols-2">
        <dl>
          <Row label="BitLocker (system volume)">
            <SecurityBadge kind="bitlocker" value={sec.bitlocker} />
          </Row>
          <Row label="Microsoft Defender">
            <SecurityBadge kind="defender" value={sec.defender} />
          </Row>
          <Row label="Antivirus products">
            {v.antivirus.length === 0 ? (
              <span className="text-faint">None reported by Security Center</span>
            ) : (
              <div className="space-y-0.5">
                {v.antivirus.map((a, i) => (
                  <div key={`${a.name}-${i}`} className="flex flex-wrap items-center gap-1.5">
                    <span>{a.name}</span>
                    {a.enabled ? null : <Badge tone="warn">Off</Badge>}
                    {a.up_to_date ? null : <Badge tone="warn">Out of date</Badge>}
                  </div>
                ))}
              </div>
            )}
          </Row>
        </dl>
        {def ? (
          <dl>
            <Row label="Real-time protection"><Flag on={def.real_time_protection} /></Row>
            <Row label="Behavior monitoring"><Flag on={def.behavior_monitoring} /></Row>
            <Row label="Tamper protection"><Flag on={def.tamper_protected} /></Row>
            <Row label="Running mode"><span className="capitalize">{def.mode.replaceAll("_", " ") || "—"}</span></Row>
            <Row label="Versions">
              <Mono className="text-[11.5px]">{def.product_version || "—"}</Mono> <span className="text-faint">· signatures</span> <Mono className="text-[11.5px]">{def.signature_version || "—"}</Mono>
            </Row>
            <Row label="Signatures updated"><When at={def.signature_updated} /></Row>
            <Row label="Last quick scan"><When at={def.quick_scan_completed} /></Row>
            <Row label="Last full scan"><When at={def.full_scan_completed} /></Row>
          </dl>
        ) : (
          <p className="py-1.5 text-[12.5px] text-faint">{v.defender_state === "absent" ? "Microsoft Defender Antivirus is not installed." : "Defender status could not be read."}</p>
        )}
      </div>
      {v.bitlocker_state === "available" ? (
        <DataTable columns={columns} rows={v.bitlocker.map((b, key) => ({ ...b, key }))} rowKey={(b) => String(b.key)} dense empty={<EmptyState title="No volumes reported" />} />
      ) : (
        <p className="p-4 text-[12.5px] text-faint">{unavailable[v.bitlocker_state]}</p>
      )}
    </Panel>
  );
}
