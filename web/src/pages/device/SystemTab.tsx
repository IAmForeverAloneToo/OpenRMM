import type { ReactNode } from "react";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { DeviceDetail, NetworkAdapter } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, Mono, Panel } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { SecurityPanel } from "./SecurityPanel";
import { snapshotState } from "../../components/status";

// Hardware, operating system, domain and network details from the
// device information report (part of the Inventory feature).

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 py-1.5 text-[12.5px]">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-fg">{children}</dd>
    </div>
  );
}
function Value({ v }: { v: string | number | undefined }) {
  return v === "" || v === 0 || v === undefined ? <span className="text-faint">Not provided</span> : <>{v}</>;
}

const joins = { domain: "Domain", workgroup: "Workgroup", unjoined: "Not joined", unknown: "Unknown" };
const entra = { joined: "Joined", registered: "Registered (workplace join)", none: "Not joined", unknown: "Unknown" };

function offset(minutes: number): string {
  const sign = minutes < 0 ? "-" : "+";
  const m = Math.abs(minutes);
  return `UTC${sign}${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
}

export function SystemTab({ d }: { d: DeviceDetail }) {
  const info = d.system_info;
  const state = snapshotState(info.status, info.stale);
  if (!info.data) {
    return (
      <div className="space-y-4">
        <Panel>
          <EmptyState title={state?.label ?? "Not reported"}>Device information is reported with the Inventory feature.</EmptyState>
        </Panel>
        <SecurityPanel d={d} />
      </div>
    );
  }
  const { hardware: h, cpu, os, domain } = info.data;
  const columns: Column<NetworkAdapter>[] = [
    {
      key: "name",
      header: "Adapter",
      sort: (a) => a.name.toLowerCase(),
      cell: (a) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{a.name}</div>
          {a.description ? <div className="truncate text-[11.5px] text-faint">{a.description}</div> : null}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      sort: (a) => a.status,
      cell: (a) => (a.status === "up" ? <Badge tone="ok" dot>Up</Badge> : a.status === "down" ? <Badge tone="neutral">Down</Badge> : <Badge tone="neutral">Other</Badge>),
    },
    { key: "type", header: "Type", sort: (a) => a.type, cell: (a) => <span className="text-muted">{a.type === "wifi" ? "Wi-Fi" : a.type === "ethernet" ? "Ethernet" : "Other"}</span> },
    {
      key: "addresses",
      header: "Addresses",
      sort: (a) => a.ipv4[0] ?? "",
      cell: (a) => (
        <div className="space-y-0.5">
          {[...a.ipv4, ...a.ipv6].map((ip) => (
            <Mono key={ip} className="block text-[11.5px] text-fg">
              {ip}
            </Mono>
          ))}
          {a.ipv4.length + a.ipv6.length === 0 ? <span className="text-faint">—</span> : null}
        </div>
      ),
    },
    { key: "gateway", header: "Gateway", sort: (a) => a.gateways[0] ?? "", cell: (a) => <Mono className="text-[11.5px] text-muted">{a.gateways.join(", ") || "—"}</Mono> },
    { key: "dns", header: "DNS servers", sort: (a) => a.dns[0] ?? "", cell: (a) => <Mono className="text-[11.5px] text-muted">{a.dns.join(", ") || "—"}</Mono> },
    {
      key: "dhcp",
      header: "DHCP",
      sort: (a) => (a.dhcp ? 0 : 1),
      cell: (a) => <span className="text-muted">{a.dhcp ? `Yes${a.dhcp_server ? ` (${a.dhcp_server})` : ""}` : "No"}</span>,
    },
    { key: "mac", header: "MAC", sort: (a) => a.mac, cell: (a) => <Mono className="text-[11.5px] text-muted">{a.mac || "—"}</Mono> },
  ];
  const adapters = [...info.data.adapters].sort((a, b) => (a.status === "up" ? 0 : 1) - (b.status === "up" ? 0 : 1));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted">
        {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
        <span>Reported with Inventory · snapshot {info.snapshot_at ? relativeTime(info.snapshot_at) : "never"}</span>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Hardware">
          <dl>
            <Row label="Manufacturer"><Value v={h.manufacturer} /></Row>
            <Row label="Model"><Value v={h.model} /></Row>
            <Row label="Serial number"><Mono><Value v={h.serial} /></Mono></Row>
            <Row label="System UUID"><Mono className="text-[11.5px]"><Value v={h.uuid} /></Mono></Row>
            <Row label="BIOS">
              <Value v={[h.bios_vendor, h.bios_version, h.bios_date].filter(Boolean).join(" · ")} />
            </Row>
            <Row label="Processor"><Value v={cpu.model} /></Row>
            <Row label="Cores">
              {cpu.cores || cpu.logical_processors ? (
                [cpu.sockets && `${cpu.sockets} socket${cpu.sockets === 1 ? "" : "s"}`, cpu.cores && `${cpu.cores} cores`, cpu.logical_processors && `${cpu.logical_processors} logical processors`].filter(Boolean).join(" · ")
              ) : (
                <span className="text-faint">Not provided</span>
              )}
            </Row>
          </dl>
        </Panel>
        <Panel title="Operating system">
          <dl>
            <Row label="Name"><Value v={os.name} /></Row>
            <Row label="Edition"><Value v={os.edition} /></Row>
            <Row label="Version"><Value v={[os.display_version, os.build && `build ${os.build}`].filter(Boolean).join(" · ")} /></Row>
            <Row label="Installed">{os.install_date ? absoluteTime(os.install_date) : <span className="text-faint">Not provided</span>}</Row>
            <Row label="Time zone">{os.time_zone ? `${os.time_zone} (${offset(os.utc_offset_minutes)})` : offset(os.utc_offset_minutes)}</Row>
            <Row label="Domain">
              {joins[domain.join]}
              {domain.name ? <span className="text-muted"> · {domain.name}</span> : null}
            </Row>
            <Row label="Microsoft Entra ID">
              {entra[domain.entra]}
              {domain.entra_tenant ? <span className="text-muted"> · {domain.entra_tenant}</span> : null}
              {domain.entra_tenant_id ? <Mono className="ml-1 text-[11.5px] text-faint">{domain.entra_tenant_id}</Mono> : null}
            </Row>
          </dl>
        </Panel>
      </div>
      <SecurityPanel d={d} />
      <Panel
        title="Network adapters"
        actions={
          <div className="flex items-center gap-2">
            {info.primary_ipv4 ? (
              <span className="text-[12px] text-muted">
                Primary IPv4 <Mono className="text-fg">{info.primary_ipv4}</Mono>
              </span>
            ) : null}
            <SkippedBadge count={info.data.skipped ?? 0} one="adapter" many="adapters" />
          </div>
        }
        bodyClassName="p-0"
      >
        <DataTable columns={columns} rows={adapters} rowKey={(a) => a.name} dense empty={<EmptyState title="No network adapters reported" />} />
      </Panel>
    </div>
  );
}
