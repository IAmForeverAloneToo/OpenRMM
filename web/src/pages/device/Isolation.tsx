import { useState } from "react";
import { Link } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldOff, Unplug } from "lucide-react";
import { post } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { DeviceDetail, Isolation, IsolationRule } from "../../lib/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, Field, Mono, Select } from "../../components/ui";
import { CaseChoice, useCaseChoice } from "../LiveResponse";

// Network isolation. Isolating needs the device name typed; while a device
// is isolated, a banner shows what stays reachable, the one-time release
// code for the local break-glass command, and Release. Until isolation has
// been verified on a disposable machine, agents run it as a dry run:
// nothing is blocked.

const LIVE = "00000000000000000000000000000000";
const releaseAfter = [
  { value: "0", label: "Never (release by hand)" },
  { value: "3600", label: "After 1 hour" },
  { value: "14400", label: "After 4 hours" },
  { value: "86400", label: "After 24 hours" },
  { value: "604800", label: "After 7 days" },
];
const purposes: Record<IsolationRule["purpose"], string> = { server: "OpenRMM server", dns: "DNS resolver", dhcp: "DHCP", loopback: "This device (loopback)", allow: "Allow list" };

export function IsolateDialog({ d, open, onOpenChange }: { d: DeviceDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const c = useCaseChoice("none");
  const [after, setAfter] = useState("0");
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Isolate ${d.device.hostname} from the network?`}
      confirmLabel="Isolate device"
      danger
      typed={d.device.hostname}
      onConfirm={async () => {
        if (!c.body) throw new Error("Choose an open case or give the new case a title.");
        await post(`/api/v1/devices/${d.device.id}/isolate`, { ...c.body, confirm: d.device.hostname, release_after: Number(after) });
        await qc.invalidateQueries({ queryKey: ["device", d.device.id] });
        await qc.invalidateQueries({ queryKey: ["devices"] });
        onOpenChange(false);
      }}
    >
      <div className="space-y-3 text-[13px]">
        <p>
          The device stops all network traffic except to the OpenRMM server, its DNS resolvers, DHCP and the addresses in its policy's allow list. You keep managing it from here; release it from the device page. A
          one-time release code lets a local administrator release it if it loses contact.
        </p>
        <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-warn">
          Dry run: isolation is not yet verified on a test machine, so agents work out and report the rules but block nothing.
        </p>
        <Field label="Release automatically">
          <Select className="w-full" value={after} onChange={(e) => setAfter(e.target.value)} aria-label="Release automatically">
            {releaseAfter.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </Select>
        </Field>
        <CaseChoice open allowNone {...c.props} noneNote="Isolating and releasing are recorded in the audit log." note="Isolating, releasing and a local release are recorded in the case's custody log." />
      </div>
    </ConfirmDialog>
  );
}

function rule(r: IsolationRule) {
  return `${r.protocol === "any" ? "" : `${r.protocol.toUpperCase()} `}${r.remote}${r.port ? ` port ${r.port}` : ""}${r.direction === "both" ? " (both ways)" : ""}`;
}

/** Shown while an isolation is under way or in force, and after a failure. */
export function IsolationBanner({ d, canRespond }: { d: DeviceDetail; canRespond: boolean }) {
  const qc = useQueryClient();
  const [releasing, setReleasing] = useState(false);
  const i: Isolation = d.isolation;
  const reported = i.reported;
  const active = i.phase === "isolating" || i.phase === "isolated" || i.phase === "releasing" || reported.isolated;
  if (!active && i.phase !== "failed") return null;
  if (i.phase === "failed") {
    // Only right after the attempt: an old failure is history.
    if (Date.now() / 1000 - (i.released_at ?? 0) > 24 * 3600) return null;
    return (
      <div className="mt-4 rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-[13px] text-danger">
        Isolation failed {relativeTime(i.released_at)}: the device did not report being isolated (for example, it could not work out the server's address or its DNS resolvers). Try again or check the device; the isolate action's result has the details.
      </div>
    );
  }
  const dry = reported.mode === "dry_run";
  const label = i.phase === "isolating" ? "Isolating — waiting for the device" : i.phase === "releasing" ? "Releasing — waiting for the device" : dry ? "Isolated (dry run)" : "Isolated from the network";
  return (
    <div className="mt-4 rounded-md border border-danger/50 bg-danger-soft/60 px-4 py-3 text-[13px]">
      <div className="flex flex-wrap items-center gap-3">
        <Unplug className="size-5 text-danger" aria-hidden />
        <span className="font-semibold text-danger">{label}</span>
        <span className="text-muted">
          by {i.actor} {relativeTime(i.requested_at)}
          {reported.release_at ? ` · releases automatically ${absoluteTime(Date.parse(reported.release_at) / 1000)}` : ""}
        </span>
        {i.case_id && i.case_id !== LIVE ? (
          <Link to={`/cases/${i.case_id}`} className="text-accent hover:underline">
            Case
          </Link>
        ) : null}
        <span className="flex-1" />
        {canRespond && i.phase !== "releasing" ? (
          <Button size="sm" icon={<ShieldOff className="size-3.5" />} onClick={() => setReleasing(true)}>
            Release
          </Button>
        ) : null}
      </div>
      {dry ? <p className="mt-2 text-warn">Dry run: the agent worked out the rules below but blocks nothing, until isolation is verified on a test machine.</p> : null}
      {reported.rules?.length ? (
        <div className="mt-2">
          <span className="text-muted">Stays reachable:</span>
          <ul className="mt-1 grid gap-x-6 gap-y-0.5 sm:grid-cols-2">
            {reported.rules.map((r, n) => (
              <li key={n} className="flex min-w-0 items-baseline gap-2">
                <Badge tone="neutral" className="shrink-0">
                  {purposes[r.purpose] ?? r.purpose}
                </Badge>
                <Mono className="min-w-0 text-[12px] break-all text-fg">{rule(r)}</Mono>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {i.code ? (
        <div className="mt-3 rounded-md border border-border bg-surface px-3 py-2">
          <span className="text-muted">Release code for a local administrator (works once, offline): </span>
          <Mono className="text-[14px] font-semibold tracking-wider text-fg">{i.code}</Mono>
          <p className="mt-1 text-[12px] text-faint">
            On the device, in an administrator prompt: <Mono className="text-[11.5px]">"C:\Program Files\OpenRMM Agent\openrmm-agent.exe" -state "C:\ProgramData\OpenRMM Agent\state" -release-isolation {i.code}</Mono>
          </p>
        </div>
      ) : null}
      <ConfirmDialog
        open={releasing}
        onOpenChange={setReleasing}
        title={`Release ${d.device.hostname} from isolation?`}
        confirmLabel="Release"
        onConfirm={async () => {
          await post(`/api/v1/devices/${d.device.id}/release-isolation`);
          await qc.invalidateQueries({ queryKey: ["device", d.device.id] });
          await qc.invalidateQueries({ queryKey: ["devices"] });
          setReleasing(false);
        }}
      >
        <p className="text-[13px]">The device's network traffic is allowed again as soon as it takes the release (it is asked first, before other work).</p>
      </ConfirmDialog>
    </div>
  );
}
