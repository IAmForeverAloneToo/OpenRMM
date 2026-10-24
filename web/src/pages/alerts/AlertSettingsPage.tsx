import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Mail } from "lucide-react";
import { get, post } from "../../lib/api";
import type { AlertRule, AlertSettings } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Input, Panel, Select, Spinner } from "../../components/ui";

const titles: Record<string, { title: string; unit: string }> = {
  offline: { title: "Device offline", unit: "" },
  cpu: { title: "High CPU", unit: "CPU use at or above" },
  memory: { title: "High memory", unit: "Memory use at or above" },
  disk_space: { title: "Low system disk space", unit: "Free space below" },
};

function RuleEditor({ rule }: { rule: AlertRule }) {
  const client = useQueryClient();
  const [draft, setDraft] = useState(rule);
  const [confirm, setConfirm] = useState(false);
  useEffect(() => setDraft(rule), [rule]);
  const changed = JSON.stringify(draft) !== JSON.stringify(rule);
  const holdMin = draft.hold_seconds / 60;
  const recMin = draft.recovery_seconds / 60;
  const valid = (draft.kind === "offline" || (draft.threshold >= 1 && draft.threshold <= 99)) && holdMin >= 1 && holdMin <= 1440 && recMin >= 1 && recMin <= 60;
  const t = titles[draft.kind] ?? { title: draft.kind, unit: "" };
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3 last:border-b-0">
      <label className="flex w-52 items-center gap-2">
        <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
        <span className="font-medium text-fg">{t.title}</span>
      </label>
      {draft.kind !== "offline" ? (
        <span className="flex items-center gap-1.5 text-[13px] text-muted">
          {t.unit}
          <Input type="number" min={1} max={99} value={draft.threshold} onChange={(e) => setDraft({ ...draft, threshold: Number(e.target.value) })} className="w-16" aria-label="Threshold percent" />%
        </span>
      ) : (
        <span className="text-[13px] text-muted">No contact</span>
      )}
      <span className="flex items-center gap-1.5 text-[13px] text-muted">
        for
        <Input type="number" min={1} max={1440} value={holdMin} onChange={(e) => setDraft({ ...draft, hold_seconds: Number(e.target.value) * 60 })} className="w-20" aria-label="Trigger minutes" />
        min
      </span>
      <span className="flex items-center gap-1.5 text-[13px] text-muted">
        recover after
        <Input type="number" min={1} max={60} value={recMin} onChange={(e) => setDraft({ ...draft, recovery_seconds: Number(e.target.value) * 60 })} className="w-16" aria-label="Recovery minutes" />
        min
      </span>
      <Select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value as AlertRule["severity"] })} aria-label="Severity">
        <option value="warning">Warning</option>
        <option value="critical">Critical</option>
      </Select>
      <label className="flex items-center gap-1.5 text-[13px] text-muted">
        <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={draft.email} onChange={(e) => setDraft({ ...draft, email: e.target.checked })} /> Email
      </label>
      <div className="flex-1" />
      {changed ? (
        <>
          <Button size="sm" variant="ghost" onClick={() => setDraft(rule)}>
            Reset
          </Button>
          <Button size="sm" variant="primary" disabled={!valid} onClick={() => setConfirm(true)}>
            Save
          </Button>
        </>
      ) : null}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={`Save the “${t.title}” rule?`}
        confirmLabel="Save rule"
        onConfirm={async () => {
          await post(`/api/v1/alert-settings/rules/${draft.kind}`, draft);
          await client.invalidateQueries({ queryKey: ["alert-settings"] });
        }}
      >
        <p>Open alerts of this type close (as “settings changed”, not recovered), and devices start qualifying again under the new rule. Devices with a group or device policy keep their own rule.</p>
      </ConfirmDialog>
    </div>
  );
}

export function AlertSettingsPage() {
  const client = useQueryClient();
  const q = useQuery({ queryKey: ["alert-settings"], queryFn: ({ signal }) => get<AlertSettings>("/api/v1/alert-settings", signal) });
  const [mailBusy, setMailBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (q.isPending) return <div className="p-8"><Spinner label="Loading settings" /></div>;
  if (q.isError) return <div className="p-8"><ErrorNotice error={q.error} /></div>;
  const d = q.data;
  const toggleMail = async () => {
    setMailBusy(true);
    setError(null);
    try {
      await post("/api/v1/alert-settings/mail", { paused: !d.runtime.mail_paused });
      await client.invalidateQueries({ queryKey: ["alert-settings"] });
    } catch (e) {
      setError(e);
    } finally {
      setMailBusy(false);
    }
  };
  return (
    <div className="mx-auto max-w-[1200px] px-6 py-6">
      <Link to="/alerts" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Alerts
      </Link>
      <PageHeader title="Alert settings" subtitle="Default rules for all devices. Groups and devices can override them in Groups & policies." />
      <div className="space-y-5">
        <Panel title="Default rules" bodyClassName="p-0">
          {d.rules.map((r) => (
            <RuleEditor key={r.kind} rule={r} />
          ))}
        </Panel>
        <Panel title="Email notifications">
          <div className="flex flex-wrap items-center gap-3">
            <Mail className="size-4 text-muted" />
            {d.runtime.mail_configured ? <Badge tone="ok">Mail server configured</Badge> : <Badge tone="neutral">No mail server configured</Badge>}
            {d.runtime.mail_configured ? <Badge tone={d.runtime.mail_paused ? "warn" : "ok"}>{d.runtime.mail_paused ? "Paused" : "Sending"}</Badge> : null}
            <div className="flex-1" />
            {d.runtime.mail_configured ? (
              <Button loading={mailBusy} onClick={() => void toggleMail()}>
                {d.runtime.mail_paused ? "Resume email" : "Pause email"}
              </Button>
            ) : null}
          </div>
          {!d.runtime.mail_configured ? <p className="mt-2 text-[12.5px] text-muted">Email is configured on the server with a protected SMTP settings file (see docs/ALERTS.md).</p> : null}
          {error ? <ErrorNotice error={error} /> : null}
        </Panel>
        <p className="text-[12px] text-faint">
          Monitoring {d.runtime.active_devices} devices{d.runtime.capacity_limited ? " (capacity limit reached)" : ""}. Offline after {Math.round(d.runtime.offline_after_seconds)}s without contact.
        </p>
      </div>
    </div>
  );
}
