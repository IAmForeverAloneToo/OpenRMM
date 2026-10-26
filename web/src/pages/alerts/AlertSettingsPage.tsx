import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Mail, Send } from "lucide-react";
import { get, post, put } from "../../lib/api";
import type { AlertRule, AlertSettings, EmailSettings } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Panel, Select, Spinner } from "../../components/ui";

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

// What a test message's result means, by the server's reason.
const testReasons: Record<string, string> = {
  accepted: "The mail server accepted the test message. Check the recipients' inboxes.",
  connection: "The mail server could not be reached. Check the host name, port and firewall.",
  tls: "The TLS connection failed. The mail server's certificate must be trusted and match the host name.",
  tls_required: "The mail server does not offer STARTTLS. Use TLS on port 465, or a server that supports STARTTLS.",
  rejected: "The mail server rejected the sign-in or the message. Check the user name, password and sender address.",
  temporary: "The mail server reported a temporary failure. Try again later.",
  acceptance_unknown: "The connection closed while sending; the message may or may not have been accepted.",
  too_large: "The message was too large.",
};

type EmailDraft = Omit<EmailSettings, "to" | "source" | "has_password" | "active" | "suggested_server_url" | "updated_at"> & { to: string; password: string; clear_password: boolean };

function draftOf(e: EmailSettings): EmailDraft {
  return {
    enabled: e.enabled,
    host: e.host,
    port: e.port,
    tls: e.tls,
    username: e.username,
    from: e.from,
    to: e.to.join(", "),
    server_url: e.server_url || e.suggested_server_url,
    revision: e.revision,
    password: "",
    clear_password: false,
  };
}

function EmailPanel({ runtime }: { runtime: AlertSettings["runtime"] }) {
  const client = useQueryClient();
  const q = useQuery({ queryKey: ["alert-settings", "email"], queryFn: ({ signal }) => get<EmailSettings>("/api/v1/alert-settings/email", signal) });
  const [draft, setDraft] = useState<EmailDraft | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "test" | "pause">("");
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [test, setTest] = useState<{ status: string; reason: string } | null>(null);
  useEffect(() => {
    if (q.data) setDraft(draftOf(q.data));
  }, [q.data]);
  if (q.isError) return <Panel title="Email notifications"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></Panel>;
  if (q.isPending || !draft) return <Panel title="Email notifications"><Spinner label="Loading e-mail settings" /></Panel>;
  const e = q.data;
  const d = draft;
  const set = (patch: Partial<EmailDraft>) => {
    setSaved(false);
    setDraft({ ...d, ...patch });
  };
  const changed = JSON.stringify(d) !== JSON.stringify(draftOf(e));
  const run = async (kind: "save" | "test" | "pause", action: () => Promise<void>) => {
    setBusy(kind);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err);
    } finally {
      setBusy("");
    }
  };
  const save = () =>
    run("save", async () => {
      const to = d.to.split(/[,;\s]+/).filter(Boolean);
      const next = await put<EmailSettings>("/api/v1/alert-settings/email", { ...d, to });
      client.setQueryData(["alert-settings", "email"], next);
      await client.invalidateQueries({ queryKey: ["alert-settings"], exact: true });
      setSaved(true);
      setTest(null);
    });
  const sendTest = () =>
    run("test", async () => {
      setTest(null);
      setTest(await post<{ status: string; reason: string }>("/api/v1/alert-settings/email/test"));
    });
  const togglePause = () =>
    run("pause", async () => {
      await post("/api/v1/alert-settings/mail", { paused: !runtime.mail_paused });
      await client.invalidateQueries({ queryKey: ["alert-settings"], exact: true });
    });
  const status = (
    <div className="flex flex-wrap items-center gap-2">
      <Mail className="size-4 text-muted" />
      {e.active ? <Badge tone="ok">Mail server configured</Badge> : <Badge tone="neutral">Email off</Badge>}
      {e.active ? <Badge tone={runtime.mail_paused ? "warn" : "ok"}>{runtime.mail_paused ? "Paused" : "Sending"}</Badge> : null}
      {e.source === "file" ? <Badge tone="neutral">Set by the server's SMTP file</Badge> : null}
      <div className="flex-1" />
      {e.active ? (
        <>
          <Button icon={<Send className="size-3.5" />} loading={busy === "test"} disabled={busy !== "" || changed} onClick={() => void sendTest()}>
            Send test
          </Button>
          <Button loading={busy === "pause"} disabled={busy !== ""} onClick={() => void togglePause()}>
            {runtime.mail_paused ? "Resume email" : "Pause email"}
          </Button>
        </>
      ) : null}
    </div>
  );
  const result = test ? (
    <p className={test.status === "sent" ? "text-[12.5px] text-ok" : "text-[12.5px] text-warn"}>
      {testReasons[test.reason] ?? `The test message was not sent (${test.reason}).`}
    </p>
  ) : null;
  if (e.source === "file") {
    return (
      <Panel title="Email notifications">
        <div className="space-y-3">
          {status}
          <p className="text-[12.5px] text-muted">The server was started with a protected SMTP settings file (-alert-smtp-config), which takes precedence over settings made here. Remove it to manage e-mail in the dashboard.</p>
          {result}
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      </Panel>
    );
  }
  return (
    <Panel title="Email notifications">
      <div className="space-y-4">
        {status}
        {e.enabled && !e.active ? <p className="text-[12.5px] text-warn">Email is turned on, but the saved settings cannot be used (the stored password may need to be entered again). Check them and save.</p> : null}
        <label className="flex items-center gap-2 text-[13px] text-fg">
          <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={d.enabled} onChange={(ev) => set({ enabled: ev.target.checked })} />
          Send alert e-mail
        </label>
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_120px_160px]">
          <Field label="SMTP server">
            <Input value={d.host} onChange={(ev) => set({ host: ev.target.value })} placeholder="smtp.example.com" autoComplete="off" spellCheck={false} />
          </Field>
          <Field label="Port">
            <Input type="number" min={1} max={65535} value={d.port} onChange={(ev) => set({ port: Number(ev.target.value) })} />
          </Field>
          <Field label="Encryption">
            <Select
              value={d.tls}
              onChange={(ev) => {
                const tls = ev.target.value as EmailDraft["tls"];
                // Follow the usual port when it was the other mode's default.
                const port = tls === "tls" && d.port === 587 ? 465 : tls === "starttls" && d.port === 465 ? 587 : d.port;
                set({ tls, port });
              }}
            >
              <option value="starttls">STARTTLS</option>
              <option value="tls">TLS</option>
            </Select>
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="User name" hint="Leave empty if the mail server does not require sign-in.">
            <Input value={d.username} onChange={(ev) => set({ username: ev.target.value, ...(ev.target.value === "" ? { password: "" } : {}) })} autoComplete="off" spellCheck={false} />
          </Field>
          <Field label="Password" hint={e.has_password && !d.clear_password ? "A password is stored. Leave empty to keep it." : "Stored encrypted and never shown again."}>
            <Input type="password" value={d.password} disabled={d.username === "" || d.clear_password} onChange={(ev) => set({ password: ev.target.value })} autoComplete="new-password" placeholder={e.has_password && !d.clear_password ? "••••••••" : ""} />
          </Field>
        </div>
        {e.has_password && d.username !== "" ? (
          <label className="flex items-center gap-2 text-[12.5px] text-muted">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={d.clear_password} onChange={(ev) => set({ clear_password: ev.target.checked, password: "" })} />
            Remove the stored password
          </label>
        ) : null}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Sender address">
            <Input type="email" value={d.from} onChange={(ev) => set({ from: ev.target.value })} placeholder="openrmm@example.com" spellCheck={false} />
          </Field>
          <Field label="Recipients" hint="Up to 10 addresses, separated by commas.">
            <Input value={d.to} onChange={(ev) => set({ to: ev.target.value })} placeholder="it@example.com, oncall@example.com" spellCheck={false} />
          </Field>
        </div>
        <Field label="Dashboard address" hint="Used for the links in alert e-mail. Must start with https://.">
          <Input value={d.server_url} onChange={(ev) => set({ server_url: ev.target.value })} placeholder="https://rmm.example.com" spellCheck={false} />
        </Field>
        <p className="text-[12px] text-faint">The connection is always encrypted, and the mail server's certificate must be publicly trusted. Changing the server, sender, recipients or dashboard address cancels e-mail still waiting to be sent.</p>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" loading={busy === "save"} disabled={!changed || busy !== ""} onClick={() => void save()}>
            Save e-mail settings
          </Button>
          {changed ? (
            <Button variant="ghost" disabled={busy !== ""} onClick={() => setDraft(draftOf(e))}>
              Reset
            </Button>
          ) : null}
          {saved && !changed ? <span className="text-[12.5px] text-ok">Saved.</span> : null}
          {changed && e.active ? <span className="text-[12.5px] text-faint">Save before sending a test.</span> : null}
        </div>
        {result}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Panel>
  );
}

export function AlertSettingsPage() {
  const q = useQuery({ queryKey: ["alert-settings"], queryFn: ({ signal }) => get<AlertSettings>("/api/v1/alert-settings", signal) });
  if (q.isPending) return <div className="p-8"><Spinner label="Loading settings" /></div>;
  if (q.isError) return <div className="p-8"><ErrorNotice error={q.error} /></div>;
  const d = q.data;
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
        <EmailPanel runtime={d.runtime} />
        <p className="text-[12px] text-faint">
          Monitoring {d.runtime.active_devices} devices{d.runtime.capacity_limited ? " (capacity limit reached)" : ""}. Offline after {Math.round(d.runtime.offline_after_seconds)}s without contact.
        </p>
      </div>
    </div>
  );
}
