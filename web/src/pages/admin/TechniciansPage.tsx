import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Plus, Users } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, plural } from "../../lib/format";
import type { DevicesResponse, Technician, TechnicianAccess } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { ConfirmDialog, Modal } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, SearchInput, Segmented, Spinner, cx, type Tone } from "../../components/ui";

type Permission = "events" | "services" | "processes" | "desktop" | "files" | "response";
const permissions: { key: Permission; label: string; help: string }[] = [
  { key: "events", label: "Event logs", help: "Query System and Application logs" },
  { key: "services", label: "Services", help: "Start, stop and restart services" },
  { key: "processes", label: "Processes", help: "End processes" },
  { key: "desktop", label: "Remote desktop", help: "View or control the signed-in user's screen" },
  { key: "files", label: "Files", help: "Browse, download and upload on the device's fixed drives" },
  { key: "response", label: "Incident response", help: "See and work on all cases and their custody logs; response actions on devices they can access" },
];
type Preset = "readonly" | "helpdesk" | "full" | "custom";
const presets: Record<Exclude<Preset, "custom">, { label: string; grants: Permission[] }> = {
  readonly: { label: "Read-only", grants: [] },
  helpdesk: { label: "Helpdesk", grants: ["events", "services", "processes", "desktop"] },
  full: { label: "Full technician", grants: ["events", "services", "processes", "desktop", "files"] },
};
function presetOf(a: TechnicianAccess): Preset {
  for (const [k, p] of Object.entries(presets)) if (permissions.every((x) => a[x.key] === p.grants.includes(x.key))) return k as Preset;
  return "custom";
}
const emptyAccess: TechnicianAccess = { all_devices: false, devices: [], groups: [], events: false, services: false, processes: false, desktop: false, files: false, response: false };

function status(t: Technician): { label: string; tone: Tone } {
  if (!t.enabled) return { label: "Disabled", tone: "neutral" };
  if (t.confirmed) return { label: "Active", tone: "ok" };
  if (t.pending_activation) return { label: "Invited", tone: "info" };
  return { label: "Invitation expired", tone: "warn" };
}

function InvitationDialog({ invitation, username, onClose }: { invitation: string; username: string; onClose: () => void }) {
  const link = `${window.location.origin}/activate#${invitation}`;
  const [copied, setCopied] = useState(false);
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Invitation for ${username}`}
      description="Shown only once. Send it to the technician over a channel you trust; it expires in 30 minutes."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="flex items-center gap-2">
        <Input readOnly value={link} className="font-mono text-[12px]" onFocus={(e) => e.target.select()} aria-label="Invitation link" />
        <Button
          icon={copied ? <Check className="size-4" /> : <Copy className="size-4" />}
          onClick={() => void navigator.clipboard.writeText(link).then(() => setCopied(true))}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <p className="mt-3 text-[12.5px] text-muted">The technician opens the link, chooses a password (at least 15 characters) and sets up an authenticator app. They can then sign in with username {username}.</p>
      <details className="mt-2 text-[12.5px] text-muted">
        <summary className="cursor-pointer hover:text-fg">Send the code separately instead</summary>
        <p className="mt-1.5">They open {window.location.origin}/activate and paste this code:</p>
        <Mono className="mt-1 block break-all text-fg">{invitation}</Mono>
      </details>
    </Modal>
  );
}

function TechnicianEditor({ existing, onClose }: { existing: Technician | null; onClose: (invite?: { invitation: string; username: string }) => void }) {
  const client = useQueryClient();
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const [username, setUsername] = useState(existing?.username ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [access, setAccess] = useState<TechnicianAccess>(existing ? { ...existing.access, devices: existing.access.devices ?? [], groups: existing.access.groups ?? [] } : { ...emptyAccess, events: true, services: true, processes: true, desktop: true });
  const [filter, setFilter] = useState("");
  const [id] = useState(() => existing?.id ?? newOperationID());
  const [digest, setDigest] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const preset = presetOf(access);
  const set = (p: Partial<TechnicianAccess>) => (setAccess({ ...access, ...p }), setDigest(""));
  const toggle = (key: "devices" | "groups", v: string) => set({ [key]: access[key].includes(v) ? access[key].filter((x) => x !== v) : [...access[key], v] });
  const list = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return (devices.data?.devices ?? []).filter((d) => d.status !== "revoked" && (!t || d.hostname.toLowerCase().includes(t)));
  }, [devices.data, filter]);
  const validName = /^[a-z0-9][a-z0-9._-]{2,63}$/.test(username);
  const valid = validName && (access.all_devices || access.devices.length + access.groups.length > 0) && access.devices.length <= 100 && access.groups.length <= 100;
  const change = { action: existing ? "save" : "create", id, username, revision: existing?.revision ?? 0, enabled, access: access.all_devices ? { ...access, devices: [], groups: [] } : access };
  const step = async (op: "review" | "apply") => {
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ digest?: string; invitation?: string }>(`/api/v1/technicians/${op}`, { change, digest: op === "apply" ? digest : "" });
      if (op === "review") setDigest(r.digest ?? "");
      else {
        await client.invalidateQueries({ queryKey: ["technicians"] });
        onClose(r.invitation ? { invitation: r.invitation, username } : undefined);
      }
    } catch (e) {
      setError(e);
      setDigest("");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onOpenChange={(o) => !o && !busy && onClose()}
      title={existing ? `Edit ${existing.username}` : "New technician"}
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={() => onClose()}>
            Cancel
          </Button>
          {digest ? (
            <Button variant="primary" loading={busy} onClick={() => void step("apply")}>
              {existing ? "Save changes" : "Create and get invitation"}
            </Button>
          ) : (
            <Button variant="primary" loading={busy} disabled={!valid} onClick={() => void step("review")}>
              Review
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-[1fr_auto] items-end gap-3">
          <Field label="Username" hint={existing ? undefined : "3–64 lowercase letters, digits, . _ -"}>
            <Input autoFocus={!existing} value={username} disabled={!!existing} onChange={(e) => (setUsername(e.target.value.toLowerCase()), setDigest(""))} maxLength={64} className={username && !validName ? "border-danger" : undefined} />
          </Field>
          {existing ? (
            <label className="mb-2 flex items-center gap-2 text-[13px] text-fg">
              <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={enabled} onChange={(e) => (setEnabled(e.target.checked), setDigest(""))} />
              Account enabled
            </label>
          ) : null}
        </div>

        <Field label="Role">
          <Segmented
            label="Role"
            value={preset}
            onChange={(p) => p !== "custom" && set(Object.fromEntries(permissions.map((x) => [x.key, presets[p].grants.includes(x.key)])) as Partial<TechnicianAccess>)}
            options={[...Object.entries(presets).map(([k, p]) => ({ value: k as Preset, label: p.label })), { value: "custom" as Preset, label: "Custom" }]}
          />
        </Field>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-md border border-border p-3">
          <div className="col-span-2 text-[12.5px] text-muted">Everyone can view devices, inventory, metrics, alerts and run history in their scope. Additionally allow:</div>
          {permissions.map((p) => (
            <label key={p.key} className="flex items-start gap-2 text-[13px]">
              <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={access[p.key]} onChange={(e) => set({ [p.key]: e.target.checked })} />
              <span>
                <span className="text-fg">{p.label}</span>
                <span className="block text-[12px] text-faint">{p.help}</span>
              </span>
            </label>
          ))}
          <div className="col-span-2 text-[12px] text-faint">The response permission also opens live response (PowerShell as SYSTEM). Script library, patching, deployments and settings stay owner-only.</div>
        </div>

        <Field label="Devices">
          <Segmented
            label="Scope"
            value={access.all_devices ? "all" : "some"}
            onChange={(v) => set({ all_devices: v === "all" })}
            options={[
              { value: "all", label: "All devices" },
              { value: "some", label: "Selected groups and devices" },
            ]}
          />
        </Field>
        {!access.all_devices ? (
          <div className="overflow-hidden rounded-md border border-border">
            {(devices.data?.groups ?? []).length ? (
              <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
                <span className="text-[12px] text-muted">Groups (current and future members):</span>
                {devices.data!.groups.map((g) => (
                  <button key={g.id} type="button" aria-pressed={access.groups.includes(g.id)} onClick={() => toggle("groups", g.id)} className={cx("rounded-md border px-2 py-0.5 text-[12.5px]", access.groups.includes(g.id) ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}>
                    {g.name}
                  </button>
                ))}
              </div>
            ) : null}
            <div className="border-b border-border px-3 py-2">
              <SearchInput value={filter} onChange={setFilter} placeholder="Filter devices" />
            </div>
            {devices.isPending ? (
              <div className="p-3">
                <Spinner label="Loading devices" />
              </div>
            ) : (
              <ul className="max-h-48 divide-y divide-border overflow-y-auto">
                {list.map((d) => (
                  <li key={d.id}>
                    <label className="flex cursor-pointer items-center gap-3 px-3 py-1.5 hover:bg-surface-2">
                      <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={access.devices.includes(d.id)} onChange={() => toggle("devices", d.id)} />
                      <span className="flex-1 truncate text-fg">{d.hostname}</span>
                      <span className="text-[12px] text-faint">{d.group_name ?? "Ungrouped"}</span>
                    </label>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}

        {digest ? (
          <p className="rounded-md bg-surface-2 px-3 py-2 text-[12.5px] text-muted">
            {existing ? "Saving signs the technician out and cancels their queued work, so the new access applies immediately." : "Creating the account gives you a one-time invitation link to send to the technician."}
          </p>
        ) : null}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

export function TechniciansPage() {
  const client = useQueryClient();
  const q = useQuery({ queryKey: ["technicians"], queryFn: ({ signal }) => get<{ technicians: Technician[] }>("/api/v1/technicians", signal) });
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const [editor, setEditor] = useState<{ existing: Technician | null; key: number } | null>(null);
  const [invite, setInvite] = useState<{ invitation: string; username: string } | null>(null);
  const [reset, setReset] = useState<Technician | null>(null);
  const groupName = (id: string) => devices.data?.groups.find((g) => g.id === id)?.name ?? id;

  const columns: Column<Technician>[] = [
    { key: "username", header: "Username", sort: (t) => t.username, cell: (t) => <Mono className="font-medium text-fg">{t.username}</Mono> },
    {
      key: "status",
      header: "Status",
      sort: (t) => status(t).label,
      cell: (t) => (
        <Badge tone={status(t).tone} dot>
          {status(t).label}
        </Badge>
      ),
    },
    { key: "role", header: "Role", cell: (t) => <span className="text-muted">{presetOf(t.access) === "custom" ? "Custom" : presets[presetOf(t.access) as Exclude<Preset, "custom">].label}</span> },
    {
      key: "scope",
      header: "Devices",
      cell: (t) =>
        t.access.all_devices ? (
          <span className="text-fg">All devices</span>
        ) : (
          <span className="text-muted">
            {[(t.access.groups ?? []).map(groupName).join(", "), (t.access.devices ?? []).length ? plural(t.access.devices.length, "device") : ""].filter(Boolean).join(" · ") || "None"}
          </span>
        ),
    },
    { key: "created", header: "Created", sort: (t) => t.created_at, cell: (t) => <span className="text-muted">{absoluteTime(t.created_at)}</span> },
    {
      key: "actions",
      header: "",
      className: "w-px text-right whitespace-nowrap",
      cell: (t) => (
        <span className="flex justify-end gap-1.5">
          <Button size="sm" variant="ghost" onClick={(e) => (e.stopPropagation(), setReset(t))} disabled={!t.enabled}>
            New invitation
          </Button>
          <Button size="sm" onClick={(e) => (e.stopPropagation(), setEditor({ existing: t, key: Date.now() }))}>
            Edit
          </Button>
        </span>
      ),
    },
  ];

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Technicians"
        subtitle="Accounts with limited, scoped access. Each signs in with a password and an authenticator app."
        actions={
          <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditor({ existing: null, key: Date.now() })}>
            New technician
          </Button>
        }
      />
      <Panel bodyClassName="p-0">
        {q.isPending ? (
          <div className="p-4">
            <Spinner label="Loading accounts" />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorNotice error={q.error} retry={() => void q.refetch()} />
          </div>
        ) : (
          <DataTable
            columns={columns}
            rows={q.data.technicians}
            rowKey={(t) => t.id}
            initialSort={{ key: "username", dir: "asc" }}
            empty={
              <EmptyState icon={<Users />} title="No technicians yet">
                Create one to give someone limited access to some or all devices.
              </EmptyState>
            }
          />
        )}
      </Panel>
      {editor ? (
        <TechnicianEditor
          key={editor.key}
          existing={editor.existing}
          onClose={(inv) => {
            setEditor(null);
            if (inv) setInvite(inv);
          }}
        />
      ) : null}
      {invite ? <InvitationDialog invitation={invite.invitation} username={invite.username} onClose={() => setInvite(null)} /> : null}
      <ConfirmDialog
        open={reset !== null}
        onOpenChange={(o) => !o && setReset(null)}
        title={`Issue a new invitation for ${reset?.username ?? ""}?`}
        confirmLabel="Reset and invite"
        danger
        onConfirm={async () => {
          const t = reset!;
          const change = { action: "reset", id: t.id, username: t.username, revision: t.revision, enabled: true, access: t.access };
          const r = await post<{ digest: string }>("/api/v1/technicians/review", { change, digest: "" });
          const applied = await post<{ invitation?: string }>("/api/v1/technicians/apply", { change, digest: r.digest });
          await client.invalidateQueries({ queryKey: ["technicians"] });
          if (applied.invitation) setInvite({ invitation: applied.invitation, username: t.username });
        }}
      >
        <p>Their password, authenticator and recovery codes stop working and they are signed out. They set up sign-in again from the new link (valid 30 minutes).</p>
      </ConfirmDialog>
    </div>
  );
}
