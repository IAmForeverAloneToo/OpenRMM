import { useState } from "react";
import { Link } from "react-router";
import { FolderTree, Plus, ShieldHalf } from "lucide-react";
import { plural } from "../../lib/format";
import { slugify } from "../../lib/parse";
import { AGENT_FEATURES } from "../../lib/features";
import type { AlertRule, OrgGroup, OrgPolicy, Organization, OrganizationChange } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, Select, Spinner, cx } from "../../components/ui";
import { OrgChangeDialog, useOrganization } from "./org";

const ruleTitles: Record<string, string> = { offline: "Device offline", cpu: "High CPU", memory: "High memory", disk_space: "Low system disk space" };
const idPattern = /^[a-z][a-z0-9_-]{0,31}$/;

type Selection = { kind: "group"; item: OrgGroup | null } | { kind: "policy"; item: OrgPolicy | null } | null;

function ruleValid(r: AlertRule): boolean {
  return (r.kind === "offline" || (r.threshold >= 1 && r.threshold <= 99)) && r.hold_seconds >= 60 && r.hold_seconds <= 86400 && r.recovery_seconds >= 60 && r.recovery_seconds <= 3600;
}

function RulesEditor({ rules, onChange }: { rules: AlertRule[]; onChange: (r: AlertRule[]) => void }) {
  const set = (i: number, p: Partial<AlertRule>) => onChange(rules.map((r, j) => (i === j ? { ...r, ...p } : r)));
  return (
    <div className="divide-y divide-border rounded-md border border-border">
      {rules.map((r, i) => (
        <div key={r.kind} className={cx("space-y-2 px-3 py-2.5", !ruleValid(r) && "bg-danger-soft")}>
          <label className="flex items-center gap-2 font-medium text-fg">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={r.enabled} onChange={(e) => set(i, { enabled: e.target.checked })} />
            {ruleTitles[r.kind] ?? r.kind}
          </label>
          {r.enabled ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2 pl-6 text-[12.5px] text-muted">
              {r.kind !== "offline" ? (
                <span className="flex items-center gap-1">
                  {r.kind === "disk_space" ? "free below" : "at or above"}
                  <Input type="number" min={1} max={99} value={r.threshold} onChange={(e) => set(i, { threshold: Number(e.target.value) })} className="w-16" aria-label="Threshold percent" />%
                </span>
              ) : null}
              <span className="flex items-center gap-1">
                for
                <Input type="number" min={1} max={1440} value={r.hold_seconds / 60} onChange={(e) => set(i, { hold_seconds: Number(e.target.value) * 60 })} className="w-16" aria-label="Trigger minutes" />
                min
              </span>
              <span className="flex items-center gap-1">
                recover
                <Input type="number" min={1} max={60} value={r.recovery_seconds / 60} onChange={(e) => set(i, { recovery_seconds: Number(e.target.value) * 60 })} className="w-14" aria-label="Recovery minutes" />
                min
              </span>
              <Select value={r.severity} onChange={(e) => set(i, { severity: e.target.value as AlertRule["severity"] })} aria-label="Severity">
                <option value="warning">Warning</option>
                <option value="critical">Critical</option>
              </Select>
              <label className="flex items-center gap-1">
                <input type="checkbox" className="size-3.5 accent-[var(--accent)]" checked={r.email} onChange={(e) => set(i, { email: e.target.checked })} /> Email
              </label>
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function GroupEditor({ org, group, onDone }: { org: Organization; group: OrgGroup | null; onDone: () => void }) {
  const [name, setName] = useState(group?.name ?? "");
  const [id, setId] = useState(group?.id ?? "");
  const [idEdited, setIdEdited] = useState(false);
  const [policy, setPolicy] = useState(group?.policy_id ?? "");
  const [change, setChange] = useState<{ c: OrganizationChange; title: string; label: string; danger?: boolean } | null>(null);
  const autoId = group ? group.id : idEdited ? id : slugify(name, org.groups.map((g) => g.id));
  const members = group ? org.devices.filter((d) => d.group_id === group.id) : [];
  const valid = name.trim().length > 0 && name.trim().length <= 80 && idPattern.test(autoId);
  return (
    <div className="space-y-4">
      <Field label="Name">
        <Input autoFocus={!group} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="e.g. Finance laptops" />
      </Field>
      {group ? null : (
        <Field label="ID" hint="Used in filters and technician access; can't be changed later.">
          <Input value={autoId} onChange={(e) => (setId(e.target.value.toLowerCase()), setIdEdited(true))} maxLength={32} className={cx("font-mono text-[12.5px]", autoId && !idPattern.test(autoId) && "border-danger")} />
        </Field>
      )}
      <Field label="Monitoring policy" hint="Alert rules for members without their own device policy.">
        <Select value={policy} onChange={(e) => setPolicy(e.target.value)} className="w-full">
          <option value="">Global defaults</option>
          {org.policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </Select>
      </Field>
      {group ? (
        <div>
          <div className="mb-1.5 text-[12.5px] font-medium text-muted">{plural(members.length, "member")}</div>
          {members.length === 0 ? (
            <p className="text-[12.5px] text-faint">Add devices from the Devices list (select them, then Organize) or from a device's console.</p>
          ) : (
            <ul className="max-h-56 divide-y divide-border overflow-y-auto rounded-md border border-border">
              {members.map((d) => (
                <li key={d.id} className="flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                  <Link to={`/devices/${d.id}`} className="flex-1 truncate text-fg hover:text-accent">
                    {d.hostname}
                  </Link>
                  {d.policy_id ? <Badge>Own policy</Badge> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
      <div className="flex items-center gap-2 border-t border-border pt-3">
        {group ? (
          <Button
            variant="ghost"
            className="text-danger"
            disabled={members.length > 0}
            onClick={() => setChange({ c: { action: "group-delete", id: group.id }, title: `Delete group “${group.name}”?`, label: "Delete group", danger: true })}
          >
            Delete
          </Button>
        ) : null}
        <div className="flex-1" />
        <Button variant="ghost" onClick={onDone}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!valid || (group !== null && name.trim() === group.name && policy === group.policy_id)}
          onClick={() =>
            setChange({ c: { action: group ? "group-save" : "group-create", id: autoId, name: name.trim(), policy_id: policy }, title: group ? `Save group “${name.trim()}”?` : `Create group “${name.trim()}”?`, label: group ? "Save group" : "Create group" })
          }
        >
          {group ? "Save" : "Create"}
        </Button>
      </div>
      {group && members.length > 0 ? <p className="text-[12px] text-faint">Move members out before deleting. Groups used in technician access can't be deleted either.</p> : null}
      <OrgChangeDialog change={change?.c ?? null} title={change?.title ?? ""} confirmLabel={change?.label ?? ""} danger={change?.danger} onClose={(applied) => (setChange(null), applied && onDone())} />
    </div>
  );
}

function PolicyEditor({ org, policy, onDone }: { org: Organization; policy: OrgPolicy | null; onDone: () => void }) {
  const [name, setName] = useState(policy?.name ?? "");
  const [id, setId] = useState("");
  const [idEdited, setIdEdited] = useState(false);
  const [rules, setRules] = useState<AlertRule[]>(() => (policy?.rules ?? org.defaults).map((r) => ({ ...r })));
  const [off, setOff] = useState<Set<string>>(() => new Set(Object.entries(policy?.features ?? {}).filter(([, on]) => !on).map(([k]) => k)));
  // Addresses or networks that stay reachable while a member is
  // isolated (the server checks the exact form).
  const [allowText, setAllowText] = useState((policy?.isolation_allow ?? []).join(", "));
  const allow = allowText.toLowerCase().split(/[\s,]+/).filter(Boolean);
  const allowValid = allow.length <= 64 && allow.every((a) => /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(a)) && new Set(allow).size === allow.length;
  const [change, setChange] = useState<{ c: OrganizationChange; title: string; label: string; danger?: boolean } | null>(null);
  const autoId = policy ? policy.id : idEdited ? id : slugify(name, org.policies.map((p) => p.id));
  const usedBy = policy ? org.groups.filter((g) => g.policy_id === policy.id).length + org.devices.filter((d) => d.policy_id === policy.id).length : 0;
  const valid = name.trim().length > 0 && name.trim().length <= 80 && idPattern.test(autoId) && rules.every(ruleValid) && allowValid;
  return (
    <div className="space-y-4">
      <Field label="Name">
        <Input autoFocus={!policy} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="e.g. Servers" />
      </Field>
      {policy ? null : (
        <Field label="ID" hint="Can't be changed later.">
          <Input value={autoId} onChange={(e) => (setId(e.target.value.toLowerCase()), setIdEdited(true))} maxLength={32} className={cx("font-mono text-[12.5px]", autoId && !idPattern.test(autoId) && "border-danger")} />
        </Field>
      )}
      <div>
        <div className="mb-1.5 flex items-center justify-between text-[12.5px] font-medium text-muted">
          Alert rules
          <Button size="sm" variant="ghost" onClick={() => setRules(org.defaults.map((r) => ({ ...r })))}>
            Copy defaults
          </Button>
        </div>
        <RulesEditor rules={rules} onChange={setRules} />
      </div>
      <div>
        <div className="mb-1.5 text-[12.5px] font-medium text-muted">Agent features</div>
        <p className="mb-2 text-[12px] text-faint">Members apply changes within a heartbeat. A feature a local administrator locked off on a device stays off.</p>
        <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          {AGENT_FEATURES.map((f) => (
            <label key={f.key} className="flex items-start gap-2 rounded-md border border-border px-2.5 py-1.5 text-[12.5px]">
              <input
                type="checkbox"
                className="mt-0.5 size-4 accent-[var(--accent)]"
                aria-label={f.label}
                checked={!off.has(f.key)}
                onChange={(e) => {
                  const next = new Set(off);
                  if (e.target.checked) next.delete(f.key);
                  else next.add(f.key);
                  setOff(next);
                }}
              />
              <span>
                <span className="block text-fg">{f.label}</span>
                <span className="block text-[11.5px] text-muted">{f.help}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
      <Field label="Reachable while isolated" hint="Addresses or networks that members can still reach when isolated, besides the OpenRMM server, DNS and DHCP — for example another security tool. Networks in their base form, such as 203.0.113.0/24; up to 64.">
        <Input value={allowText} onChange={(e) => setAllowText(e.target.value)} placeholder="None" className={cx("font-mono text-[12.5px]", !allowValid && "border-danger")} aria-label="Reachable while isolated" />
      </Field>
      <div className="flex items-center gap-2 border-t border-border pt-3">
        {policy ? (
          <Button
            variant="ghost"
            className="text-danger"
            disabled={usedBy > 0}
            onClick={() => setChange({ c: { action: "policy-delete", id: policy.id }, title: `Delete policy “${policy.name}”?`, label: "Delete policy", danger: true })}
          >
            Delete
          </Button>
        ) : null}
        <div className="flex-1" />
        <Button variant="ghost" onClick={onDone}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!valid}
          onClick={() =>
            setChange({
              c: { action: policy ? "policy-save" : "policy-create", id: autoId, name: name.trim(), rules: rules.map((r) => ({ ...r, revision: 1 })), features: Object.fromEntries([...off].map((k) => [k, false])), isolation_allow: allow },
              title: policy ? `Save policy “${name.trim()}”?` : `Create policy “${name.trim()}”?`,
              label: policy ? "Save policy" : "Create policy",
            })
          }
        >
          {policy ? "Save" : "Create"}
        </Button>
      </div>
      {policy && usedBy > 0 ? <p className="text-[12px] text-faint">Used by {plural(usedBy, "group or device", "groups or devices")}; detach it before deleting.</p> : null}
      <OrgChangeDialog change={change?.c ?? null} title={change?.title ?? ""} confirmLabel={change?.label ?? ""} danger={change?.danger} onClose={(applied) => (setChange(null), applied && onDone())} />
    </div>
  );
}

export function OrganizationPage() {
  const org = useOrganization();
  const [selected, setSelected] = useState<Selection>(null);
  const [key, setKey] = useState(0);
  const open = (s: Selection) => (setSelected(s), setKey(key + 1));
  if (org.isPending) return <div className="p-8"><Spinner label="Loading groups and policies" /></div>;
  if (org.isError) return <div className="p-8"><ErrorNotice error={org.error} retry={() => void org.refetch()} /></div>;
  const o = org.data;
  const policyName = (id: string) => o.policies.find((p) => p.id === id)?.name ?? "Global defaults";
  const ungrouped = o.devices.filter((d) => !d.group_id).length;
  const isSel = (kind: "group" | "policy", id: string) => selected?.kind === kind && selected.item?.id === id;
  const row = "flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2";

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Groups & policies" subtitle="Groups organize devices and technician access; monitoring policies set alert rules and which agent features are on." />
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_440px]">
        <div className="space-y-5">
          <Panel
            title="Groups"
            bodyClassName="p-0"
            actions={
              <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => open({ kind: "group", item: null })}>
                New group
              </Button>
            }
          >
            {o.groups.length === 0 ? (
              <EmptyState icon={<FolderTree />} title="No groups yet" />
            ) : (
              <ul className="divide-y divide-border">
                {o.groups.map((g) => (
                  <li key={g.id}>
                    <button type="button" onClick={() => open({ kind: "group", item: g })} className={cx(row, isSel("group", g.id) && "bg-accent-soft")}>
                      <span className="w-56 truncate font-medium text-fg">{g.name}</span>
                      <span className="w-28 text-[12.5px] text-muted tabular-nums">{plural(g.members, "device")}</span>
                      <span className="flex-1 truncate text-[12.5px] text-muted">{policyName(g.policy_id)}</span>
                      <span className="font-mono text-[11.5px] text-faint">{g.id}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <p className="border-t border-border px-4 py-2 text-[12px] text-faint">{plural(ungrouped, "device")} ungrouped</p>
          </Panel>
          <Panel
            title="Monitoring policies"
            bodyClassName="p-0"
            actions={
              <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => open({ kind: "policy", item: null })}>
                New policy
              </Button>
            }
          >
            <ul className="divide-y divide-border">
              <li>
                <Link to="/settings/alerts" className={row}>
                  <span className="w-56 truncate font-medium text-fg">Global defaults</span>
                  <span className="flex-1 text-[12.5px] text-muted">Used by everything without a policy · edit in Alert settings</span>
                </Link>
              </li>
              {o.policies.map((p) => {
                const groups = o.groups.filter((g) => g.policy_id === p.id).length;
                const devices = o.devices.filter((d) => d.policy_id === p.id).length;
                return (
                  <li key={p.id}>
                    <button type="button" onClick={() => open({ kind: "policy", item: p })} className={cx(row, isSel("policy", p.id) && "bg-accent-soft")}>
                      <span className="w-56 truncate font-medium text-fg">{p.name}</span>
                      <span className="flex-1 text-[12.5px] text-muted">
                        {plural(groups, "group")} · {plural(devices, "device")} directly
                      </span>
                      <span className="font-mono text-[11.5px] text-faint">{p.id}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Panel>
        </div>
        <Panel className="xl:sticky xl:top-4" title={selected ? (selected.item ? selected.item.name : selected.kind === "group" ? "New group" : "New policy") : "Details"}>
          {selected === null ? (
            <EmptyState icon={<ShieldHalf />} title="Select a group or policy">
              Or create a new one.
            </EmptyState>
          ) : selected.kind === "group" ? (
            <GroupEditor key={key} org={o} group={selected.item} onDone={() => setSelected(null)} />
          ) : (
            <PolicyEditor key={key} org={o} policy={selected.item} onDone={() => setSelected(null)} />
          )}
        </Panel>
      </div>
    </div>
  );
}
