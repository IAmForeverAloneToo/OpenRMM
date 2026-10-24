import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Archive, CircleCheck, Ellipsis, Pause, Pencil, Play, Plus, ShieldCheck } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { LIVE_INTERVAL, useNow } from "../../lib/hooks";
import { absoluteTime, clock, plural, relativeTime, weekdays, windowLabel } from "../../lib/format";
import { parseKB } from "../../lib/parse";
import type { PatchDefinition, PatchGuard, PatchOverview, PatchPolicy, PatchReview, PatchRun } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { Freshness } from "../../components/Freshness";
import { Modal } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { TargetPicker, useHostnames, type Targets } from "../../components/TargetPicker";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, Select, Spinner, Tip, cx, type Tone } from "../../components/ui";
import { OperationStatus } from "../../components/status";
import { ReviewDialog, TargetList } from "./shared";

const stateTone: Record<PatchPolicy["state"], Tone> = { active: "ok", paused: "neutral", archived: "neutral" };

// Outcomes that need an operator to look at the device.
const attentionRuns = new Set(["blocked", "unknown", "verification_failed", "window_closed", "pending_restart", "reboot_deferred", "restart_requested"]);

const detailText: Record<string, string> = {
  approved_complete: "Approved updates installed and verified",
  no_approved_updates_applicable: "No approved updates were needed",
  scan_complete: "Scan completed",
  install_unavailable: "Windows Update installation is not enabled on the device",
  mutation_requires_review: "A previous run needs review before updates can install",
  owner_unavailable: "The owner account is unavailable",
  restart_unavailable: "Restart is not enabled on the device",
  manual_restart_policy: "Restart pending; this policy leaves restarts to you",
  deferral_active: "Restart deferred",
  restart_not_yet_verified: "Restart requested; waiting for the device to come back",
  missed_start: "Missed the window start",
  offline_busy_or_broker_unavailable: "Device was offline, busy or its update service unavailable",
  incomplete_or_blocked_scan: "Scan was incomplete or blocked",
  unexpected_restart_outcome: "Restart outcome was unexpected",
  update_job_unavailable: "Update job could not be tracked",
  verification_unavailable: "Could not verify the result",
  approved_updates_still_applicable: "Approved updates are still missing after install",
  install_window_closed: "Window closed before installation finished",
  restart_window_closed: "Window closed before the restart",
};
const holdText: Record<string, { label: string; tone: Tone }> = {
  needs_review: { label: "Automation paused: needs review", tone: "warn" },
  mutation_running: { label: "Update in progress", tone: "info" },
  restart_requested: { label: "Restart requested", tone: "info" },
};

type Draft = { name: string; ring: string; weekday: number; minute: number; duration: number; install: boolean; kb: string; restart: boolean; deferHours: number; enabled: boolean };

const steps = ["Devices", "Window", "Updates", "Restart", "Review"] as const;

function PolicyWizard({ open, onOpenChange, existing }: { open: boolean; onOpenChange: (o: boolean) => void; existing: PatchPolicy | null }) {
  const client = useQueryClient();
  const initial = (): Draft =>
    existing
      ? {
          name: existing.definition.name,
          ring: existing.definition.ring,
          weekday: existing.definition.weekday,
          minute: existing.definition.minute_utc,
          duration: existing.definition.duration_minutes,
          install: existing.definition.install,
          kb: (existing.definition.approved_kb ?? []).map((k) => `KB${k}`).join("\n"),
          restart: existing.definition.restart_after_deferral,
          deferHours: existing.definition.defer_hours,
          enabled: existing.state === "active",
        }
      : { name: "", ring: "pilot", weekday: 2, minute: 120, duration: 120, install: false, kb: "", restart: false, deferHours: 24, enabled: true };
  const [draft, setDraft] = useState<Draft>(initial);
  const [targets, setTargets] = useState<Targets>({ devices: existing?.definition.devices ?? [], groups: [] });
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<PatchReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [id] = useState(() => existing?.id ?? newOperationID());
  const set = (p: Partial<Draft>) => setDraft({ ...draft, ...p });
  const kbs = parseKB(draft.kb);
  const kbValid = kbs.every((k) => /^[1-9][0-9]{3,15}$/.test(k)) && kbs.length <= 64;

  const valid = [
    draft.name.trim().length > 0 && draft.ring.trim().length > 0 && targets.devices.length + targets.groups.length > 0,
    draft.duration >= 30 && draft.duration <= 240 && draft.minute >= 0 && draft.minute < 1440,
    !draft.install || (kbs.length > 0 && kbValid),
    draft.deferHours >= 1 && draft.deferHours <= 168,
    true,
  ];
  const body = (digest = "") => {
    const definition: PatchDefinition = {
      name: draft.name.trim(),
      ring: draft.ring.trim(),
      devices: targets.devices,
      weekday: draft.weekday,
      minute_utc: draft.minute,
      duration_minutes: draft.duration,
      install: draft.install,
      approved_kb: draft.install ? kbs : [],
      restart_after_deferral: draft.restart,
      defer_hours: draft.deferHours,
    };
    return { action: "save", id, revision: existing?.revision ?? 0, enabled: draft.enabled, definition, groups: targets.groups, digest };
  };
  const goReview = async () => {
    setBusy(true);
    setError(null);
    setReview(null);
    setStep(4);
    try {
      setReview(await post<PatchReview>("/api/v1/patch-policies/review", body()));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!review) return;
    setBusy(true);
    setError(null);
    try {
      await post("/api/v1/patch-policies/apply", body(review.digest));
      await client.invalidateQueries({ queryKey: ["patching"] });
      onOpenChange(false);
    } catch (e) {
      setError(e);
      setReview(null);
    } finally {
      setBusy(false);
    }
  };
  const next = () => (step === 3 ? void goReview() : setStep(step + 1));

  return (
    <Modal
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title={existing ? `Edit “${existing.definition.name}”` : "New patch policy"}
      width="max-w-2xl"
      footer={
        <>
          {step > 0 ? (
            <Button variant="ghost" disabled={busy} onClick={() => (setStep(step - 1), setReview(null), setError(null))}>
              Back
            </Button>
          ) : null}
          <div className="flex-1" />
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {step < 4 ? (
            <Button variant="primary" disabled={!valid[step]} loading={busy} onClick={next}>
              {step === 3 ? "Review" : "Next"}
            </Button>
          ) : review ? (
            <Button variant="primary" loading={busy} onClick={() => void apply()}>
              {existing ? "Save policy" : "Create policy"}
            </Button>
          ) : (
            <Button loading={busy} onClick={() => void goReview()}>
              Review again
            </Button>
          )}
        </>
      }
    >
      <ol className="mb-4 flex items-center gap-1 text-[12px]">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-1">
            <button
              type="button"
              disabled={i > step || busy}
              onClick={() => (setStep(i), setReview(null))}
              className={cx("rounded px-2 py-0.5", i === step ? "bg-accent-soft font-medium text-fg" : i < step ? "text-muted hover:text-fg" : "text-faint")}
            >
              {i + 1}. {s}
            </button>
            {i < steps.length - 1 ? <span className="text-faint">›</span> : null}
          </li>
        ))}
      </ol>

      {step === 0 ? (
        <div className="space-y-3">
          <div className="grid grid-cols-[1fr_180px] gap-3">
            <Field label="Policy name">
              <Input autoFocus value={draft.name} onChange={(e) => set({ name: e.target.value })} maxLength={100} placeholder="e.g. Workstations – pilot" />
            </Field>
            <Field label="Ring" hint="Label for your rollout stage">
              <Input value={draft.ring} onChange={(e) => set({ ring: e.target.value })} maxLength={40} />
            </Field>
          </div>
          <TargetPicker value={targets} onChange={setTargets} include={(d) => d.os === "windows"} height="max-h-64" />
          <p className="text-[12px] text-faint">Groups are expanded to their current members when you save. A device can belong to only one active policy.</p>
        </div>
      ) : null}

      {step === 1 ? (
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <Field label="Day (UTC)">
              <Select value={draft.weekday} onChange={(e) => set({ weekday: Number(e.target.value) })} className="w-full">
                {weekdays.map((d, i) => (
                  <option key={d} value={i}>
                    {d}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Start (UTC)">
              <Input
                type="time"
                value={clock(draft.minute)}
                onChange={(e) => {
                  const [h = NaN, m = NaN] = e.target.value.split(":").map(Number);
                  if (Number.isFinite(h) && Number.isFinite(m)) set({ minute: h * 60 + m });
                }}
              />
            </Field>
            <Field label="Length (minutes)" hint="30–240">
              <Input type="number" min={30} max={240} step={15} value={draft.duration} onChange={(e) => set({ duration: Number(e.target.value) })} />
            </Field>
          </div>
          <p className="text-[12.5px] text-muted">
            Weekly, {windowLabel(draft.weekday, draft.minute, draft.duration)}. Devices that are offline or busy at the start are skipped until the next window.
          </p>
        </div>
      ) : null}

      {step === 2 ? (
        <div className="space-y-3">
          {[
            { install: false, title: "Scan only", text: "Check which updates are missing. Nothing is installed." },
            { install: true, title: "Install approved updates", text: "Install only the KB numbers you list. Updates that are not on the list are never installed." },
          ].map((o) => (
            <label key={o.title} className={cx("flex cursor-pointer gap-3 rounded-md border p-3", draft.install === o.install ? "border-accent bg-accent-soft" : "border-border hover:border-border-strong")}>
              <input type="radio" name="mode" className="mt-0.5 accent-[var(--accent)]" checked={draft.install === o.install} onChange={() => set({ install: o.install })} />
              <span>
                <span className="block font-medium text-fg">{o.title}</span>
                <span className="text-[12.5px] text-muted">{o.text}</span>
              </span>
            </label>
          ))}
          {draft.install ? (
            <Field label="Approved updates" hint={`${kbs.length} KB${kbs.length === 1 ? "" : "s"} · one per line, “KB” prefix optional, up to 64`}>
              <textarea
                value={draft.kb}
                onChange={(e) => set({ kb: e.target.value })}
                rows={5}
                spellCheck={false}
                className={cx("w-full rounded-md border bg-surface-2 px-2.5 py-1.5 font-mono text-[12.5px] text-fg outline-none focus:border-accent", kbValid ? "border-border" : "border-danger")}
                placeholder={"KB5034441\nKB5034122"}
              />
            </Field>
          ) : null}
        </div>
      ) : null}

      {step === 3 ? (
        <div className="space-y-3">
          {[
            { restart: true, title: "Restart automatically", text: "Once a restart has been pending for the delay below, a normal restart (60-second warning) is requested inside a window." },
            { restart: false, title: "Leave restarts to me", text: "Pending restarts are reported under “Needs attention”; nothing restarts on its own." },
          ].map((o) => (
            <label key={o.title} className={cx("flex cursor-pointer gap-3 rounded-md border p-3", draft.restart === o.restart ? "border-accent bg-accent-soft" : "border-border hover:border-border-strong")}>
              <input type="radio" name="restart" className="mt-0.5 accent-[var(--accent)]" checked={draft.restart === o.restart} onChange={() => set({ restart: o.restart })} />
              <span>
                <span className="block font-medium text-fg">{o.title}</span>
                <span className="text-[12.5px] text-muted">{o.text}</span>
              </span>
            </label>
          ))}
          {draft.restart ? (
            <Field label="Delay before restarting (hours)" hint="1–168, counted from when the pending restart was first seen.">
              <Input type="number" min={1} max={168} value={draft.deferHours} onChange={(e) => set({ deferHours: Number(e.target.value) })} className="w-32" />
            </Field>
          ) : null}
          <label className="flex items-center gap-2 text-[13px] text-fg">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
            Turn the policy on when saved (otherwise it is saved paused)
          </label>
        </div>
      ) : null}

      {step === 4 ? (
        <div className="space-y-3 text-[13px]">
          {busy && !review ? <Spinner label="Checking devices" /> : null}
          {review ? (
            <>
              <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5">
                <dt className="text-muted">Policy</dt>
                <dd className="text-fg">
                  {review.policy.definition.name} <span className="text-faint">· {review.policy.definition.ring}</span>
                </dd>
                <dt className="text-muted">Window</dt>
                <dd className="text-fg">{windowLabel(review.policy.definition.weekday, review.policy.definition.minute_utc, review.policy.definition.duration_minutes)}</dd>
                <dt className="text-muted">Updates</dt>
                <dd className="text-fg">{review.policy.definition.install ? `Install ${plural(review.policy.definition.approved_kb?.length ?? 0, "approved KB")}` : "Scan only"}</dd>
                <dt className="text-muted">Restart</dt>
                <dd className="text-fg">
                  {review.policy.definition.restart_after_deferral ? `Automatic, ${review.policy.definition.defer_hours}h after it is first pending` : "Manual"}
                </dd>
                <dt className="text-muted">State</dt>
                <dd>
                  <Badge tone={stateTone[review.policy.state]}>{review.policy.state === "active" ? "On" : "Paused"}</Badge>
                  {review.policy.state === "active" ? <span className="ml-2 text-muted">first window {absoluteTime(review.policy.next_at)}</span> : null}
                </dd>
              </dl>
              <div>
                <div className="mb-1.5 text-muted">{plural(review.targets.length, "device")}</div>
                <TargetList targets={review.targets} />
              </div>
            </>
          ) : null}
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      ) : null}
    </Modal>
  );
}

type Pending =
  | { kind: "policy"; policy: PatchPolicy; action: "pause" | "resume" | "archive" }
  | { kind: "guard"; guard: PatchGuard; action: "acknowledge" }
  | { kind: "guard"; guard: PatchGuard; action: "defer"; until: number };

function DeferDialog({ guard, onClose, onReview }: { guard: PatchGuard | null; onClose: () => void; onReview: (until: number) => void }) {
  const [hours, setHours] = useState(24);
  return (
    <Modal
      open={guard !== null}
      onOpenChange={(o) => !o && onClose()}
      title={`Defer the restart on ${guard?.hostname ?? ""}?`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!(hours >= 1 && hours <= 168)} onClick={() => onReview(Math.floor(Date.now() / 1000) + hours * 3600)}>
            Continue
          </Button>
        </>
      }
    >
      <Field label="Defer for (hours)" hint="1–168">
        <Input type="number" min={1} max={168} value={hours} onChange={(e) => setHours(Number(e.target.value))} className="w-32" autoFocus />
      </Field>
    </Modal>
  );
}

export function PatchingPage() {
  const client = useQueryClient();
  const now = useNow();
  const hostnames = useHostnames();
  const q = useQuery({ queryKey: ["patching"], queryFn: ({ signal }) => get<PatchOverview>("/api/v1/patch-policies", signal), refetchInterval: LIVE_INTERVAL });
  const [wizard, setWizard] = useState<{ open: boolean; existing: PatchPolicy | null; key: number }>({ open: false, existing: null, key: 0 });
  const [pending, setPending] = useState<Pending | null>(null);
  const [deferring, setDeferring] = useState<PatchGuard | null>(null);
  const [showArchived, setShowArchived] = useState(false);

  const d = q.data;
  const policyName = useMemo(() => new Map((d?.policies ?? []).map((p) => [p.id, p.definition.name])), [d]);
  const attention = useMemo(() => {
    if (!d) return [];
    const latest = new Map<string, PatchRun>();
    for (const r of d.runs) {
      const cur = latest.get(r.device_id);
      if (!cur || r.scheduled_at > cur.scheduled_at) latest.set(r.device_id, r);
    }
    const ids = new Set<string>();
    for (const g of d.guards) if (g.hold || g.reboot_since) ids.add(g.device_id);
    for (const [id, r] of latest) if (attentionRuns.has(r.status)) ids.add(id);
    const guards = new Map(d.guards.map((g) => [g.device_id, g]));
    return [...ids]
      .map((id) => ({ id, hostname: guards.get(id)?.hostname ?? hostnames.get(id) ?? id, guard: guards.get(id), run: latest.get(id) }))
      .sort((a, b) => a.hostname.localeCompare(b.hostname));
  }, [d, hostnames]);

  if (q.isPending) return <div className="p-8"><Spinner label="Loading patching" /></div>;
  if (q.isError && !d) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;

  const policies = d!.policies.filter((p) => showArchived || p.state !== "archived");
  const archived = d!.policies.length - d!.policies.filter((p) => p.state !== "archived").length;
  const openWizard = (existing: PatchPolicy | null) => setWizard({ open: true, existing, key: wizard.key + 1 });

  const columns: Column<PatchPolicy>[] = [
    {
      key: "name",
      header: "Policy",
      sort: (p) => p.definition.name,
      cell: (p) => (
        <div>
          <div className="font-medium text-fg">{p.definition.name}</div>
          <div className="text-[12px] text-faint">{p.definition.ring}</div>
        </div>
      ),
    },
    { key: "window", header: "Window", cell: (p) => <span className="text-muted">{windowLabel(p.definition.weekday, p.definition.minute_utc, p.definition.duration_minutes)}</span> },
    { key: "mode", header: "Updates", cell: (p) => (p.definition.install ? <Badge tone="info">Install {p.definition.approved_kb?.length ?? 0} KB</Badge> : <Badge>Scan only</Badge>) },
    { key: "restart", header: "Restart", cell: (p) => <span className="text-muted">{p.definition.restart_after_deferral ? `Auto after ${p.definition.defer_hours}h` : "Manual"}</span> },
    { key: "devices", header: "Devices", sort: (p) => p.definition.devices.length, cell: (p) => <span className="tabular-nums">{p.definition.devices.length}</span> },
    { key: "state", header: "State", sort: (p) => p.state, cell: (p) => <Badge tone={stateTone[p.state]} dot>{p.state === "active" ? "On" : p.state === "paused" ? "Paused" : "Archived"}</Badge> },
    {
      key: "next",
      header: "Next window",
      sort: (p) => (p.state === "active" ? p.next_at : Number.MAX_SAFE_INTEGER),
      cell: (p) =>
        p.state === "active" ? (
          <Tip label={absoluteTime(p.next_at)}>
            <span className="text-muted">{relativeTime(p.next_at, now)}</span>
          </Tip>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      key: "actions",
      header: "",
      className: "w-px text-right",
      cell: (p) =>
        p.state === "archived" ? null : (
          <Menu.Root>
            <Menu.Trigger asChild>
              <Button size="sm" variant="ghost" aria-label={`Actions for ${p.definition.name}`} icon={<Ellipsis className="size-4" />} />
            </Menu.Trigger>
            <Menu.Portal>
              <Menu.Content align="end" sideOffset={4} className="z-50 min-w-44 rounded-md border border-border-strong bg-surface p-1 shadow-panel">
                <MenuItem icon={<Pencil />} onSelect={() => openWizard(p)}>
                  Edit
                </MenuItem>
                {p.state === "active" ? (
                  <MenuItem icon={<Pause />} onSelect={() => setPending({ kind: "policy", policy: p, action: "pause" })}>
                    Pause
                  </MenuItem>
                ) : (
                  <MenuItem icon={<Play />} onSelect={() => setPending({ kind: "policy", policy: p, action: "resume" })}>
                    Turn on
                  </MenuItem>
                )}
                <MenuItem icon={<Archive />} danger onSelect={() => setPending({ kind: "policy", policy: p, action: "archive" })}>
                  Archive
                </MenuItem>
              </Menu.Content>
            </Menu.Portal>
          </Menu.Root>
        ),
    },
  ];

  const review = async () => {
    if (!pending) throw new Error("Nothing to review.");
    if (pending.kind === "policy") return post<PatchReview>("/api/v1/patch-policies/review", { action: pending.action, id: pending.policy.id, revision: pending.policy.revision });
    return post<{ digest: string }>(`/api/v1/patch-guards/${pending.guard.device_id}/review`, { action: pending.action, revision: pending.guard.revision, until: pending.action === "defer" ? pending.until : 0 });
  };
  const apply = async (r: { digest: string }) => {
    if (!pending) return;
    if (pending.kind === "policy") await post("/api/v1/patch-policies/apply", { action: pending.action, id: pending.policy.id, revision: pending.policy.revision, digest: r.digest });
    else await post(`/api/v1/patch-guards/${pending.guard.device_id}/apply`, { action: pending.action, revision: pending.guard.revision, until: pending.action === "defer" ? pending.until : 0, digest: r.digest });
    await client.invalidateQueries({ queryKey: ["patching"] });
  };
  const pendingTitle = !pending
    ? ""
    : pending.kind === "policy"
      ? `${{ pause: "Pause", resume: "Turn on", archive: "Archive" }[pending.action]} “${pending.policy.definition.name}”?`
      : pending.action === "acknowledge"
        ? `Allow patching again on ${pending.guard.hostname}?`
        : `Defer the restart on ${pending.guard.hostname} until ${absoluteTime(pending.until)}?`;

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Patching"
        subtitle="Weekly Windows Update windows for up to 25 devices per policy."
        actions={
          <>
            <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />
            <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => openWizard(null)}>
              New policy
            </Button>
          </>
        }
      />
      <div className="space-y-5">
        <Panel title="Needs attention" bodyClassName="p-0" actions={<span className="text-[12px] text-muted">{plural(attention.length, "device")}</span>}>
          {attention.length === 0 ? (
            <EmptyState icon={<CircleCheck />} title="No devices need attention">
              Holds, pending restarts and failed runs show up here.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {attention.map((a) => (
                <li key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                  <Link to={`/devices/${a.id}?tab=updates`} className="w-48 truncate font-medium text-fg hover:text-accent">
                    {a.hostname}
                  </Link>
                  <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                    {a.guard?.hold ? <Badge tone={holdText[a.guard.hold]?.tone ?? "warn"}>{holdText[a.guard.hold]?.label ?? a.guard.hold}</Badge> : null}
                    {a.guard?.reboot_since ? <Badge tone="warn">Restart pending since {relativeTime(a.guard.reboot_since, now)}</Badge> : null}
                    {a.guard && a.guard.defer_until * 1000 > now ? <Badge>Deferred until {absoluteTime(a.guard.defer_until)}</Badge> : null}
                    {a.run ? (
                      <span className="flex min-w-0 items-center gap-2 text-[12.5px] text-muted">
                        <OperationStatus status={a.run.status} />
                        <span className="truncate">{detailText[a.run.detail] ?? a.run.detail}</span>
                        <span className="text-faint">· {policyName.get(a.run.policy_id) ?? "policy"} · {relativeTime(a.run.scheduled_at, now)}</span>
                      </span>
                    ) : null}
                  </div>
                  {a.guard?.hold === "needs_review" ? (
                    <Button size="sm" onClick={() => setPending({ kind: "guard", guard: a.guard!, action: "acknowledge" })}>
                      Allow patching
                    </Button>
                  ) : null}
                  {a.guard?.reboot_since && a.guard.hold !== "restart_requested" ? (
                    <Button size="sm" variant="ghost" onClick={() => setDeferring(a.guard!)}>
                      Defer restart
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Policies"
          bodyClassName="p-0"
          actions={
            archived > 0 ? (
              <label className="flex items-center gap-1.5 text-[12px] text-muted">
                <input type="checkbox" className="size-3.5 accent-[var(--accent)]" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />
                Show {archived} archived
              </label>
            ) : null
          }
        >
          <DataTable
            columns={columns}
            rows={policies}
            rowKey={(p) => p.id}
            empty={
              <EmptyState icon={<ShieldCheck />} title="No patch policies yet">
                Create one to scan or install approved Windows updates in a weekly window.
              </EmptyState>
            }
          />
        </Panel>

        <Panel title="Recent runs" bodyClassName="p-0">
          {d!.runs.length === 0 ? (
            <EmptyState title="No runs yet" />
          ) : (
            <ul className="max-h-[420px] divide-y divide-border overflow-y-auto">
              {[...d!.runs]
                .sort((a, b) => b.scheduled_at - a.scheduled_at)
                .slice(0, 100)
                .map((r) => (
                  <li key={r.id} className="flex items-center gap-3 px-4 py-2">
                    <Link to={`/devices/${r.device_id}?tab=updates`} className="w-48 truncate text-fg hover:text-accent">
                      {hostnames.get(r.device_id) ?? r.device_id.slice(0, 8)}
                    </Link>
                    <span className="w-48 truncate text-[12.5px] text-muted">{policyName.get(r.policy_id) ?? "—"}</span>
                    <OperationStatus status={r.status} />
                    <span className="min-w-0 flex-1 truncate text-[12.5px] text-muted">{detailText[r.detail] ?? r.detail}</span>
                    <Tip label={absoluteTime(r.scheduled_at)}>
                      <span className="w-20 shrink-0 text-right text-[12px] text-muted tabular-nums">{relativeTime(r.scheduled_at, now)}</span>
                    </Tip>
                  </li>
                ))}
            </ul>
          )}
        </Panel>
      </div>

      {wizard.open ? <PolicyWizard key={wizard.key} open={wizard.open} onOpenChange={(o) => setWizard({ ...wizard, open: o })} existing={wizard.existing} /> : null}
      <DeferDialog
        key={deferring?.device_id ?? "none"}
        guard={deferring}
        onClose={() => setDeferring(null)}
        onReview={(until) => {
          const g = deferring!;
          setDeferring(null);
          setPending({ kind: "guard", guard: g, action: "defer", until });
        }}
      />
      <ReviewDialog<{ digest: string; targets?: { id: string; hostname: string }[] }>
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={pendingTitle}
        review={review}
        apply={apply}
        danger={pending?.kind === "policy" && pending.action === "archive"}
        confirmLabel={
          !pending ? "" : pending.kind === "policy" ? { pause: "Pause policy", resume: "Turn on", archive: "Archive policy" }[pending.action] : pending.action === "acknowledge" ? "Allow patching" : "Defer restart"
        }
        render={(r) =>
          pending?.kind === "policy" ? (
            <>
              <p>
                {pending.action === "pause"
                  ? "No new windows start until you turn it back on. Runs already in progress finish."
                  : pending.action === "resume"
                    ? `Windows start again from ${absoluteTime(pending.policy.next_at)}.`
                    : "Archived policies stop permanently and free their devices for other policies. This cannot be undone."}
              </p>
              {r.targets ? <TargetList targets={r.targets} /> : null}
            </>
          ) : pending?.action === "acknowledge" ? (
            <p>You have checked the device after the last uncertain or failed run. Its patch policy can install updates in the next window.</p>
          ) : (
            <p>No automatic restart is requested on this device before then. Installed updates stay pending until it restarts.</p>
          )
        }
      />
    </div>
  );
}

function MenuItem({ icon, children, onSelect, danger }: { icon: React.ReactNode; children: React.ReactNode; onSelect: () => void; danger?: boolean }) {
  return (
    <Menu.Item
      onSelect={onSelect}
      className={cx(
        "flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-[13px] outline-none [&>svg]:size-4",
        danger ? "text-danger data-[highlighted]:bg-danger-soft" : "text-fg data-[highlighted]:bg-surface-2",
      )}
    >
      {icon}
      {children}
    </Menu.Item>
  );
}
