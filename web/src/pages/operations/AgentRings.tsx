import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CirclePause, Play, Settings2 } from "lucide-react";
import { get, post } from "../../lib/api";
import { LIVE_INTERVAL, useNow } from "../../lib/hooks";
import { absoluteTime, plural } from "../../lib/format";
import type { AgentRingPolicy, DevicesResponse } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Panel, Spinner, cx } from "../../components/ui";

function RingEditor({ policy, groups, onClose }: { policy: AgentRingPolicy; groups: { id: string; name: string }[]; onClose: () => void }) {
  const client = useQueryClient();
  const [enabled, setEnabled] = useState(policy.enabled);
  const [pilot, setPilot] = useState<string[]>(policy.pilot_groups);
  const [delay, setDelay] = useState(policy.delay_hours);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await post("/api/v1/agent-rings", { enabled, pilot_groups: pilot, delay_hours: delay, resume: false, revision: policy.revision });
      await client.invalidateQueries({ queryKey: ["agent-rings"] });
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onOpenChange={(o) => !o && !busy && onClose()}
      title="Automatic agent updates"
      description="When a new release is the latest, pilot groups update right away; every other device follows after the delay. Any failed update pauses the rollout and raises an alert."
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} disabled={!(delay >= 1 && delay <= 720)} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <label className="flex items-center gap-2 text-[13px] text-fg">
          <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Update agents automatically
        </label>
        <Field label="Pilot groups" hint={groups.length ? "Up to 10. With no pilot group, the whole fleet waits for the delay after a release appears." : "Create groups in Groups & policies to choose pilots."}>
          <div className="flex flex-wrap gap-2">
            {groups.map((g) => (
              <button
                key={g.id}
                type="button"
                aria-pressed={pilot.includes(g.id)}
                onClick={() => setPilot(pilot.includes(g.id) ? pilot.filter((x) => x !== g.id) : pilot.length < 10 ? [...pilot, g.id] : pilot)}
                className={cx("rounded-md border px-2 py-0.5 text-[12.5px]", pilot.includes(g.id) ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}
              >
                {g.name}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Delay before the rest of the fleet (hours)" hint="1–720. Counted from when the pilot devices have finished updating.">
          <Input type="number" min={1} max={720} value={delay} onChange={(e) => setDelay(Number(e.target.value))} className="w-32" />
        </Field>
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

/** Automatic rollout settings and state (pilot rings, delay, pause). */
export function AgentRings() {
  const client = useQueryClient();
  const now = useNow();
  const q = useQuery({ queryKey: ["agent-rings"], queryFn: ({ signal }) => get<AgentRingPolicy>("/api/v1/agent-rings", signal), refetchInterval: LIVE_INTERVAL });
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const [editing, setEditing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (q.isPending) return <Panel title="Automatic updates"><Spinner label="Loading settings" /></Panel>;
  if (q.isError && !q.data) return <Panel title="Automatic updates"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></Panel>;
  const p = q.data!;
  const groups = devices.data?.groups ?? [];
  const names = p.pilot_groups.map((id) => groups.find((g) => g.id === id)?.name ?? id);
  const resume = async () => {
    setResuming(true);
    setError(null);
    try {
      await post("/api/v1/agent-rings", { enabled: p.enabled, pilot_groups: p.pilot_groups, delay_hours: p.delay_hours, resume: true, revision: p.revision });
      await Promise.all([client.invalidateQueries({ queryKey: ["agent-rings"] }), client.invalidateQueries({ queryKey: ["alerts"] }), client.invalidateQueries({ queryKey: ["dashboard"] })]);
    } catch (e) {
      setError(e);
    } finally {
      setResuming(false);
    }
  };
  const fleetAt = p.pilot_done_at ? p.pilot_done_at + p.delay_hours * 3600 : null;
  return (
    <Panel
      title="Automatic updates"
      actions={
        <Button size="sm" icon={<Settings2 className="size-3.5" />} onClick={() => setEditing(true)}>
          Settings
        </Button>
      }
    >
      {p.paused ? (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-warn bg-warn-soft px-3 py-2 text-[13px]">
          <CirclePause className="size-4 text-warn" />
          <span className="min-w-0 flex-1 text-fg">Paused: {p.pause_reason}</span>
          <Button size="sm" icon={<Play className="size-3.5" />} loading={resuming} onClick={() => void resume()}>
            Resume
          </Button>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px]">
        <span className="flex items-center gap-2">
          <Badge tone={p.enabled ? (p.paused ? "warn" : "ok") : "neutral"} dot>
            {p.enabled ? (p.paused ? "Paused" : "On") : "Off"}
          </Badge>
        </span>
        <span className="text-muted">
          Pilot: <span className="text-fg">{names.length ? names.join(", ") : "none"}</span>
        </span>
        <span className="text-muted">
          Rest of fleet after <span className="text-fg">{plural(p.delay_hours, "hour")}</span>
        </span>
        {p.enabled && !p.paused && fleetAt ? <span className="text-muted">{fleetAt * 1000 > now ? `Fleet updates from ${absoluteTime(fleetAt)}` : "Fleet updating"}</span> : null}
      </div>
      {!p.enabled ? <p className="mt-2 text-[12.5px] text-faint">Off: releases are only rolled out when you click Update.</p> : null}
      {error ? <ErrorNotice error={error} /> : null}
      {editing ? <RingEditor policy={p} groups={groups} onClose={() => setEditing(false)} /> : null}
    </Panel>
  );
}
