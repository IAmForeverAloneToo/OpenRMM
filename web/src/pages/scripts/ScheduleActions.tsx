import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Pause, Play } from "lucide-react";
import { post } from "../../lib/api";
import type { ScriptSchedule } from "../../lib/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, type Tone } from "../../components/ui";

const states: Record<string, { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "ok" },
  paused: { label: "Paused", tone: "warn" },
  cancelled: { label: "Cancelled", tone: "neutral" },
  completed: { label: "Completed", tone: "neutral" },
};

export function ScheduleState({ state }: { state: string }) {
  const s = states[state] ?? { label: state, tone: "neutral" as Tone };
  return (
    <Badge tone={s.tone} dot>
      {s.label}
    </Badge>
  );
}

/** Pause and resume take effect immediately; cancelling asks first. */
export function ScheduleActions({ schedule, onEdit }: { schedule: ScriptSchedule; onEdit?: () => void }) {
  const client = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [cancelOpen, setCancelOpen] = useState(false);
  const change = async (action: "pause" | "resume" | "cancel") => {
    setBusy(true);
    setError(null);
    try {
      await post(`/api/v1/devices/${schedule.device_id}/script-schedules/${schedule.id}/state`, { action, revision: schedule.revision });
      await Promise.all([client.invalidateQueries({ queryKey: ["script-schedules"] }), client.invalidateQueries({ queryKey: ["device-scripts", schedule.device_id] })]);
    } catch (e) {
      setError(e);
      throw e;
    } finally {
      setBusy(false);
    }
  };
  if (schedule.state !== "active" && schedule.state !== "paused") return null;
  return (
    <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
      {schedule.state === "active" ? (
        <Button size="sm" variant="ghost" icon={<Pause className="size-3.5" />} loading={busy} onClick={() => void change("pause").catch(() => undefined)}>
          Pause
        </Button>
      ) : (
        <Button size="sm" variant="ghost" icon={<Play className="size-3.5" />} loading={busy} onClick={() => void change("resume").catch(() => undefined)}>
          Resume
        </Button>
      )}
      {onEdit ? (
        <Button size="sm" variant="ghost" onClick={onEdit}>
          Edit
        </Button>
      ) : null}
      <Button size="sm" variant="ghost" onClick={() => setCancelOpen(true)}>
        Cancel
      </Button>
      {error ? <span className="text-[12px] text-danger">Changed elsewhere — refresh</span> : null}
      <ConfirmDialog open={cancelOpen} onOpenChange={setCancelOpen} title={`Cancel “${schedule.name}”?`} confirmLabel="Cancel schedule" danger onConfirm={() => change("cancel")}>
        <p>No further runs will start. Runs already sent to the device are not affected. A cancelled schedule can't be resumed.</p>
      </ConfirmDialog>
    </div>
  );
}
