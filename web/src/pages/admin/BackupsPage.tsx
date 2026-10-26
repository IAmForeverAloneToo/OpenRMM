import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { DatabaseBackup } from "lucide-react";
import { get, post, put } from "../../lib/api";
import { useNow } from "../../lib/hooks";
import { bytes, relativeTime, utcTime } from "../../lib/format";
import { PageHeader } from "../../app/AppShell";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, Select, Spinner, type Tone } from "../../components/ui";

type BackupRun = { id?: string; kind: string; name?: string; started_at: number; finished_at?: number; ok: boolean; detail?: string };
type BackupInfo = { name: string; kind: string; created_at: number; live: boolean; size: number; schema_version?: number };
type BackupState = {
  updater: boolean;
  settings: { enabled: boolean; hour: number; updated_at: number | null; revision: number };
  report: { updated_at: number; next_at?: number; running?: BackupRun; last?: BackupRun; backups: BackupInfo[] } | null;
};

const kinds: Record<string, { label: string; tone: Tone }> = {
  nightly: { label: "Nightly", tone: "info" },
  manual: { label: "On request", tone: "accent" },
  update: { label: "Before update", tone: "neutral" },
  "pre-restore": { label: "Before restore", tone: "warn" },
};

const hours = Array.from({ length: 24 }, (_, h) => h);

/**
 * Server backups: the updater sidecar copies the database (live, without
 * stopping the server) and the secrets every night and on request, verifies
 * each copy and keeps the newest of each kind. Restores stop the server and
 * are done with the install command.
 */
export function BackupsPage() {
  const client = useQueryClient();
  const now = useNow(10_000);
  const q = useQuery({
    queryKey: ["server-backups"],
    queryFn: ({ signal }) => get<BackupState>("/api/v1/server/backups", signal),
    refetchInterval: (query) => (query.state.data?.report?.running ? 3000 : 30_000),
  });
  const [draft, setDraft] = useState<{ enabled: boolean; hour: number } | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "run">("");
  const [error, setError] = useState<unknown>(null);
  const [requested, setRequested] = useState(false);
  useEffect(() => {
    if (q.data) setDraft({ enabled: q.data.settings.enabled, hour: q.data.settings.hour });
  }, [q.data?.settings.revision]);
  if (q.isPending || (q.data && !draft)) return <div className="p-8"><Spinner label="Loading backups" /></div>;
  if (q.isError) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const d = q.data;
  const s = draft!;
  const changed = s.enabled !== d.settings.enabled || s.hour !== d.settings.hour;
  const report = d.report;
  const run = async (kind: "save" | "run", action: () => Promise<void>) => {
    setBusy(kind);
    setError(null);
    try {
      await action();
      await client.invalidateQueries({ queryKey: ["server-backups"] });
    } catch (e) {
      setError(e);
    } finally {
      setBusy("");
    }
  };
  const save = () => run("save", async () => void (await put("/api/v1/server/backups/settings", { ...s, revision: d.settings.revision })));
  const backupNow = () =>
    run("run", async () => {
      await post("/api/v1/server/backups/run");
      setRequested(true);
    });
  const last = report?.last;
  const waiting = requested && !report?.running && (!last || last.kind !== "manual" || last.started_at * 1000 < now - 60_000);

  return (
    <div className="mx-auto max-w-[1100px] px-6 py-6">
      <PageHeader title="Backups" subtitle="Verified copies of the database and secrets, taken nightly without stopping the server." />
      <div className="space-y-5">
        {!d.updater ? (
          <p className="rounded-md border border-border bg-surface px-3 py-2 text-[13px] text-muted" role="status">
            Backups are taken by the updater, which is not running on this installation. Run the install command again to add it; until then, back up the Docker volumes yourself (see the recovery guide).
          </p>
        ) : null}
        <Panel
          title="Schedule"
          actions={
            <Button size="sm" icon={<DatabaseBackup className="size-3.5" />} loading={busy === "run"} disabled={!d.updater || busy !== "" || !!report?.running} onClick={() => void backupNow()}>
              Back up now
            </Button>
          }
        >
          <div className="space-y-3 text-[13px]">
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-fg">
                <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={s.enabled} onChange={(e) => setDraft({ ...s, enabled: e.target.checked })} />
                Back up every night at
              </label>
              <Select value={String(s.hour)} disabled={!s.enabled} onChange={(e) => setDraft({ ...s, hour: Number(e.target.value) })} aria-label="Backup hour (UTC)">
                {hours.map((h) => (
                  <option key={h} value={h}>
                    {String(h).padStart(2, "0")}:00 UTC
                  </option>
                ))}
              </Select>
              {changed ? (
                <>
                  <Button size="sm" variant="primary" loading={busy === "save"} disabled={busy !== ""} onClick={() => void save()}>
                    Save
                  </Button>
                  <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => setDraft({ enabled: d.settings.enabled, hour: d.settings.hour })}>
                    Reset
                  </Button>
                </>
              ) : null}
            </div>
            <p className="text-muted">
              The newest 7 nightly backups are kept, plus up to 5 taken on request and 3 from before each update or restore. They stay on this machine in the
              <Mono> backups</Mono> volume; copy them elsewhere with <Mono>install.sh backup</Mono>, which also exports case evidence with <Mono>--evidence</Mono>.
            </p>
            {report ? (
              <p className="text-muted">
                {report.running ? (
                  <span className="text-fg">A backup is running…</span>
                ) : waiting ? (
                  <span className="text-fg">Backup requested; the updater starts it within a few seconds.</span>
                ) : last ? (
                  <span className={last.ok ? "" : "text-danger"}>
                    Last backup {relativeTime(last.finished_at ?? last.started_at, now)}: {last.ok ? "verified" : last.detail || "failed"}.
                  </span>
                ) : (
                  "No backup has been taken yet."
                )}
                {report.next_at && !report.running ? <span> Next nightly backup {relativeTime(report.next_at, now)}.</span> : null}
              </p>
            ) : null}
            {error ? <ErrorNotice error={error} /> : null}
          </div>
        </Panel>

        <Panel title="Backups on this server" bodyClassName="p-0">
          {!report || report.backups.length === 0 ? (
            <EmptyState icon={<DatabaseBackup />} title="No backups yet" />
          ) : (
            <table className="w-full text-[13px]">
              <thead className="text-left text-[12px] text-muted">
                <tr className="border-b border-border">
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="px-4 py-2 font-medium">Kind</th>
                  <th className="px-4 py-2 font-medium">Taken</th>
                  <th className="px-4 py-2 text-right font-medium">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {report.backups.map((b) => {
                  const k = kinds[b.kind] ?? { label: b.kind, tone: "neutral" as Tone };
                  return (
                    <tr key={b.name}>
                      <td className="px-4 py-2">
                        <Mono>{b.name}</Mono>
                      </td>
                      <td className="px-4 py-2">
                        <Badge tone={k.tone}>{k.label}</Badge>
                      </td>
                      <td className="px-4 py-2 text-muted">{utcTime(b.created_at)}</td>
                      <td className="px-4 py-2 text-right text-muted">{bytes(b.size)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Restoring">
          <div className="space-y-2 text-[13px] text-muted">
            <p>
              A restore stops the server, so it is done on the server machine: <Mono>sudo bash install.sh restore NAME</Mono> (or the path of an exported
              <Mono> .tar.gz</Mono>). The current state is kept as a backup first, devices revoked since the backup stay revoked, and queued work, sessions and
              one-time codes from the backup are not brought back.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
