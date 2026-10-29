import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CloudDownload, RefreshCw } from "lucide-react";
import { get, post, put } from "../../lib/api";
import { useNow } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import { PageHeader } from "../../app/AppShell";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, Spinner, type Tone } from "../../components/ui";

type ServerUpdate = {
  id: string;
  version: string;
  sequence: number;
  from_version: string;
  requested_by: string;
  requested_at: number;
  phase: string;
  detail: string;
  backup: string;
  finished_at: number | null;
};

type UpdateState = {
  current: { version: string; sequence: number };
  check_enabled: boolean;
  checked_at: number | null;
  check_error: string;
  repository_configured: boolean;
  available: { version: string; sequence: number; notes: string; issued: number; image: string } | null;
  updater: { phase: string; version: string; detail: string; updated_at: number; build: string } | null;
  history: ServerUpdate[];
};

const phases: Record<string, { label: string; tone: Tone }> = {
  requested: { label: "Waiting for the updater", tone: "info" },
  accepted: { label: "Verifying", tone: "info" },
  pulling: { label: "Downloading", tone: "info" },
  backing_up: { label: "Backing up", tone: "info" },
  starting: { label: "Starting new version", tone: "info" },
  succeeded: { label: "Updated", tone: "ok" },
  rolled_back: { label: "Rolled back", tone: "warn" },
  failed: { label: "Failed", tone: "danger" },
};

const running = (phase: string) => !["succeeded", "rolled_back", "failed", "idle"].includes(phase);

/**
 * Server updates: the daily release check, the newest signed
 * release, and the Update button. The updater sidecar takes a verified
 * backup of the database and secrets, swaps the image and rolls back if the
 * new version does not become healthy. The server restarts during an
 * update, so this page reconnects on its own.
 */
export function ServerUpdatesPage() {
  const client = useQueryClient();
  const now = useNow(5000);
  const [confirm, setConfirm] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<unknown>(null);
  const q = useQuery({
    queryKey: ["server-update"],
    queryFn: ({ signal }) => get<UpdateState>("/api/v1/server/update", signal),
    // Poll while an update runs; the request fails while the server restarts.
    refetchInterval: (query) => {
      const d = query.state.data;
      const active = d?.history.some((h) => h.finished_at === null) || (d?.updater && running(d.updater.phase));
      return active || query.state.status === "error" ? 3000 : 60_000;
    },
    retry: false,
  });
  if (q.isPending) return <div className="p-8"><Spinner label="Loading server updates" /></div>;
  if (q.isError && !q.data) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const d = q.data!;
  const open = d.history.find((h) => h.finished_at === null);
  const refresh = () => client.invalidateQueries({ queryKey: ["server-update"] });

  const checkNow = async () => {
    setChecking(true);
    setCheckError(null);
    try {
      await post("/api/v1/server/update/check");
      await refresh();
    } catch (e) {
      setCheckError(e);
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1100px] px-6 py-6">
      <PageHeader title="Server updates" subtitle="Signed server releases installed with a verified backup and an automatic rollback." />
      <div className="space-y-5">
        {q.isError ? (
          <p className="rounded-md border border-border bg-surface px-3 py-2 text-[13px] text-muted" role="status">
            The server is not answering — it may be restarting for an update. This page reconnects automatically.
          </p>
        ) : null}
        <Panel title="This server">
          <dl className="grid gap-x-8 gap-y-2 text-[13px] sm:grid-cols-[160px_1fr]">
            <dt className="text-muted">Version</dt>
            <dd className="text-fg">
              <Mono>{d.current.version}</Mono>
              {d.current.sequence > 0 ? <span className="ml-2 text-faint">release {d.current.sequence}</span> : null}
            </dd>
            <dt className="text-muted">Updater</dt>
            <dd className="text-fg">
              {d.updater ? (
                <>
                  <span>
                    Installed{d.updater.build ? <> · <Mono>{d.updater.build}</Mono></> : null}
                    {d.updater.updated_at ? <span className="text-faint"> · last report {relativeTime(d.updater.updated_at, now)}</span> : null}
                  </span>
                  {!d.updater.build ? (
                    <p className="mt-1 text-muted">This updater is from a release that cannot update itself. Run the install command once to replace it; later updaters follow the server on their own.</p>
                  ) : d.updater.build !== d.current.version && !running(d.updater.phase) ? (
                    <p className="mt-1 text-muted">The updater still runs an older version. It replaces itself within a few minutes of an update; if this stays, run the install command once.</p>
                  ) : null}
                </>
              ) : (
                <span className="text-muted">Not installed — run the install command again to add it, or update with the install command.</span>
              )}
            </dd>
          </dl>
        </Panel>

        <Panel
          title="Release check"
          actions={
            <Button size="sm" icon={<RefreshCw className="size-3.5" />} loading={checking} disabled={!d.repository_configured} onClick={() => void checkNow()}>
              Check now
            </Button>
          }
        >
          <div className="space-y-3 text-[13px]">
            <label className="flex items-center gap-2 text-fg">
              <input
                type="checkbox"
                className="size-4 accent-[var(--accent)]"
                checked={d.check_enabled}
                onChange={(e) => void put("/api/v1/server/update/settings", { check_enabled: e.target.checked }).then(refresh)}
              />
              Check for new releases once a day
            </label>
            <p className="text-muted">The check asks GitHub for the latest release. It sends no device, user or server data.</p>
            {!d.repository_configured ? (
              <p className="text-muted">This build has no release repository yet, so it does not check.</p>
            ) : (
              <p className="text-muted">
                {d.checked_at ? <>Last checked {relativeTime(d.checked_at, now)}.</> : "Not checked yet."}
                {d.check_error ? <span className="text-danger"> {d.check_error}</span> : null}
              </p>
            )}
            {checkError ? <ErrorNotice error={checkError} /> : null}
          </div>
        </Panel>

        <Panel title="Available update">
          {d.available ? (
            <div className="space-y-3 text-[13px]">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-[15px] font-semibold text-fg">{d.available.version}</span>
                <Badge tone="accent">release {d.available.sequence}</Badge>
                <span className="text-faint">published {absoluteTime(d.available.issued)}</span>
              </div>
              {d.available.notes ? <pre className="max-h-72 overflow-auto rounded-md bg-surface-2 p-3 font-sans text-[13px] whitespace-pre-wrap text-fg">{d.available.notes}</pre> : null}
              <p className="text-muted">
                Updating stops the server for a few minutes. The database and secrets are backed up and verified first; if the new version does not become healthy,
                the previous version and its data are restored. Agents update afterwards through their rings.
              </p>
              <Button variant="primary" icon={<CloudDownload className="size-3.5" />} disabled={!d.updater || !!open} onClick={() => setConfirm(true)}>
                Update to {d.available.version}
              </Button>
            </div>
          ) : (
            <EmptyState icon={<CloudDownload />} title="This server is up to date" />
          )}
        </Panel>

        <Panel title="History" bodyClassName="p-0">
          {d.history.length === 0 ? (
            <EmptyState title="No updates from the dashboard yet" />
          ) : (
            <ul className="divide-y divide-border">
              {d.history.map((h) => {
                const p = phases[h.phase] ?? { label: h.phase, tone: "neutral" as Tone };
                return (
                  <li key={h.id} className="flex flex-wrap items-start gap-x-4 gap-y-1 px-4 py-3 text-[13px]">
                    <Badge tone={p.tone} dot>
                      {p.label}
                    </Badge>
                    <span className="text-fg">
                      {h.from_version} → <span className="font-medium">{h.version}</span>
                    </span>
                    <span className="text-faint">
                      {h.requested_by} · {absoluteTime(h.requested_at)}
                    </span>
                    {h.detail ? <p className="basis-full text-muted">{h.detail}</p> : null}
                    {h.backup ? <p className="basis-full text-[12px] text-faint">Backup: <Mono>{h.backup}</Mono></p> : null}
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      </div>

      {d.available ? (
        <ConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title={`Update the server to ${d.available.version}?`}
          confirmLabel="Update now"
          onConfirm={async () => {
            await post("/api/v1/server/update/install", { sequence: d.available!.sequence });
            await refresh();
          }}
        >
          The dashboard and agent connections are unavailable for a few minutes while the server restarts. Running work on devices continues and reports back afterwards.
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
