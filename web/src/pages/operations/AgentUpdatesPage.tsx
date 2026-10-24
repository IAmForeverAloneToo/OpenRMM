import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Rocket, Upload } from "lucide-react";
import { ApiError, csrfHeader, get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { LIVE_INTERVAL, useNow } from "../../lib/hooks";
import { absoluteTime, bytes, plural, relativeTime, short } from "../../lib/format";
import type { AgentRelease, AgentRolloutReview, AgentUpgradeJob } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { PageHeader } from "../../app/AppShell";
import { Freshness } from "../../components/Freshness";
import { ConfirmDialog, Modal } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { TargetPicker, type Targets } from "../../components/TargetPicker";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Spinner, Tip } from "../../components/ui";
import { OperationStatus } from "../../components/status";
import { AgentFleet } from "./AgentFleet";
import { AgentRings } from "./AgentRings";

const MAX_BINARY = 32 * 1024 * 1024;

function UploadDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const client = useQueryClient();
  const [manifest, setManifest] = useState<File | null>(null);
  const [binary, setBinary] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const keyValid = /^[0-9a-f]{64}$/i.test(publicKey.trim());
  const ready = !!manifest && manifest.size <= 16384 && !!binary && binary.size <= MAX_BINARY && keyValid;
  const upload = async () => {
    if (!manifest || !binary) return;
    setBusy(true);
    setError(null);
    try {
      // Field order matters: the server verifies the signed manifest before
      // it accepts the package bytes.
      const form = new FormData();
      form.append("manifest", manifest);
      form.append("public", publicKey.trim().toLowerCase());
      form.append("binary", binary);
      const r = await fetch("/api/v1/agent-releases", { method: "POST", body: form, headers: csrfHeader(), credentials: "same-origin" });
      if (!r.ok) {
        const body = (await r.json().catch(() => ({}))) as { error?: string; code?: string };
        throw new ApiError(body.error ?? "Upload failed.", r.status, body.code ?? "error");
      }
      await client.invalidateQueries({ queryKey: ["agent-releases"] });
      onOpenChange(false);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title="Upload an agent release"
      description="Signed outside the server with openrmm-release. Uploading does not install it anywhere."
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" icon={<Upload className="size-4" />} loading={busy} disabled={!ready} onClick={() => void upload()}>
            Upload and verify
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Signed release file (.json)">
          <input type="file" accept=".json,application/json" onChange={(e) => setManifest(e.target.files?.[0] ?? null)} className="block w-full text-[13px] text-muted file:mr-3 file:rounded-md file:border file:border-border file:bg-surface-2 file:px-2.5 file:py-1 file:text-fg" />
        </Field>
        <Field label="Publisher public key" hint="64 hexadecimal characters">
          <Input value={publicKey} onChange={(e) => setPublicKey(e.target.value)} spellCheck={false} className={`font-mono text-[12px] ${publicKey && !keyValid ? "border-danger" : ""}`} />
        </Field>
        <Field label="Agent package (.msi)" hint={binary ? `${bytes(binary.size)}${binary.size > MAX_BINARY ? " — over the 32 MiB limit" : ""}` : "Up to 32 MiB"}>
          <input type="file" accept=".msi,.exe" onChange={(e) => setBinary(e.target.files?.[0] ?? null)} className="block w-full text-[13px] text-muted file:mr-3 file:rounded-md file:border file:border-border file:bg-surface-2 file:px-2.5 file:py-1 file:text-fg" />
        </Field>
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

function RolloutDialog({ release, onClose }: { release: AgentRelease; onClose: () => void }) {
  const client = useQueryClient();
  const [targets, setTargets] = useState<Targets>({ devices: [], groups: [] });
  const [id] = useState(newOperationID);
  const [review, setReview] = useState<AgentRolloutReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const change = { id, release_id: release.id, devices: targets.devices, groups: targets.groups };
  const step = async (op: "review" | "apply") => {
    setBusy(true);
    setError(null);
    try {
      const r = await post<AgentRolloutReview>(`/api/v1/agent-rollouts/${op}`, { change, digest: op === "apply" ? review!.digest : "" });
      if (op === "review") setReview(r);
      else {
        await client.invalidateQueries({ queryKey: ["agent-upgrades"] });
        onClose();
      }
    } catch (e) {
      setError(e);
      setReview(null);
    } finally {
      setBusy(false);
    }
  };
  const m = release.release.manifest;
  return (
    <Modal
      open
      onOpenChange={(o) => !o && !busy && onClose()}
      title={review ? `Update ${plural(review.targets.length, "device")} to agent ${m.version}?` : `Roll out agent ${m.version}`}
      width="max-w-2xl"
      footer={
        <>
          {review ? (
            <Button variant="ghost" disabled={busy} onClick={() => setReview(null)}>
              Back
            </Button>
          ) : null}
          <div className="flex-1" />
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          {review ? (
            <Button variant="primary" loading={busy} onClick={() => void step("apply")}>
              Update {plural(review.targets.length, "device")}
            </Button>
          ) : (
            <Button variant="primary" loading={busy} disabled={targets.devices.length + targets.groups.length === 0} onClick={() => void step("review")}>
              Review
            </Button>
          )}
        </>
      }
    >
      {review ? (
        <div className="space-y-3 text-[13px]">
          <ul className="max-h-64 divide-y divide-border overflow-y-auto rounded-md border border-border">
            {review.targets.map((t) => (
              <li key={t.id} className="flex items-center gap-3 px-3 py-1.5">
                <span className="flex-1 truncate text-fg">{t.hostname}</span>
                <Tip label={`Current agent ${t.current_sha256}`}>
                  <Mono className="text-[11.5px] text-faint">{short(t.current_sha256)}</Mono>
                </Tip>
                <span className="text-[12px] text-muted">
                  sequence {t.high_water} → {m.sequence}
                </span>
              </li>
            ))}
          </ul>
          <p className="text-muted">Each device's agent verifies the signature again, installs the package with Windows Installer and reinstalls its previous package if the new agent does not come back healthy. A dispatched update cannot be cancelled. Start with one canary device.</p>
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      ) : (
        <div className="space-y-3">
          <TargetPicker value={targets} onChange={setTargets} include={(d) => d.os === "windows"} height="max-h-64" />
          <p className="text-[12px] text-faint">Targets need an agent that trusts this release's signing key and installs MSI packages.</p>
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      )}
    </Modal>
  );
}

function Releases({ releases }: { releases: AgentRelease[] }) {
  const client = useQueryClient();
  const now = useNow();
  const [uploading, setUploading] = useState(false);
  const [rollout, setRollout] = useState<AgentRelease | null>(null);
  const [withdraw, setWithdraw] = useState<AgentRelease | null>(null);
  const rows = releases.filter((r) => !r.withdrawn);
  const columns: Column<AgentRelease>[] = [
    { key: "version", header: "Version", sort: (r) => r.release.manifest.sequence, cell: (r) => <span className="font-medium text-fg">{r.release.manifest.version}</span> },
    { key: "seq", header: "Sequence", sort: (r) => r.release.manifest.sequence, cell: (r) => <span className="tabular-nums text-muted">{r.release.manifest.sequence}</span> },
    { key: "size", header: "Size", cell: (r) => <span className="text-muted">{bytes(r.release.manifest.size)}</span> },
    {
      key: "hash",
      header: "SHA-256",
      cell: (r) => (
        <Tip label={r.release.manifest.sha256}>
          <Mono className="text-[11.5px] text-faint">{short(r.release.manifest.sha256)}</Mono>
        </Tip>
      ),
    },
    {
      key: "key",
      header: "Signing key",
      cell: (r) => (
        <Tip label={r.public_key}>
          <Mono className="text-[11.5px] text-faint">{short(r.release.manifest.key_id)}</Mono>
        </Tip>
      ),
    },
    {
      key: "expires",
      header: "Valid until",
      sort: (r) => r.release.manifest.expires_at,
      cell: (r) => (r.release.manifest.expires_at * 1000 < now ? <Badge tone="warn">Expired</Badge> : <span className="text-muted">{absoluteTime(r.release.manifest.expires_at)}</span>),
    },
    {
      key: "actions",
      header: "",
      className: "w-px text-right whitespace-nowrap",
      cell: (r) => (
        <span className="flex justify-end gap-1.5">
          <Button size="sm" icon={<Rocket className="size-3.5" />} disabled={r.release.manifest.expires_at * 1000 < now} onClick={() => setRollout(r)}>
            Roll out
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setWithdraw(r)}>
            Withdraw
          </Button>
        </span>
      ),
    },
  ];
  return (
    <Panel
      title="Releases"
      bodyClassName="p-0"
      actions={
        <Button size="sm" variant="primary" icon={<Upload className="size-3.5" />} onClick={() => setUploading(true)}>
          Upload release
        </Button>
      }
    >
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        initialSort={{ key: "seq", dir: "desc" }}
        empty={
          <EmptyState icon={<Rocket />} title="No releases">
            Upload an agent build signed with your publisher key. Up to eight releases are kept.
          </EmptyState>
        }
      />
      {uploading ? <UploadDialog open onOpenChange={setUploading} /> : null}
      {rollout ? <RolloutDialog release={rollout} onClose={() => setRollout(null)} /> : null}
      <ConfirmDialog
        open={withdraw !== null}
        onOpenChange={(o) => !o && setWithdraw(null)}
        title={`Withdraw agent ${withdraw?.release.manifest.version ?? ""}?`}
        confirmLabel="Withdraw release"
        danger
        onConfirm={async () => {
          await post(`/api/v1/agent-releases/${withdraw!.id}/withdraw`);
          await client.invalidateQueries({ queryKey: ["agent-releases"] });
        }}
      >
        <p>Queued updates using it are cancelled, it can no longer be rolled out, and its stored package is deleted. Devices already updated keep it.</p>
      </ConfirmDialog>
    </Panel>
  );
}

function Jobs({ versions }: { versions: Map<string, string> }) {
  const account = useAccount();
  const client = useQueryClient();
  const now = useNow();
  const q = useQuery({
    queryKey: ["agent-upgrades"],
    queryFn: ({ signal }) => get<{ jobs: AgentUpgradeJob[] }>("/api/v1/agent-upgrades", signal),
    refetchInterval: (query) => ((query.state.data?.jobs ?? []).some((j) => j.status === "queued" || j.status === "dispatched") ? 3000 : LIVE_INTERVAL),
  });
  const [cancel, setCancel] = useState<AgentUpgradeJob | null>(null);
  const columns: Column<AgentUpgradeJob>[] = [
    {
      key: "device",
      header: "Device",
      sort: (j) => j.hostname,
      cell: (j) => (
        <Link to={`/devices/${j.device_id}`} className="text-fg hover:text-accent">
          {j.hostname}
        </Link>
      ),
    },
    { key: "version", header: "Release", cell: (j) => <span className="text-muted">{versions.get(j.release_id) ?? short(j.release_id)}</span> },
    { key: "status", header: "Status", sort: (j) => j.status, cell: (j) => <OperationStatus status={j.status} /> },
    { key: "actor", header: "By", cell: (j) => <span className="text-muted">{j.actor}</span> },
    {
      key: "when",
      header: "Queued",
      sort: (j) => j.created_at,
      cell: (j) => (
        <Tip label={absoluteTime(j.created_at)}>
          <span className="text-muted tabular-nums">{relativeTime(j.created_at, now)}</span>
        </Tip>
      ),
    },
    { key: "finished", header: "Finished", sort: (j) => j.finished_at ?? 0, cell: (j) => <span className="text-muted">{j.finished_at ? absoluteTime(j.finished_at) : "—"}</span> },
    {
      key: "cancel",
      header: "",
      className: "w-px text-right",
      cell: (j) =>
        account.permissions.owner && j.status === "queued" ? (
          <Button size="sm" variant="ghost" onClick={() => setCancel(j)}>
            Cancel
          </Button>
        ) : null,
    },
  ];
  return (
    <Panel title="Update history" bodyClassName="p-0" actions={<Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />}>
      {q.isPending ? (
        <div className="p-4">
          <Spinner label="Loading updates" />
        </div>
      ) : q.isError && !q.data ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : (
        <DataTable columns={columns} rows={q.data!.jobs} rowKey={(j) => j.id} initialSort={{ key: "when", dir: "desc" }} empty={<EmptyState title="No agent updates yet" />} />
      )}
      <ConfirmDialog
        open={cancel !== null}
        onOpenChange={(o) => !o && setCancel(null)}
        title={`Cancel the update on ${cancel?.hostname ?? ""}?`}
        confirmLabel="Cancel update"
        danger
        onConfirm={async () => {
          await post(`/api/v1/agent-upgrades/${cancel!.id}/cancel`);
          await client.invalidateQueries({ queryKey: ["agent-upgrades"] });
        }}
      >
        <p>Only updates the device has not picked up yet can be cancelled.</p>
      </ConfirmDialog>
    </Panel>
  );
}

export function AgentUpdatesPage() {
  const account = useAccount();
  const owner = account.permissions.owner;
  const releases = useQuery({ queryKey: ["agent-releases"], queryFn: ({ signal }) => get<{ releases: AgentRelease[]; bundled: { version: string; sequence: number; in_library: boolean } | null }>("/api/v1/agent-releases", signal), enabled: owner });
  const versions = useMemo(() => new Map((releases.data?.releases ?? []).map((r) => [r.id, r.release.manifest.version])), [releases.data]);
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Agent updates" subtitle="Signed Windows agent packages, rolled out to devices whose agent trusts the signing key." />
      <div className="space-y-5">
        {owner ? (
          releases.isPending ? (
            <Spinner label="Loading releases" />
          ) : releases.isError ? (
            <ErrorNotice error={releases.error} retry={() => void releases.refetch()} />
          ) : (
            <>
              {releases.data.bundled && !releases.data.bundled.in_library ? (
                <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-[13px] text-fg" role="alert">
                  The agent release built with this server ({releases.data.bundled.version}, release {releases.data.bundled.sequence}) is not in the library, so
                  devices are not offered it. The library holds at most eight active releases: withdraw unused ones below, then restart the server.
                </p>
              ) : null}
              <AgentRings />
              <AgentFleet />
              <Releases releases={releases.data.releases} />
            </>
          )
        ) : null}
        <Jobs versions={versions} />
      </div>
    </div>
  );
}
