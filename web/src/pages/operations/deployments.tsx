import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { PackageCheck } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { LIVE_INTERVAL, useNow } from "../../lib/hooks";
import { absoluteTime, plural, relativeTime, short } from "../../lib/format";
import { versionCompare } from "../../lib/parse";
import type { AppCatalog, AppOperation, AppVersion, Deployment, DeploymentChange, DeploymentReview } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { Modal, ConfirmDialog } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { TargetPicker, type Targets } from "../../components/TargetPicker";
import { Badge, Button, EmptyState, ErrorNotice, Field, Mono, Segmented, Select, Spinner, Tip } from "../../components/ui";
import { OperationStatus } from "../../components/status";
import { TargetList } from "./shared";

export const operationLabels: Record<AppOperation, string> = { install: "Install", update: "Update", uninstall: "Uninstall", verify: "Verify" };
const operationHelp: Record<AppOperation, string> = {
  install: "Download, check the SHA-256 and install this MSI.",
  update: "Upgrade devices that have an older version of this application.",
  uninstall: "Remove this exact package (by its product code).",
  verify: "Only check whether this version is installed. Nothing changes.",
};
const reasonText: Record<string, string> = {
  execution_uncertain: "Result could not be confirmed",
  not_executed: "Never ran",
  verified: "",
  precondition: "Device was not in the expected state",
  download: "Download failed",
  checksum: "Downloaded file did not match the SHA-256",
  package_identity: "MSI product code or version did not match",
  installer: "Installer failed",
  verification: "Post-install check failed",
  observation: "Installed products could not be read",
  denied: "Refused on the device",
  unsupported: "Not supported on the device",
  interrupted: "Interrupted",
};

export function useCatalog(enabled = true) {
  return useQuery({ queryKey: ["applications"], queryFn: ({ signal }) => get<AppCatalog>("/api/v1/applications", signal), enabled });
}

/**
 * Deploy an application version. From the catalog the targets are chosen
 * here; from the device console the device is fixed.
 */
export function DeployDialog({ open, onOpenChange, device, versionId, onDone }: { open: boolean; onOpenChange: (o: boolean) => void; device?: { id: string; hostname: string }; versionId?: string; onDone?: () => void }) {
  const client = useQueryClient();
  const catalog = useCatalog(open);
  const versions = catalog.data?.versions ?? [];
  const [selected, setSelected] = useState(versionId ?? "");
  const [operation, setOperation] = useState<AppOperation>("install");
  const [previous, setPrevious] = useState("");
  const [targets, setTargets] = useState<Targets>({ devices: device ? [device.id] : [], groups: [] });
  const [review, setReview] = useState<{ change: DeploymentChange; result: DeploymentReview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const version = versions.find((v) => v.id === selected);
  const older = useMemo(() => (version ? versions.filter((v) => v.application_id === version.application_id && versionCompare(v.definition.version, version.definition.version) < 0) : []), [versions, version]);
  const apps = useMemo(() => {
    const m = new Map<string, AppVersion[]>();
    for (const v of versions) m.set(v.application_id, [...(m.get(v.application_id) ?? []), v]);
    return [...m.values()].map((list) => list.sort((a, b) => versionCompare(b.definition.version, a.definition.version))).sort((a, b) => a[0]!.definition.name.localeCompare(b[0]!.definition.name));
  }, [versions]);
  const count = targets.devices.length + targets.groups.length;
  const ready = !!version && count > 0 && (operation !== "update" || !!previous);

  const doReview = async () => {
    if (!version) return;
    setBusy(true);
    setError(null);
    const change: DeploymentChange = { id: newOperationID(), version_id: version.id, previous_version_id: operation === "update" ? previous : "", operation, devices: targets.devices, groups: targets.groups };
    try {
      setReview({ change, result: await post<DeploymentReview>("/api/v1/deployments/review", { change, digest: "" }) });
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
      await post("/api/v1/deployments/apply", { change: review.change, digest: review.result.digest });
      await client.invalidateQueries({ queryKey: ["deployments"] });
      onOpenChange(false);
      onDone?.();
    } catch (e) {
      setError(e);
      setReview(null);
    } finally {
      setBusy(false);
    }
  };

  const r = review?.result;
  return (
    <Modal
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title={r ? `${operationLabels[review!.change.operation]} ${r.version.definition.name} ${r.version.definition.version} on ${plural(r.targets.length, "device")}?` : device ? `Install an app on ${device.hostname}` : "Deploy an application"}
      width="max-w-2xl"
      footer={
        <>
          {r ? (
            <Button variant="ghost" disabled={busy} onClick={() => setReview(null)}>
              Back
            </Button>
          ) : null}
          <div className="flex-1" />
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {r ? (
            <Button variant="primary" loading={busy} onClick={() => void apply()}>
              {operationLabels[review!.change.operation]} on {plural(r.targets.length, "device")}
            </Button>
          ) : (
            <Button variant="primary" loading={busy} disabled={!ready} onClick={() => void doReview()}>
              Review
            </Button>
          )}
        </>
      }
    >
      {catalog.isPending ? (
        <Spinner label="Loading catalog" />
      ) : versions.length === 0 ? (
        <EmptyState icon={<PackageCheck />} title="The catalog is empty">
          <Link to="/deployments?view=catalog" className="text-accent hover:underline" onClick={() => onOpenChange(false)}>
            Add an application first
          </Link>
        </EmptyState>
      ) : r ? (
        <div className="space-y-3 text-[13px]">
          <dl className="grid grid-cols-[130px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-muted">Package</dt>
            <dd className="text-fg">
              {r.version.definition.name} {r.version.definition.version} <Mono className="text-faint">{r.version.definition.product_code}</Mono>
            </dd>
            {r.previous ? (
              <>
                <dt className="text-muted">Replaces</dt>
                <dd className="text-fg">{r.previous.definition.version}</dd>
              </>
            ) : null}
            {review!.change.operation !== "verify" ? (
              <>
                <dt className="text-muted">Script hash</dt>
                <dd>
                  <Tip label={r.version.mutation.sha256}>
                    <Mono className="text-fg">{short(r.version.mutation.sha256, 20)}</Mono>
                  </Tip>
                </dd>
              </>
            ) : null}
          </dl>
          <TargetList targets={r.targets} />
          {review!.change.operation !== "verify" ? (
            <p className="text-muted">Runs as SYSTEM. Every device must be online with scripts turned on; otherwise nothing is queued.</p>
          ) : (
            <p className="text-muted">Read-only check. Devices must be online with scripts enabled.</p>
          )}
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Application">
              <Select value={selected} onChange={(e) => (setSelected(e.target.value), setPrevious(""))} className="w-full">
                <option value="">Choose…</option>
                {apps.map((list) => (
                  <optgroup key={list[0]!.application_id} label={list[0]!.definition.name}>
                    {list.map((v) => (
                      <option key={v.id} value={v.id}>
                        {v.definition.name} {v.definition.version}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </Select>
            </Field>
            <Field label="Action">
              <Segmented label="Action" value={operation} onChange={setOperation} options={(Object.keys(operationLabels) as AppOperation[]).map((o) => ({ value: o, label: operationLabels[o] }))} />
            </Field>
          </div>
          <p className="-mt-2 text-[12.5px] text-muted">{operationHelp[operation]}</p>
          {operation === "update" ? (
            <Field label="Upgrade from" hint={version && older.length === 0 ? "No older version of this application is in the catalog." : undefined}>
              <Select value={previous} onChange={(e) => setPrevious(e.target.value)} className="w-full" disabled={older.length === 0}>
                <option value="">Choose the installed version…</option>
                {older.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.definition.version}
                  </option>
                ))}
              </Select>
            </Field>
          ) : null}
          {device ? (
            <p className="text-[13px] text-muted">
              Target: <span className="text-fg">{device.hostname}</span>
            </p>
          ) : (
            <TargetPicker value={targets} onChange={setTargets} include={(d) => d.os === "windows"} height="max-h-56" />
          )}
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      )}
    </Modal>
  );
}

/** Deployment history (all devices, or one), with cancel for queued work. */
export function DeploymentsTable({ device, compact }: { device?: string; compact?: boolean }) {
  const account = useAccount();
  const client = useQueryClient();
  const now = useNow();
  const q = useQuery({
    queryKey: ["deployments", device ?? ""],
    queryFn: ({ signal }) => get<{ deployments: Deployment[] }>(`/api/v1/deployments${device ? `?device=${device}` : ""}`, signal),
    refetchInterval: (query) => ((query.state.data?.deployments ?? []).some((d) => ["queued", "dispatched", "running"].includes(d.status)) ? 3000 : LIVE_INTERVAL),
  });
  const [cancel, setCancel] = useState<Deployment | null>(null);
  if (q.isPending) return <div className="p-4"><Spinner label="Loading deployments" /></div>;
  if (q.isError && !q.data) return <div className="p-4"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const columns: Column<Deployment>[] = [
    ...(device
      ? []
      : [
          {
            key: "device",
            header: "Device",
            sort: (d: Deployment) => d.hostname,
            cell: (d: Deployment) => (
              <Link to={`/devices/${d.device_id}?tab=software`} className="text-fg hover:text-accent">
                {d.hostname}
              </Link>
            ),
          },
        ]),
    {
      key: "app",
      header: "Application",
      sort: (d) => d.name,
      cell: (d) => (
        <span className="text-fg">
          {d.name} <span className="text-muted">{d.version}</span>
        </span>
      ),
    },
    { key: "op", header: "Action", sort: (d) => d.operation, cell: (d) => <Badge>{operationLabels[d.operation] ?? d.operation}</Badge> },
    {
      key: "status",
      header: "Result",
      sort: (d) => d.status,
      cell: (d) => (
        <span className="flex items-center gap-2">
          {d.operation === "verify" && d.status === "verified" ? (
            d.report?.products?.some((p) => p.code === d.product_code) ? (
              <Badge tone="ok" dot>
                Installed
              </Badge>
            ) : (
              <Badge dot>Not installed</Badge>
            )
          ) : (
            <OperationStatus status={d.status} />
          )}
          {reasonText[d.reason] ? <span className="text-[12px] text-muted">{reasonText[d.reason]}</span> : null}
          {d.report?.restart_required ? <Badge tone="warn">Restart needed</Badge> : null}
        </span>
      ),
    },
    ...(compact ? [] : [{ key: "actor", header: "By", cell: (d: Deployment) => <span className="text-muted">{d.actor}</span> }]),
    {
      key: "when",
      header: "Started",
      sort: (d) => d.created_at,
      cell: (d) => (
        <Tip label={absoluteTime(d.created_at)}>
          <span className="text-muted tabular-nums">{relativeTime(d.created_at, now)}</span>
        </Tip>
      ),
    },
    {
      key: "cancel",
      header: "",
      className: "w-px text-right",
      cell: (d) =>
        account.permissions.owner && (d.status === "queued" || d.status === "dispatched") ? (
          <Button size="sm" variant="ghost" onClick={() => setCancel(d)}>
            Cancel
          </Button>
        ) : null,
    },
  ];
  return (
    <>
      <DataTable
        columns={columns}
        rows={q.data!.deployments}
        rowKey={(d) => d.id}
        initialSort={{ key: "when", dir: "desc" }}
        dense={compact}
        empty={<EmptyState icon={<PackageCheck />} title="No deployments yet" />}
      />
      <ConfirmDialog
        open={cancel !== null}
        onOpenChange={(o) => !o && setCancel(null)}
        title={`Cancel ${cancel ? operationLabels[cancel.operation].toLowerCase() : ""} of ${cancel?.name ?? ""} on ${cancel?.hostname ?? ""}?`}
        confirmLabel="Cancel deployment"
        danger
        onConfirm={async () => {
          await post(`/api/v1/deployments/${cancel!.id}/cancel`);
          await client.invalidateQueries({ queryKey: ["deployments"] });
        }}
      >
        <p>Only work the device has not started can be cancelled.</p>
      </ConfirmDialog>
    </>
  );
}
