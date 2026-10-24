import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Download, File, Folder, FolderOpen, RefreshCw, Upload } from "lucide-react";
import { ApiError, csrfHeader, get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import type { FileEntry, FileJob, FilesResponse } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Select, Spinner, Tip, Toolbar } from "../../components/ui";
import { OperationStatus } from "../../components/status";

type Staged = { id: string; path: string; size: number; sha256: string };

const join = (folder: string, name: string) => (folder === "." ? name : `${folder}/${name}`);
const parent = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : ".");

export function FilesTab({ deviceId }: { deviceId: string }) {
  const client = useQueryClient();
  const [root, setRoot] = useState("");
  const [folder, setFolder] = useState(".");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [staged, setStaged] = useState<Staged | null>(null);
  const stagedRef = useRef<Staged | null>(null);
  const setStage = (v: Staged | null) => {
    stagedRef.current = v;
    setStaged(v);
  };
  const [uploading, setUploading] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const q = useQuery({
    queryKey: ["files", deviceId],
    queryFn: ({ signal }) => get<FilesResponse>(`/api/v1/devices/${deviceId}/files`, signal),
    refetchInterval: (query) => (query.state.data?.jobs.some((j) => j.status === "queued" || j.status === "dispatched") ? 1500 : 10_000),
  });
  const roots = q.data?.support.support.roots ?? [];
  const currentRoot = roots.find((r) => r.id === root) ?? roots[0];
  useEffect(() => {
    if (!root && roots[0]) setRoot(roots[0].id);
  }, [root, roots]);

  const jobs = q.data?.jobs ?? [];
  const listing = useMemo(
    () => jobs.find((j) => j.operation === "list" && j.status === "succeeded" && j.root === currentRoot?.id && j.path === folder),
    [jobs, currentRoot, folder],
  );
  const listingPending = jobs.some((j) => j.operation === "list" && (j.status === "queued" || j.status === "dispatched") && j.root === currentRoot?.id && j.path === folder);
  const autoListed = useRef(new Set<string>());
  useEffect(() => {
    const key = `${currentRoot?.id}:${folder}`;
    if (!q.data?.available || !currentRoot?.read || listing || listingPending || autoListed.current.has(key)) return;
    autoListed.current.add(key);
    void queue("list", folder);
    // Listing is read-only; it runs once per folder visit without confirmation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data?.available, currentRoot?.id, folder, listing, listingPending]);
  const entries = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return (listing?.result?.entries ?? []).filter((e) => !t || e.name.toLowerCase().includes(t));
  }, [listing, filter]);

  const queue = async (operation: "list" | "download", path: string) => {
    if (!currentRoot) return;
    setError(null);
    try {
      await post(`/api/v1/devices/${deviceId}/files`, { id: newOperationID(), operation, root: currentRoot.id, path });
      await client.invalidateQueries({ queryKey: ["files", deviceId] });
    } catch (e) {
      setError(e);
    }
  };
  const open = (path: string) => {
    setFolder(path);
    setFilter("");
    const known = jobs.some((j) => j.operation === "list" && j.status === "succeeded" && j.root === currentRoot?.id && j.path === path);
    if (!known) void queue("list", path);
  };
  const upload = async (file: File) => {
    if (!currentRoot) return;
    if (file.size > (q.data?.max_bytes ?? 0)) {
      setError(new Error("Files are limited to 8 MB."));
      return;
    }
    setUploading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("id", newOperationID());
      form.append("root", currentRoot.id);
      form.append("path", folder);
      form.append("file", file);
      const r = await fetch(`/api/v1/devices/${deviceId}/files/upload`, { method: "POST", body: form, headers: csrfHeader(), credentials: "same-origin" });
      const body = (await r.json().catch(() => ({}))) as Staged & { error?: string; code?: string };
      if (!r.ok) throw new ApiError(body.error ?? "Upload failed.", r.status, body.code ?? "error");
      setStage(body);
    } catch (e) {
      setError(e);
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  if (q.isPending) return <Spinner label="Loading file access" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  if (roots.length === 0) {
    return (
      <EmptyState icon={<FolderOpen />} title="No drives reported">
        The agent offers every local fixed drive once file transfer is turned on and the device is reporting. OpenRMM's own folders are never reachable.
      </EmptyState>
    );
  }

  const crumbs = folder === "." ? [] : folder.split("/");
  const columns: Column<FileEntry>[] = [
    {
      key: "name",
      header: "Name",
      sort: (e) => (e.directory ? "0" : "1") + e.name.toLowerCase(),
      cell: (e) =>
        e.directory ? (
          <button type="button" className="inline-flex items-center gap-2 font-medium text-fg hover:text-accent" onClick={() => open(join(folder, e.name))}>
            <Folder className="size-4 text-accent" /> {e.name}
          </button>
        ) : (
          <span className="inline-flex items-center gap-2 text-fg">
            <File className="size-4 text-faint" /> {e.name}
          </span>
        ),
    },
    { key: "size", header: "Size", sort: (e) => (e.directory ? -1 : e.size), className: "text-muted tabular-nums", cell: (e) => (e.directory ? "" : bytes(e.size)) },
    {
      key: "modified",
      header: "Modified",
      sort: (e) => e.modified_at,
      cell: (e) => (
        <Tip label={absoluteTime(e.modified_at)}>
          <span className="text-muted">{relativeTime(e.modified_at)}</span>
        </Tip>
      ),
    },
    {
      key: "act",
      header: "",
      className: "text-right",
      cell: (e) =>
        !e.directory && currentRoot?.read ? (
          <Button size="sm" variant="ghost" icon={<Download className="size-3.5" />} disabled={!d.available || e.size > d.max_bytes} onClick={() => void queue("download", join(folder, e.name))}>
            Download
          </Button>
        ) : null,
    },
  ];

  return (
    <div className="space-y-5">
      <Panel bodyClassName="p-0">
        <Toolbar>
          <Select value={currentRoot?.id ?? ""} onChange={(e) => (setRoot(e.target.value), setFolder("."))} aria-label="Shared folder">
            {roots.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </Select>
          {currentRoot ? (
            <>
              <Badge tone={currentRoot.read ? "ok" : "neutral"}>{currentRoot.read ? "Read" : "No read"}</Badge>
              <Badge tone={currentRoot.write ? "accent" : "neutral"}>{currentRoot.write ? "Upload" : "No upload"}</Badge>
            </>
          ) : null}
          {!d.available ? <Badge tone="warn">Device offline or not reporting</Badge> : null}
          <div className="flex-1" />
          <SearchInput value={filter} onChange={setFilter} placeholder="Filter this folder" className="w-56" />
          <Button size="sm" icon={<RefreshCw className="size-3.5" />} loading={listingPending} disabled={!d.available || !currentRoot?.read} onClick={() => void queue("list", folder)}>
            Refresh
          </Button>
          {currentRoot?.write ? (
            <>
              <input ref={fileInput} type="file" hidden onChange={(e) => e.target.files?.[0] && void upload(e.target.files[0])} />
              <Button size="sm" variant="primary" icon={<Upload className="size-3.5" />} loading={uploading} disabled={!d.available} onClick={() => fileInput.current?.click()}>
                Upload
              </Button>
            </>
          ) : null}
        </Toolbar>
        <nav className="flex flex-wrap items-center gap-1 border-b border-border px-4 py-2 text-[13px]" aria-label="Folder">
          <button type="button" className="text-accent hover:underline" onClick={() => open(".")}>
            {currentRoot?.name}
          </button>
          {crumbs.map((c, i) => (
            <span key={i} className="inline-flex items-center gap-1">
              <ChevronRight className="size-3.5 text-faint" />
              <button type="button" className={i === crumbs.length - 1 ? "text-fg" : "text-accent hover:underline"} onClick={() => open(crumbs.slice(0, i + 1).join("/"))}>
                {c}
              </button>
            </span>
          ))}
          {folder !== "." ? (
            <button type="button" className="ml-3 text-[12px] text-muted hover:text-fg" onClick={() => open(parent(folder))}>
              Up one level
            </button>
          ) : null}
          <span className="ml-auto text-[12px] text-faint">{listing ? `Listed ${relativeTime(listing.finished_at ?? listing.created_at)}${listing.result?.more ? " · first 500 entries" : ""}` : ""}</span>
        </nav>
        {error ? (
          <div className="p-3">
            <ErrorNotice error={error} />
          </div>
        ) : null}
        {listing ? (
          <DataTable columns={columns} rows={entries} rowKey={(e) => e.name} dense initialSort={{ key: "name", dir: "asc" }} empty={<EmptyState title={filter ? "Nothing matches" : "This folder is empty"} />} />
        ) : listingPending ? (
          <div className="p-6">
            <Spinner label="Asking the device for this folder" />
          </div>
        ) : (
          <EmptyState icon={<FolderOpen />} title="Not listed yet">
            {currentRoot?.read ? "Choose Refresh to list this folder." : "This folder does not allow reading."}
          </EmptyState>
        )}
      </Panel>

      <Transfers jobs={jobs} deviceId={deviceId} />

      <ConfirmDialog
        open={staged !== null}
        onOpenChange={(o) => {
          // Dismissing without confirming discards the staged upload; a
          // confirmed stage must never be cancelled here.
          const pendingStage = stagedRef.current;
          if (!o && pendingStage) void post(`/api/v1/devices/${deviceId}/files/${pendingStage.id}/cancel`).catch(() => undefined);
          if (!o) setStage(null);
        }}
        title="Upload this file to the device?"
        confirmLabel="Upload"
        onConfirm={async () => {
          const pendingStage = stagedRef.current;
          if (!pendingStage) return;
          await post(`/api/v1/devices/${deviceId}/files/${pendingStage.id}/confirm`);
          setStage(null);
          await client.invalidateQueries({ queryKey: ["files", deviceId] });
        }}
      >
        {staged ? (
          <dl className="grid grid-cols-[90px_1fr] gap-x-3 gap-y-1.5">
            <dt>Folder</dt>
            <dd className="text-fg">
              {currentRoot?.name} / {parent(staged.path) === "." ? "" : parent(staged.path)}
            </dd>
            <dt>File</dt>
            <dd className="text-fg">{staged.path.split("/").pop()}</dd>
            <dt>Size</dt>
            <dd className="text-fg">{bytes(staged.size)}</dd>
            <dt>SHA-256</dt>
            <dd>
              <Mono className="break-all text-fg">{staged.sha256}</Mono>
            </dd>
          </dl>
        ) : null}
        <p className="mt-2">The upload never overwrites: it fails if a file with this name already exists.</p>
      </ConfirmDialog>
    </div>
  );
}

const opLabel = (j: FileJob) => (j.operation === "list" ? "List" : j.operation === "download" ? "Download" : "Upload");

function Transfers({ jobs, deviceId }: { jobs: FileJob[]; deviceId: string }) {
  const transfers = jobs.filter((j) => j.operation !== "list").slice(0, 12);
  if (transfers.length === 0) return null;
  const now = Date.now() / 1000;
  return (
    <Panel title="Transfers" bodyClassName="p-0">
      <ul className="divide-y divide-border">
        {transfers.map((j) => {
          const ready = j.operation === "download" && j.status === "succeeded" && j.payload_until > now;
          return (
            <li key={j.id} className="flex items-center gap-3 px-4 py-2.5">
              <div className="min-w-0 flex-1">
                <div className="truncate text-fg">
                  {opLabel(j)} <span className="font-mono text-[12.5px]">{j.path}</span>
                </div>
                <div className="text-[12px] text-faint">
                  by {j.actor}
                  {j.result?.sha256 || j.sha256 ? (
                    <>
                      {" · "}
                      <Tip label={j.result?.sha256 || j.sha256}>
                        <span className="font-mono">sha256 {(j.result?.sha256 || j.sha256).slice(0, 12)}…</span>
                      </Tip>
                    </>
                  ) : null}
                  {j.result?.size ? ` · ${bytes(j.result.size)}` : j.size ? ` · ${bytes(j.size)}` : ""}
                </div>
              </div>
              {ready ? (
                <a href={`/api/v1/devices/${deviceId}/files/${j.id}/download`} download className="inline-flex h-7 items-center gap-1.5 rounded-md bg-accent px-2.5 text-[12.5px] font-medium text-accent-fg hover:bg-accent-hover">
                  <Download className="size-3.5" /> Save
                </a>
              ) : null}
              <OperationStatus status={j.status === "succeeded" && j.result && j.result.outcome !== "ok" ? j.result.outcome : j.status} />
              <span className="w-16 text-right text-[12px] text-muted">{relativeTime(j.finished_at ?? j.created_at)}</span>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
