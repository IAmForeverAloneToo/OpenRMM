import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Cog, Cpu, Download, Eye, FileSearch, KeyRound, ListStart, Network, SquareTerminal } from "lucide-react";
import { get, post } from "../../lib/api";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import type { DevicesResponse, EvidenceCollection, ResponseAction } from "../../lib/types";
import { ActionViewer } from "./ActionViewer";
import { NtfsViewer } from "./NtfsViewer";
import { DropAndScript } from "./DropAndScript";
import { useTriageProfiles } from "./TriageProfiles";
import { ntfsVolumes } from "../../lib/ntfs";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Select, Tip, type Tone } from "../../components/ui";

// Collect files from devices as case evidence, verified chunk by
// chunk and as a whole, stored by SHA-256.

const active = new Set(["queued", "dispatched", "uploading", "verifying"]);
export const states: Record<EvidenceCollection["status"], { label: string; tone: Tone }> = {
  queued: { label: "Waiting for device", tone: "neutral" },
  dispatched: { label: "Opening file", tone: "info" },
  uploading: { label: "Uploading", tone: "info" },
  verifying: { label: "Verifying", tone: "info" },
  succeeded: { label: "Collected", tone: "ok" },
  failed: { label: "Failed", tone: "danger" },
  expired: { label: "Expired", tone: "warn" },
  cancelled: { label: "Cancelled", tone: "neutral" },
};
const methods: Record<string, string> = {
  read: "Read",
  backup: "Backup privilege",
  shadow_copy: "Shadow copy",
  registry_save: "Registry save",
  export: "Exported",
  triage: "Triage package",
  ntfs: "NTFS raw read",
};
export const reasons: Record<string, string> = {
  denied: "The file is not allowed (outside fixed drives, a link, OpenRMM's own folders or an unknown hive) or cannot be read.",
  not_found: "The file, stream, hive or user profile does not exist.",
  too_large: "The file is larger than the 16 GB limit.",
  changed: "The file changed while it was read.",
  hash_mismatch: "The server's hash did not match the device's.",
  quota: "The evidence store quota is full.",
  no_response: "The device did not start the collection in time.",
  stalled: "The upload stopped making progress.",
  expired: "The device did not pick up the request within an hour.",
  failed: "The agent could not read or upload the file.",
  verify_failed: "The server could not read the upload to verify it.",
  missing_upload: "The upload was missing when the server verified it.",
  response_off: "Incident response was switched off on the device.",
  not_permitted: "The requester no longer has access to the device.",
  server_restore: "The server was restored from a backup.",
  purged: "Results of a live response session without a case are kept for 24 hours.",
  no_space: "The device does not have enough free disk space to build the package.",
  withdrawn: "The tool was withdrawn from the library before the device fetched it.",
  unknown: "The device may have run the action, but its result was lost (for example the agent restarted). Check the device before repeating it.",
};

export function progress(c: EvidenceCollection): string {
  if (c.status !== "uploading" || !c.size) return "";
  const total = Math.max(1, Math.ceil(c.size / c.chunk_size));
  return ` ${Math.floor((c.received_chunks / total) * 100)}%`;
}

export function Collections({ caseId, open }: { caseId: string; open: boolean }) {
  const qc = useQueryClient();
  const [device, setDevice] = useState("");
  const [path, setPath] = useState("");
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal), enabled: open });
  const q = useQuery({
    queryKey: ["collections", caseId],
    queryFn: ({ signal }) => get<{ collections: EvidenceCollection[] }>(`/api/v1/cases/${caseId}/collections`, signal),
    refetchInterval: (query) => ((query.state.data?.collections ?? []).some((c) => active.has(c.status)) ? 3000 : false),
  });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["collections", caseId] });
    void qc.invalidateQueries({ queryKey: ["case", caseId] });
  };
  // A file (optionally :stream) or a registry hive.
  const [source, setSource] = useState<"file" | "hive" | "evtx" | "triage" | "ntfs">("file");
  const [profile, setProfile] = useState("full");
  const profiles = useTriageProfiles(open);
  // A withdrawn profile falls back to the built-in one.
  useEffect(() => {
    if (profiles.data && !profiles.data.profiles.some((p) => p.id === profile)) setProfile("full");
  }, [profiles.data, profile]);
  // NTFS: drive letters (C D: or all); empty is the system drive.
  const [drives, setDrives] = useState("");
  const volumes = ntfsVolumes(drives);
  const [channel, setChannel] = useState("Security");
  const [hive, setHive] = useState("SYSTEM");
  const [user, setUser] = useState("");
  const userHive = hive === "NTUSER" || hive === "USRCLASS";
  const target = source === "file" ? path.trim() : source === "evtx" ? channel.trim() : source === "triage" || source === "ntfs" ? "" : userHive ? `${hive}:${user.trim()}` : hive;
  const ready = source === "file" ? !!path.trim() : source === "evtx" ? !!channel.trim() : source === "triage" ? !!profile : source === "ntfs" ? volumes !== null : !userHive || !!user.trim();
  const collect = useMutation({
    mutationFn: () => post(`/api/v1/cases/${caseId}/collect`, { device_id: device, source, path: target, ...(source === "triage" ? { profile } : {}), ...(source === "ntfs" ? { volumes } : {}) }),
    onSuccess: () => (setPath(""), setUser(""), refresh()),
  });
  const cancel = useMutation({ mutationFn: (job: string) => post(`/api/v1/cases/${caseId}/collections/${job}/cancel`), onSettled: refresh });
  // A live response session recorded to this case.
  const navigate = useNavigate();
  const terminal = useMutation({
    mutationFn: () => post<{ id: string }>(`/api/v1/devices/${device}/terminal`, { case_id: caseId }),
    onSuccess: (r) => navigate(`/devices/${device}/terminal/${r.id}`),
  });
  // Structured actions; their results are case evidence.
  const [registryKey, setRegistryKey] = useState("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
  const [viewing, setViewing] = useState<EvidenceCollection | null>(null);
  const action = useMutation({
    mutationFn: (a: ResponseAction) => post(`/api/v1/cases/${caseId}/actions`, { device_id: device, action: a }),
    onSuccess: refresh,
  });
  const list = q.data?.collections ?? [];
  const usable = (devices.data?.devices ?? []).filter((d) => d.status !== "revoked");
  const online = usable.some((d) => d.id === device && d.status === "online");
  // With one online device it is chosen for you.
  const onlineDevices = usable.filter((d) => d.status === "online");
  useEffect(() => {
    const only = onlineDevices.length === 1 ? onlineDevices[0] : undefined;
    if (!device && only) setDevice(only.id);
  }, [device, onlineDevices.length, onlineDevices[0]?.id]);

  return (
    <Panel title="Evidence" className="mb-4" bodyClassName="p-0">
      {open ? (
        <div className="border-b border-border p-4">
          {collect.isError ? <ErrorNotice error={collect.error} /> : null}
          {terminal.isError ? <ErrorNotice error={terminal.error} /> : null}
          <div className="grid gap-3 sm:grid-cols-[minmax(0,220px)_minmax(0,150px)_1fr_auto] sm:items-end">
            <Field label="Device">
              <Select className="w-full" value={device} onChange={(e) => setDevice(e.target.value)} aria-label="Device">
                <option value="">Choose a device</option>
                {usable.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.hostname} ({d.status})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Collect">
              <Select className="w-full" value={source} onChange={(e) => setSource(e.target.value as "file" | "hive" | "evtx" | "triage" | "ntfs")} aria-label="Source">
                <option value="file">File</option>
                <option value="hive">Registry hive</option>
                <option value="evtx">Event log (.evtx)</option>
                <option value="triage">Triage package</option>
                <option value="ntfs">NTFS artifacts</option>
              </Select>
            </Field>
            {source === "ntfs" ? (
              <Field label="Drives ($MFT, $LogFile, USN journal and timelines)">
                <Input value={drives} onChange={(e) => setDrives(e.target.value)} placeholder="System drive (or C: D:, or all)" maxLength={100} spellCheck={false} aria-label="Drives" />
              </Field>
            ) : source === "triage" ? (
              <Field label="Profile">
                <Select className="w-full" value={profile} onChange={(e) => setProfile(e.target.value)} aria-label="Triage profile">
                  {(profiles.data?.profiles ?? [{ id: "full", name: "Full triage" }]).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : source === "evtx" ? (
              <Field label="Channel (whole log)">
                <Input value={channel} onChange={(e) => setChannel(e.target.value)} placeholder="Security" maxLength={256} spellCheck={false} aria-label="Channel" list="evtx-channels" />
                <datalist id="evtx-channels">
                  {["Security", "System", "Application", "Setup", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-Windows Defender/Operational"].map((c) => (
                    <option key={c} value={c} />
                  ))}
                </datalist>
              </Field>
            ) : source === "file" ? (
              <Field label="File path on the device">
                <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\Users\name\Downloads\invoice.pdf" maxLength={1024} spellCheck={false} aria-label="File path" />
              </Field>
            ) : (
              <div className="grid gap-3 sm:grid-cols-[minmax(0,200px)_1fr]">
                <Field label="Hive">
                  <Select value={hive} onChange={(e) => setHive(e.target.value)} aria-label="Hive">
                    <option value="SYSTEM">SYSTEM</option>
                    <option value="SOFTWARE">SOFTWARE</option>
                    <option value="SAM">SAM</option>
                    <option value="SECURITY">SECURITY</option>
                    <option value="DEFAULT">DEFAULT</option>
                    <option value="NTUSER">User: NTUSER.DAT</option>
                    <option value="USRCLASS">User: UsrClass.dat</option>
                  </Select>
                </Field>
                {userHive ? (
                  <Field label="User profile or SID">
                    <Input value={user} onChange={(e) => setUser(e.target.value)} placeholder="alice or S-1-5-21-…" maxLength={64} spellCheck={false} aria-label="User profile or SID" />
                  </Field>
                ) : null}
              </div>
            )}
            <Button variant="primary" icon={<FileSearch className="size-4" />} loading={collect.isPending} disabled={!device || !ready} onClick={() => collect.mutate()}>
              Collect
            </Button>
          </div>
          {!device ? <p className="mt-2 text-[12.5px] text-warn">Choose a device to collect evidence, take snapshots, drop files, run scripts or open live response.</p> : null}
          <p className="mt-2 text-[12px] text-faint">
            The agent reads without changing content, records times, owner and alternate data streams, hashes and uploads in verified chunks (up to 16 GB). Files it may not read are read with the backup privilege; locked files from a temporary shadow copy; loaded hives are saved. Add <Mono>:stream</Mono> to a path to collect one stream; streams up to 1 MiB are collected automatically. Recorded in the custody log. Up to two collections run per device.
          </p>
          <div className="mt-3 space-y-2 border-t border-border pt-3">
            {action.isError ? <ErrorNotice error={action.error} /> : null}
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[12.5px] text-muted">Snapshot to the case:</span>
              {(
                [
                  ["processes", "Process list", <Cpu className="size-4" />],
                  ["connections", "Network connections", <Network className="size-4" />],
                  ["services", "Services", <Cog className="size-4" />],
                  ["tasks", "Scheduled tasks", <CalendarClock className="size-4" />],
                  ["persistence", "Persistence report", <ListStart className="size-4" />],
                ] as const
              ).map(([kind, label, icon]) => (
                <Button key={kind} size="sm" icon={icon} disabled={!device} loading={action.isPending && action.variables?.kind === kind} onClick={() => action.mutate({ kind })}>
                  {label}
                </Button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input className="max-w-xl flex-1" value={registryKey} onChange={(e) => setRegistryKey(e.target.value)} placeholder="HKLM\SOFTWARE\…" maxLength={512} spellCheck={false} aria-label="Registry key" />
              <Button size="sm" icon={<KeyRound className="size-4" />} disabled={!device || !registryKey.trim()} loading={action.isPending && action.variables?.kind === "registry"} onClick={() => action.mutate({ kind: "registry", key: registryKey.trim() })}>
                Read registry key
              </Button>
            </div>
            <p className="text-[12px] text-faint">
              Process lists include command lines, users and image hashes; services include binaries and service DLLs with hashes. Registry keys under HKLM, HKU or HKCR are read only. Results are stored as hashed evidence; open one with View to filter it, read subkeys or kill a process.
            </p>
          </div>
          <DropAndScript caseId={caseId} device={device} evidence={list} onQueued={refresh} />
          <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-border pt-3">
            <Tip label="PowerShell as SYSTEM on the chosen device with built-in response commands. Every input and output is recorded with its time and stored here as evidence when the session ends; command results are stored here too.">
              <span>
                <Button icon={<SquareTerminal className="size-4" />} loading={terminal.isPending} disabled={!online} onClick={() => terminal.mutate()}>
                  Open live response
                </Button>
              </span>
            </Tip>
            <span className="text-[12px] text-faint">{!device ? "Choose a device above first." : !online ? "The device is offline." : "Recorded to this case as a terminal transcript."}</span>
          </div>
        </div>
      ) : null}
      {q.isError ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : list.length === 0 ? (
        <EmptyState title="No evidence collected yet" />
      ) : (
        <ul className="divide-y divide-border">
          {list.map((c) => {
            const transcript = c.kind === "transcript";
            const s = c.source === "action" && c.status === "dispatched" ? { label: "Running", tone: "info" as Tone } : !transcript ? states[c.status] : c.status === "uploading" ? { label: "Recording", tone: "warn" as Tone } : c.status === "succeeded" ? { label: "Stored", tone: "ok" as Tone } : states[c.status];
            return (
              <li key={c.id} className="flex flex-wrap items-start gap-3 px-4 py-3 text-[12.5px]">
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {transcript ? (
                      <Tip label={c.path}>
                        <span className="inline-flex items-center gap-1.5 text-fg">
                          <SquareTerminal className="size-3.5 shrink-0 text-muted" /> Terminal transcript
                        </span>
                      </Tip>
                    ) : c.source === "ntfs" ? (
                      <span className="min-w-0 text-fg">
                        NTFS artifacts <span className="text-muted">{!c.query ? "system drive" : c.query === "all" ? "all fixed drives" : c.query.replaceAll(",", " ")}</span>
                      </span>
                    ) : c.source === "triage" ? (
                      <span className="min-w-0 text-fg">
                        Triage package <span className="font-medium">{c.path}</span>
                        {c.query ? <span className="ml-1 block truncate text-[11.5px] text-muted">{c.query.replaceAll(",", " · ")}</span> : null}
                      </span>
                    ) : c.source === "evtx" ? (
                      <span className="min-w-0 text-fg">
                        Event log <Mono>{c.path}</Mono>
                        {c.query ? <Mono className="ml-1 block truncate text-[11px] text-muted">{c.query}</Mono> : null}
                      </span>
                    ) : c.source === "hive" ? (
                      <span className="text-fg">
                        Registry hive <Mono>{c.path}</Mono>
                      </span>
                    ) : (
                      <Mono className="truncate text-fg">{c.path}</Mono>
                    )}
                    <Badge tone={s.tone} dot={active.has(c.status)}>
                      {s.label}
                      {progress(c)}
                    </Badge>
                    {c.meta && methods[c.meta.method] ? <Badge tone="neutral">{methods[c.meta.method]}</Badge> : null}
                    {c.parent_id ? <span className="text-[12px] text-faint">stream, collected automatically</span> : null}
                  </div>
                  <div className="text-muted">
                    {c.hostname || c.device_id.slice(0, 12)} · {transcript ? "opened" : "requested"} {relativeTime(c.created_at)}
                    {c.size ? ` · ${bytes(c.size)}` : ""}
                    {c.file_modified ? (
                      <Tip label={`Created ${c.file_created ? absoluteTime(Math.floor(c.file_created / 1e9)) : "unknown"}`}>
                        <span> · modified {absoluteTime(Math.floor(c.file_modified / 1e9))}</span>
                      </Tip>
                    ) : null}
                  </div>
                  {c.meta?.owner || c.meta?.owner_sid ? (
                    <div className="text-muted">
                      Owner {c.meta.owner || c.meta.owner_sid}
                      {c.meta.accessed ? ` · accessed ${absoluteTime(Math.floor(c.meta.accessed / 1e9))}` : ""}
                      {c.meta.changed ? ` · record changed ${absoluteTime(Math.floor(c.meta.changed / 1e9))}` : ""}
                    </div>
                  ) : null}
                  {c.meta?.streams?.length ? (
                    <div className="text-muted">
                      Streams:{" "}
                      {c.meta.streams.map((x) => `${x.name} (${bytes(x.size)})`).join(", ")}
                      {c.meta.streams_more ? ", more not listed" : ""}
                    </div>
                  ) : null}
                  {c.status === "failed" || c.status === "expired" ? <div className="text-danger">{reasons[c.outcome] ?? c.outcome}</div> : null}
                  {transcript && c.status === "succeeded" && c.outcome === "hash_mismatch" ? (
                    <div className="text-danger">The stored transcript differs from what the server recorded; it was changed on the evidence volume. Preserve the volume for examination.</div>
                  ) : null}
                  {transcript && c.status === "succeeded" && c.outcome === "unverified" ? (
                    <div className="text-warn">Stored after a server stop: it ends where the recording stopped and could not be checked against the recorder&apos;s hash.</div>
                  ) : null}
                  {c.server_sha256 ? <Mono className="block truncate text-[11px] text-faint">SHA-256 {c.server_sha256}</Mono> : null}
                </div>
                {c.status === "succeeded" && (c.source === "action" || c.source === "ntfs") ? (
                  <Button size="sm" icon={<Eye className="size-3.5" />} onClick={() => setViewing(c)}>
                    View
                  </Button>
                ) : null}
                {c.status === "succeeded" ? (
                  <a
                    href={`/api/v1/cases/${caseId}/collections/${c.id}/file`}
                    download
                    className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-[12.5px] font-medium text-fg hover:bg-surface-3"
                  >
                    <Download className="size-3.5" /> Download
                  </a>
                ) : null}
                {open && !transcript && (c.source === "action" ? c.status === "queued" : c.status === "queued" || c.status === "dispatched" || c.status === "uploading") ? (
                  <Button size="sm" variant="ghost" loading={cancel.isPending && cancel.variables === c.id} onClick={() => cancel.mutate(c.id)}>
                    Cancel
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      <p className="border-t border-border px-4 py-2 text-[12px] text-faint">Every download is recorded in the custody log with the account that downloaded it.</p>
      {viewing?.source === "ntfs" ? (
        <NtfsViewer base={`/api/v1/cases/${caseId}/collections/${viewing.id}/ntfs`} job={viewing} open onClose={() => setViewing(null)} />
      ) : viewing ? (
        <ActionViewer caseId={caseId} job={viewing} open onClose={() => setViewing(null)} onQueued={refresh} />
      ) : null}
    </Panel>
  );
}
