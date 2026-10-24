import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { get, post } from "../../lib/api";
import type { ActionResult, EvidenceCollection, PersistenceEntry, ProcessDetail, ResponseAction } from "../../lib/types";
import { Modal, ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Mono, SearchInput, Spinner } from "../../components/ui";
import { MatchesTable, Scanned } from "../hunting/matches";

// Shows a response action's result document. Opening it downloads
// the evidence, which the custody log records like any download. A live
// response session passes its own result URL and sends follow-up
// actions (kill, read a subkey) as console commands.

const cell = "border-b border-border px-2 py-1.5 align-top text-[12px]";
const head = "border-b border-border-strong px-2 py-1.5 text-left text-[11.5px] font-medium text-muted";

function Table({ columns, rows }: { columns: string[]; rows: React.ReactNode[][] }) {
  return (
    <table className="w-full border-collapse">
      <thead className="sticky top-0 bg-surface">
        <tr>
          {columns.map((c) => (
            <th key={c} className={head}>
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-surface-2">
            {r.map((v, j) => (
              <td key={j} className={cell}>
                {v}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function short(hash?: string) {
  return hash ? <Mono className="text-[11px]" >{hash.slice(0, 12)}…</Mono> : <span className="text-faint">—</span>;
}

function matches(filter: string, ...values: (string | number | undefined)[]) {
  const f = filter.trim().toLowerCase();
  return !f || values.some((v) => String(v ?? "").toLowerCase().includes(f));
}

// recordedIn: where viewing this result is recorded; actionIn: where a
// follow-up action is recorded (they differ after a case is attached).
export type ActionSource = { fileUrl: string; queue: (a: ResponseAction) => Promise<unknown>; recordedIn: string; actionIn: string; queued: string };

// Persistence entries, optionally without Microsoft-signed ones.
const categories: Record<string, string> = {
  run_key: "Run key",
  winlogon: "Winlogon",
  appinit: "AppInit DLL",
  appcert: "AppCert DLL",
  boot_execute: "Boot execute",
  lsa: "LSA package",
  ifeo: "IFEO debugger",
  silent_exit: "Silent process exit",
  active_setup: "Active Setup",
  print_monitor: "Print monitor",
  service: "Service",
  driver: "Driver",
  service_dll: "Service DLL",
  task: "Scheduled task",
  startup_folder: "Startup folder",
  wmi: "WMI subscription",
  windows_load: "Windows Load/Run",
  logon_script: "Logon script",
  cmd_autorun: "Command Processor AutoRun",
};

// Hiding Microsoft-signed entries must not hide a signed program used to run
// something else: script hosts and system tools that run arbitrary commands
// are always shown, so are shortcuts (their real target is not verified) and
// WMI consumers, and outside service-like entries anything passing
// arguments. Only Microsoft's own signer names count.
const microsoftSigners = new Set(["Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher", "Microsoft Windows Hardware Compatibility Publisher", "Microsoft Windows Production PCA 2011"]);
const runsAnything = new Set(["cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "forfiles.exe", "hh.exe", "cmstp.exe", "odbcconf.exe", "msxsl.exe", "scriptrunner.exe", "curl.exe", "conhost.exe", "explorer.exe", "pcalua.exe", "mavinject.exe", "control.exe", "ieexec.exe", "presentationhost.exe", "infdefaultinstall.exe", "msdt.exe", "wsl.exe", "bash.exe", "ftp.exe", "xwizard.exe", "dnscmd.exe", "esentutl.exe", "expand.exe", "extrac32.exe", "makecab.exe", "replace.exe", "sc.exe", "reg.exe", "net.exe", "net1.exe", "at.exe", "dfsvc.exe", "atbroker.exe"]);
const serviceLike = new Set(["service", "driver", "service_dll", "lsa", "print_monitor", "boot_execute", "appinit", "appcert"]);

function quietMicrosoft(p: PersistenceEntry): boolean {
  if (p.signature?.status !== "valid" || !microsoftSigners.has(p.signature.signer ?? "")) return false;
  if (p.category === "startup_folder" || p.category === "wmi") return false;
  const base = (p.image ?? "").split(/[\\/]/).pop()?.toLowerCase() ?? "";
  if (runsAnything.has(base)) return false;
  return serviceLike.has(p.category) || !p.arguments;
}

function SignatureBadge({ s }: { s?: PersistenceEntry["signature"] }) {
  if (!s) return <span className="text-faint">—</span>;
  if (s.status === "valid")
    return (
      <span>
        <Badge tone="ok">Signed</Badge> <span className="text-muted">{s.signer}</span>
        {s.catalog ? <span className="text-faint"> (catalog)</span> : null}
      </span>
    );
  if (s.status === "unsigned") return <Badge tone="warn">Unsigned</Badge>;
  return (
    <span>
      <Badge tone="danger">{s.status === "invalid" ? "Invalid" : "Error"}</Badge> <Mono className="text-[11px]">{s.error}</Mono>
    </span>
  );
}

export function ActionViewer({ caseId, job, open, onClose, onQueued, source }: { caseId: string; job: EvidenceCollection; open: boolean; onClose: () => void; onQueued: () => void; source?: ActionSource }) {
  const [filter, setFilter] = useState("");
  const [hideMicrosoft, setHideMicrosoft] = useState(true);
  const [target, setTarget] = useState<{ p: ProcessDetail; tree: boolean } | null>(null);
  const q = useQuery({
    queryKey: ["action-result", job.id],
    queryFn: ({ signal }) => get<ActionResult>(source?.fileUrl ?? `/api/v1/cases/${caseId}/collections/${job.id}/file`, signal),
    enabled: open,
    staleTime: Infinity,
  });
  const run = useMutation({
    mutationFn: (action: ResponseAction) => (source ? source.queue(action) : post(`/api/v1/cases/${caseId}/actions`, { device_id: job.device_id, action })),
    onSuccess: onQueued,
  });
  const r = q.data;
  const body = useMemo(() => {
    if (!r) return null;
    if (r.processes)
      return (
        <Table
          columns={["PID", "Parent", "Name", "User", "Started", "Image / command line", "SHA-256", ""]}
          rows={r.processes
            .filter((p) => matches(filter, p.pid, p.name, p.user, p.image, p.command_line, p.sha256))
            .map((p) => [
              p.pid,
              p.parent_pid,
              p.name,
              p.user ?? "",
              p.started_at ? new Date(p.started_at).toLocaleString() : "",
              <div className="max-w-[420px] space-y-0.5">
                <Mono className="block break-all text-[11px]">{p.image}</Mono>
                {p.command_line ? <Mono className="block break-all text-[11px] text-muted">{p.command_line}</Mono> : null}
              </div>,
              p.sha256 ? short(p.sha256) : <span className="text-faint">{p.hash_note}</span>,
              p.can_kill ? (
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setTarget({ p, tree: false })}>
                    Kill
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setTarget({ p, tree: true })}>
                    Kill tree
                  </Button>
                </div>
              ) : null,
            ])}
        />
      );
    if (r.connections)
      return (
        <Table
          columns={["Protocol", "Local", "Remote", "State", "PID", "Process"]}
          rows={r.connections
            .filter((c) => matches(filter, c.local_address, c.remote_address, c.local_port, c.remote_port, c.state, c.pid, c.process))
            .map((c) => [c.protocol, `${c.local_address}:${c.local_port}`, c.remote_address ? `${c.remote_address}:${c.remote_port}` : "", c.state ?? "", c.pid, c.process ?? ""])}
        />
      );
    if (r.services)
      return (
        <Table
          columns={["Name", "State", "Start", "Account", "Image", "SHA-256", "Service DLL"]}
          rows={r.services
            .filter((s) => matches(filter, s.name, s.display_name, s.image, s.account, s.service_dll, s.sha256))
            .map((s) => [
              <div>
                <div>{s.name}</div>
                <div className="text-muted">{s.display_name}</div>
              </div>,
              s.state,
              s.start_type,
              s.account ?? "",
              <Mono className="break-all text-[11px]">{s.binary_path}</Mono>,
              short(s.sha256),
              s.service_dll ? (
                <div>
                  <Mono className="break-all text-[11px]">{s.service_dll}</Mono> {short(s.service_dll_sha256)}
                </div>
              ) : null,
            ])}
        />
      );
    if (r.persistence) {
      const rows = r.persistence.filter((p) => !(hideMicrosoft && quietMicrosoft(p)) && matches(filter, p.category, categories[p.category], p.location, p.name, p.command, p.image, p.sha256, p.signature?.signer, p.user, p.detail));
      return (
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-[12.5px] text-muted">
            <input type="checkbox" className="accent-[var(--accent)]" checked={hideMicrosoft} onChange={(e) => setHideMicrosoft(e.target.checked)} />
            Hide plain Microsoft-signed entries (script hosts, system tools that run commands, shortcuts and entries passing arguments stay visible) — {rows.length} of {r.persistence.length} shown
          </label>
          <Table
            columns={["Type", "Name / location", "Command", "Program", "SHA-256", "Signature"]}
            rows={rows.map((p) => [
              <span>
                {categories[p.category] ?? p.category}
                {p.disabled ? <Badge tone="neutral">disabled</Badge> : null}
              </span>,
              <div className="max-w-[260px] space-y-0.5">
                <div className="break-all text-fg">{p.name}</div>
                <Mono className="block break-all text-[11px] text-muted">{p.location}</Mono>
                {p.user ? <Mono className="block break-all text-[11px] text-faint">{p.user}</Mono> : null}
                {p.detail ? <div className="text-[11.5px] text-faint">{p.detail}</div> : null}
              </div>,
              <Mono className="line-clamp-3 block max-w-[320px] break-all text-[11px]">{p.command}</Mono>,
              <Mono className="block max-w-[260px] break-all text-[11px]">{p.image || "—"}</Mono>,
              p.sha256 ? short(p.sha256) : <span className="text-faint">{p.hash_note ?? "—"}</span>,
              <SignatureBadge s={p.signature} />,
            ])}
          />
        </div>
      );
    }
    if (r.tasks)
      return (
        <Table
          columns={["Task", "State", "Runs as", "Triggers", "Actions", "Author"]}
          rows={r.tasks
            .filter((t) => matches(filter, t.path, t.author, t.user_id, ...(t.actions ?? []).map((a) => `${a.command} ${a.arguments ?? ""}`)))
            .map((t) => [
              <Mono className="break-all text-[11px]">{t.path}</Mono>,
              <span>
                {t.enabled ? "Enabled" : "Disabled"}
                {t.hidden ? <Badge tone="warn">hidden</Badge> : null}
              </span>,
              `${t.user_id ?? ""}${t.run_level ? ` (${t.run_level})` : ""}`,
              (t.triggers ?? []).join(", "),
              <div className="space-y-0.5">
                {(t.actions ?? []).map((a, i) => (
                  <Mono key={i} className="block break-all text-[11px]">
                    {a.command ? `${a.command} ${a.arguments ?? ""}` : `COM ${a.com_class_id}`}
                  </Mono>
                ))}
              </div>,
              t.author ?? "",
            ])}
        />
      );
    if (r.registry) {
      const k = r.registry;
      return (
        <div className="space-y-3">
          <p className="text-[12px] text-muted">
            <Mono>{k.key}</Mono> · last written {k.last_write ? new Date(k.last_write).toLocaleString() : "unknown"}
            {k.backup_privilege ? " · read with the backup privilege" : ""}
          </p>
          <Table
            columns={["Value", "Type", "Data"]}
            rows={k.values
              .filter((v) => matches(filter, v.name, v.data, ...(v.strings ?? [])))
              .map((v) => [v.name || "(Default)", v.type, <Mono className="break-all text-[11px]">{v.data ?? v.strings?.join(" | ") ?? `${v.hex ?? ""}${v.truncated ? "…" : ""}`}</Mono>])}
          />
          {k.subkeys.length ? (
            <Table
              columns={["Subkey", "Last written", ""]}
              rows={k.subkeys
                .filter((s) => matches(filter, s.name))
                .map((s) => [
                  s.name,
                  s.last_write ? new Date(s.last_write).toLocaleString() : "",
                  <Button size="sm" variant="ghost" loading={run.isPending && run.variables?.kind === "registry" && run.variables.key === `${k.key}\\${s.name}`} onClick={() => run.mutate({ kind: "registry", key: `${k.key}\\${s.name}` })}>
                    Read
                  </Button>,
                ])}
            />
          ) : null}
          {k.values_more || k.subkeys_more ? <p className="text-[12px] text-warn">Only the first 1,000 values and subkeys are shown.</p> : null}
        </div>
      );
    }
    if (r.script) {
      const s = r.script;
      return (
        <div className="space-y-3 text-[12.5px]">
          <p className="text-muted">
            <Badge tone={s.outcome === "succeeded" ? "ok" : "danger"}>{s.outcome}</Badge> exit code {s.exit_code ?? "—"} · {new Date(s.started).toLocaleString()} to {new Date(s.finished).toLocaleString()} · script SHA-256 <Mono className="text-[11px]">{s.sha256}</Mono>
            {s.truncated ? " · output truncated" : ""}
          </p>
          {s.arguments && Object.keys(s.arguments).length ? <p className="text-muted">Arguments: {Object.entries(s.arguments).map(([k, v]) => `${k}=${v}`).join(", ")}</p> : null}
          <pre className="max-h-[40vh] overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] whitespace-pre-wrap text-fg">{s.stdout || "(no output)"}</pre>
          {s.stderr ? <pre className="max-h-[20vh] overflow-auto rounded-md border border-danger/30 bg-danger-soft p-3 font-mono text-[12px] whitespace-pre-wrap text-danger">{s.stderr}</pre> : null}
        </div>
      );
    }
    if (r.drop) {
      const d = r.drop;
      return (
        <div className="space-y-1 text-[12.5px]">
          <p>
            <Badge tone={d.outcome === "written" && d.verified ? "ok" : "danger"}>{d.outcome}</Badge> {d.verified ? "verified after writing" : "not verified"}
          </p>
          <p className="text-muted">
            <Mono>{d.path}</Mono> · {d.size} bytes · SHA-256 <Mono className="text-[11px]">{d.sha256}</Mono>
          </p>
          {d.replaced ? (
            <p className="text-warn">
              Replaced a file with SHA-256 <Mono className="text-[11px]">{d.replaced_sha256}</Mono>
            </p>
          ) : null}
        </div>
      );
    }
    if (r.hunt) {
      return (
        <div className="space-y-2">
          <Scanned r={r.hunt} />
          <MatchesTable rows={r.hunt.matches} />
        </div>
      );
    }
    if (r.event_log) {
      const l = r.event_log;
      if (l.outcome !== "ok") return <p className="text-[13px] text-warn">The device could not search this log ({l.outcome.replaceAll("_", " ")}).</p>;
      return (
        <div className="space-y-2">
          {l.more ? <p className="text-[12px] text-muted">The newest {l.events?.length ?? 0} matching events; more matched.</p> : null}
          <Table
            columns={["Time (UTC)", "Level", "Source", "ID", "Message"]}
            rows={(l.events ?? [])
              .filter((ev) => matches(filter, ev.provider, ev.event_id, ev.message, ev.xml))
              .map((ev) => [new Date(ev.time * 1000).toISOString().replace("T", " ").slice(0, 19), ev.level, ev.provider, ev.event_id, <span className="line-clamp-4 block max-w-xl break-words" title={ev.message || ev.xml}>{ev.message || <Mono className="text-[11px]">{ev.xml}</Mono>}</span>])}
          />
        </div>
      );
    }
    if (r.killed)
      return <Table columns={["PID", "Parent", "Name", "Image", "SHA-256", "Outcome"]} rows={r.killed.map((k) => [k.pid, k.parent_pid, k.name, <Mono className="break-all text-[11px]">{k.image}</Mono>, short(k.sha256), <Badge tone={k.outcome === "succeeded" || k.outcome === "exited" ? "ok" : "danger"}>{k.outcome}</Badge>])} />;
    return <p className="text-[13px] text-muted">The result is empty.</p>;
  }, [r, filter, run, hideMicrosoft]);

  return (
    <Modal open={open} onOpenChange={(o) => !o && onClose()} title={job.path} description={`${job.hostname || job.device_id.slice(0, 12)} · ${r ? `device time ${new Date(r.device_time).toLocaleString()}` : ""} · viewing is recorded ${source?.recordedIn ?? "in the custody log"}`} width="max-w-[1200px]">
      {q.isPending ? <Spinner label="Loading result" /> : null}
      {q.isError ? <ErrorNotice error={q.error} retry={() => void q.refetch()} /> : null}
      {run.isError ? <ErrorNotice error={run.error} /> : null}
      {run.isSuccess ? <p className="mb-2 text-[12.5px] text-ok">{source?.queued ?? "Queued; the result appears in the case's evidence list."}</p> : null}
      {r && !r.killed && !r.registry && !r.script && !r.drop && !r.hunt ? <SearchInput value={filter} onChange={setFilter} placeholder="Filter" label="Filter" className="mb-3 max-w-xs" /> : null}
      <div className="max-h-[62vh] overflow-auto">{body}</div>
      {r?.notes?.length ? (
        <details className="mt-3 text-[12px] text-muted">
          <summary>{r.notes.length} notes</summary>
          <ul className="mt-1 list-disc pl-5">
            {r.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </details>
      ) : null}
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(o) => !o && setTarget(null)}
        title={target?.tree ? "Kill process tree" : "Kill process"}
        confirmLabel={target?.tree ? "Kill tree" : "Kill process"}
        danger
        onConfirm={async () => {
          if (!target) return;
          await run.mutateAsync({ kind: "kill", pid: target.p.pid, start: target.p.start ?? "", name: target.p.name, tree: target.tree });
          setTarget(null);
        }}
      >
        <p className="text-[13px] text-fg">
          End <Mono>{target?.p.name}</Mono> (PID {target?.p.pid}){target?.tree ? " and every process it started, children first" : ""} on the device. Each process is hashed before it ends; the result is recorded {source?.actionIn ?? "in the case"}. A process that is protected or has been replaced is not ended.
        </p>
      </ConfirmDialog>
    </Modal>
  );
}
