import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListPlus, Pencil, Radar, Trash2 } from "lucide-react";
import { csrfHeader, del, get, post, put } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Hunt, HuntProblem, Indicator, IOCList } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { ConfirmDialog, Modal } from "../../components/Dialog";
import { TargetPicker, type Targets } from "../../components/TargetPicker";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, Select, Spinner, Tip } from "../../components/ui";
import { CaseChoice, useCaseChoice } from "../LiveResponse";
import { indicatorTypes } from "./matches";

// Indicator hunts (files, processes, network, persistence) and
// saved indicator lists (anyone with the response permission manages them).

const MAX_HUNT_TARGETS = 500;
const textareaClass =
  "min-h-40 w-full rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-faint hover:border-border-strong focus:border-accent focus:outline-none";
const placeholder = `One indicator per line, for example:
44d88612fea8a8f36de82e1278abb02f       (MD5, SHA-1 or SHA-256)
mimikatz*.exe                          (a file or process name)
C:\\Users\\*\\AppData\\Roaming\\upd.exe     (a path; * and %APPDATA% match any text)
203.0.113.7  or  198.51.100.0/24        (a remote address or network)
domain:bad.example  domain:*.bad.example
cmd:-EncodedCommand                    (text in a command line)
CSV lines "type,value" work too.`;

type Parsed = { indicators: Indicator[]; problems: string[] };

/** Parses pasted text on the server (the agent's own rules), shortly after typing stops. */
function useParsed(text: string) {
  const [debounced, setDebounced] = useState(text);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(text), 400);
    return () => clearTimeout(t);
  }, [text]);
  const q = useQuery({
    queryKey: ["ioc-parse", debounced],
    queryFn: () => post<Parsed>("/api/v1/hunts/indicators/parse", { text: debounced }),
    enabled: debounced.trim() !== "",
    staleTime: Infinity,
  });
  // settled: the parse is of the text as it is now, not before the last edit.
  return { ...q, settled: debounced === text && !q.isFetching };
}

export function listText(list: Indicator[]): string {
  return list.map((i) => `${i.type}:${i.value}`).join("\n");
}

function ParsedSummary({ q, text }: { q: ReturnType<typeof useParsed>; text: string }) {
  if (!text.trim()) return null;
  if (q.isFetching && !q.data) return <Spinner label="Reading indicators" />;
  if (q.isError) return <ErrorNotice error={q.error} />;
  if (!q.data) return null;
  const counts = new Map<string, number>();
  for (const i of q.data.indicators) counts.set(i.type, (counts.get(i.type) ?? 0) + 1);
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
        <span className="text-muted">{q.data.indicators.length} indicators:</span>
        {[...counts].map(([t, n]) => (
          <Badge key={t} tone="accent">
            {n} {indicatorTypes[t as Indicator["type"]]}
          </Badge>
        ))}
      </div>
      {q.data.problems.length ? (
        <ul className="space-y-0.5 text-[12px] text-warn">
          {q.data.problems.slice(0, 8).map((p) => (
            <li key={p}>Not understood, left out: {p}</li>
          ))}
          {q.data.problems.length > 8 ? <li>and {q.data.problems.length - 8} more</li> : null}
        </ul>
      ) : null}
    </div>
  );
}

export function NewIndicatorHunt({ initialList }: { initialList?: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const lists = useQuery({ queryKey: ["ioc-lists"], queryFn: ({ signal }) => get<{ lists: IOCList[] }>("/api/v1/ioc-lists", signal) });
  const [targets, setTargets] = useState<Targets>({ devices: [], groups: [] });
  const [text, setText] = useState("");
  const [files, setFiles] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problems, setProblems] = useState<HuntProblem[]>([]);
  const [saving, setSaving] = useState(false);
  const c = useCaseChoice("none");
  const parsed = useParsed(text);
  const ready = parsed.data && text.trim() !== "" && parsed.data.indicators.length > 0 && parsed.settled;

  // A list chosen on the Saved lists tab arrives as ?list=; it is loaded
  // once, so a later refresh of the lists never replaces edits.
  const applied = useRef("");
  useEffect(() => {
    const l = lists.data?.lists.find((x) => x.id === initialList);
    if (l && applied.current !== l.id) {
      applied.current = l.id;
      setText(listText(l.indicators));
    }
  }, [initialList, lists.data]);

  const submit = async () => {
    if (!c.body || !parsed.data) return;
    setBusy(true);
    setError(null);
    setProblems([]);
    try {
      const r = await fetch("/api/v1/hunts/indicators", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", ...csrfHeader() },
        credentials: "same-origin",
        body: JSON.stringify({ ...c.body, ...targets, indicators: parsed.data.indicators, files }),
      });
      const body = (await r.json().catch(() => ({}))) as Hunt & { error?: string; problems?: HuntProblem[] };
      if (!r.ok) {
        setProblems(body.problems ?? []);
        setError(new Error(body.error ?? "The hunt could not start."));
        return;
      }
      void qc.invalidateQueries({ queryKey: ["hunts"] });
      navigate(`/hunting/${body.id}`);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="New indicator hunt" className="mb-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div>
          <p className="mb-2 text-[12.5px] text-muted">Devices and groups (up to {MAX_HUNT_TARGETS} devices including group members)</p>
          <TargetPicker value={targets} onChange={setTargets} include={(d) => d.os === "windows"} height="max-h-72" max={MAX_HUNT_TARGETS} />
        </div>
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] font-medium text-fg">Indicators</span>
            <span className="flex-1" />
            <Select
              value=""
              onChange={(e) => {
                const l = lists.data?.lists.find((x) => x.id === e.target.value);
                if (l) setText(listText(l.indicators));
              }}
              aria-label="Load a saved list"
              disabled={!lists.data?.lists.length}
            >
              <option value="">{lists.data?.lists.length ? "Load a saved list…" : "No saved lists"}</option>
              {(lists.data?.lists ?? []).map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name} ({l.indicators.length})
                </option>
              ))}
            </Select>
          </div>
          <textarea className={textareaClass} value={text} onChange={(e) => setText(e.target.value)} placeholder={placeholder} spellCheck={false} maxLength={400_000} aria-label="Indicators" />
          <ParsedSummary q={parsed} text={text} />
          <label className="flex items-start gap-2 text-[12.5px] text-fg">
            <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={files} onChange={(e) => setFiles(e.target.checked)} />
            <span>
              Search files in common locations
              <span className="block text-[12px] text-muted">
                Users' Downloads, Desktop and AppData, ProgramData, Windows\Temp, Public and the root of each fixed drive. With hashes in the list every file up to 100 MB is hashed: this can take up to 15 minutes per device. Processes,
                connections, the DNS cache and autostart entries are always searched.
              </span>
            </span>
          </label>
          <CaseChoice open allowNone {...c.props} noneNote="The search is recorded in the audit log only. Each device's result is kept for 24 hours after it answers." note="Each device's result is stored in the case as hashed evidence, recorded in its custody log." />
          {error ? <ErrorNotice error={error} /> : null}
          {problems.length ? (
            <ul className="space-y-0.5 text-[12.5px] text-warn">
              {problems.map((p) => (
                <li key={p.device_id}>
                  {p.hostname}: {p.reason}
                </li>
              ))}
            </ul>
          ) : null}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-[12px] text-faint">Up to 1,000 matches per device. Devices that are offline answer when they come back, for up to 7 days.</span>
            <span className="flex gap-2">
              <Button icon={<ListPlus className="size-4" />} disabled={!ready} onClick={() => setSaving(true)}>
                Save as list
              </Button>
              <Button variant="primary" icon={<Radar className="size-4" />} loading={busy} disabled={!c.body || !ready || targets.devices.length + targets.groups.length === 0} onClick={() => void submit()}>
                Hunt
              </Button>
            </span>
          </div>
        </div>
      </div>
      {saving && parsed.data ? <ListEditor initial={{ name: "", indicators: parsed.data.indicators }} onClose={() => setSaving(false)} /> : null}
    </Panel>
  );
}

/** Creates a list (no id) or edits one. */
function ListEditor({ initial, onClose }: { initial: { id?: string; name: string; indicators: Indicator[] }; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(initial.name);
  const [text, setText] = useState(listText(initial.indicators));
  const parsed = useParsed(text);
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), indicators: parsed.data?.indicators ?? [] };
      return initial.id ? put<IOCList>(`/api/v1/ioc-lists/${initial.id}`, body) : post<IOCList>("/api/v1/ioc-lists", body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["ioc-lists"] });
      onClose();
    },
  });
  const ok = name.trim() !== "" && !!parsed.data?.indicators.length && parsed.settled;
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={initial.id ? "Edit indicator list" : "Save indicator list"}
      description="Anyone with the response permission can use, change and delete saved lists. Hunts keep their own copy of the indicators."
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={!ok} onClick={() => save.mutate()}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} aria-label="List name" />
        </Field>
        <textarea className={textareaClass} value={text} onChange={(e) => setText(e.target.value)} placeholder={placeholder} spellCheck={false} maxLength={400_000} aria-label="Indicators" />
        <ParsedSummary q={parsed} text={text} />
        {save.isError ? <ErrorNotice error={save.error} /> : null}
      </div>
    </Modal>
  );
}

export function SavedLists({ onUse }: { onUse: (id: string) => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ioc-lists"], queryFn: ({ signal }) => get<{ lists: IOCList[] }>("/api/v1/ioc-lists", signal) });
  const [editing, setEditing] = useState<{ id?: string; name: string; indicators: Indicator[] } | null>(null);
  const [deleting, setDeleting] = useState<IOCList | null>(null);
  const remove = useMutation({ mutationFn: (id: string) => del(`/api/v1/ioc-lists/${id}`), onSettled: () => void qc.invalidateQueries({ queryKey: ["ioc-lists"] }) });
  const columns: Column<IOCList>[] = useMemo(
    () => [
      { key: "name", header: "List", sort: (l) => l.name.toLowerCase(), cell: (l) => <span className="font-medium text-fg">{l.name}</span> },
      { key: "count", header: "Indicators", sort: (l) => l.indicators.length, cell: (l) => <span className="text-muted tabular-nums">{l.indicators.length}</span> },
      {
        key: "updated",
        header: "Changed",
        sort: (l) => l.updated_at,
        cell: (l) => (
          <Tip label={`Created ${absoluteTime(l.created_at)} by ${l.created_by}`}>
            <span className="text-muted">
              {relativeTime(l.updated_at)} · {l.updated_by}
            </span>
          </Tip>
        ),
      },
      {
        key: "actions",
        header: "",
        className: "text-right",
        cell: (l) => (
          <span className="flex justify-end gap-1.5">
            <Button size="sm" icon={<Radar className="size-3.5" />} onClick={() => onUse(l.id)}>
              Hunt
            </Button>
            <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(l)}>
              Edit
            </Button>
            <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} onClick={() => setDeleting(l)}>
              Delete
            </Button>
          </span>
        ),
      },
    ],
    [onUse],
  );
  return (
    <Panel
      title="Saved indicator lists"
      bodyClassName="p-0"
      actions={
        <Button size="sm" icon={<ListPlus className="size-3.5" />} onClick={() => setEditing({ name: "", indicators: [] })}>
          New list
        </Button>
      }
    >
      {q.isPending ? (
        <div className="p-6">
          <Spinner label="Loading lists" />
        </div>
      ) : q.isError ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : (
        <DataTable columns={columns} rows={q.data.lists} rowKey={(l) => l.id} empty={<EmptyState title="No saved lists">Save indicators you hunt for often, such as a threat report's indicators.</EmptyState>} />
      )}
      {remove.isError ? <ErrorNotice error={remove.error} /> : null}
      {editing ? <ListEditor initial={editing} onClose={() => setEditing(null)} /> : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete indicator list"
        confirmLabel="Delete"
        danger
        onConfirm={async () => {
          if (deleting) await remove.mutateAsync(deleting.id);
          setDeleting(null);
        }}
      >
        <p className="text-[13px] text-fg">Delete “{deleting?.name}”? Hunts that used it keep their own copy of the indicators.</p>
      </ConfirmDialog>
    </Panel>
  );
}
