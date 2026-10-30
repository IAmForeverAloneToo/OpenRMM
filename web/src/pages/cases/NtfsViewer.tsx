import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import { get } from "../../lib/api";
import { bytes } from "../../lib/format";
import type { EvidenceCollection, NtfsManifest, NtfsPage } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Mono, Segmented, Select, Spinner } from "../../components/ui";

// Browses an NTFS package's timelines on the server: the device parsed
// $MFT and the USN change journal into CSV, and the server pages through
// them with filters. Opening the package and downloading a CSV are recorded
// in the custody log (or, for console results, as session activity).

const reasons = ["FileCreate", "FileDelete", "RenameOldName", "RenameNewName", "DataOverwrite", "DataExtend", "DataTruncation", "SecurityChange", "BasicInfoChange", "StreamChange", "Close"];

type Table = "mft" | "usn";

// The columns shown; the CSV download has all of them.
const shown: Record<Table, { label: string; col: string }[]> = {
  mft: [
    { label: "Path", col: "path" },
    { label: "Size", col: "FileSize" },
    { label: "State", col: "InUse" },
    { label: "Created (SI)", col: "Created0x10" },
    { label: "Modified (SI)", col: "LastModified0x10" },
    { label: "Record changed (SI)", col: "LastRecordChange0x10" },
    { label: "Created (FN)", col: "Created0x30" },
    { label: "Modified (FN)", col: "LastModified0x30" },
    { label: "Entry", col: "EntryNumber" },
  ],
  usn: [
    { label: "Time", col: "UpdateTimestamp" },
    { label: "Path", col: "path" },
    { label: "Reasons", col: "UpdateReasons" },
    { label: "Entry", col: "EntryNumber" },
    { label: "USN", col: "UpdateSequenceNumber" },
  ],
};

const cell = "border-b border-border px-2 py-1 align-top text-[12px] whitespace-nowrap";
const head = "border-b border-border-strong px-2 py-1.5 text-left text-[11.5px] font-medium text-muted whitespace-nowrap";

// datetime-local text (local time) to RFC 3339 UTC, or "" when empty.
function instant(v: string): string {
  if (!v) return "";
  const t = new Date(v);
  return isNaN(t.getTime()) ? "" : t.toISOString();
}

export function NtfsViewer({ base, job, open, onClose, recordedIn }: { base: string; job: EvidenceCollection; open: boolean; onClose: () => void; recordedIn?: string }) {
  const manifest = useQuery({ queryKey: ["ntfs-manifest", base], queryFn: ({ signal }) => get<NtfsManifest>(base, signal), enabled: open, staleTime: Infinity });
  const volumes = (manifest.data?.volumes ?? []).filter((v) => !v.error);
  const [volume, setVolume] = useState("");
  useEffect(() => {
    if (!volume && volumes[0]) setVolume(volumes[0].volume[0] ?? "");
  }, [volume, volumes]);
  const [table, setTable] = useState<Table>("mft");
  const [text, setText] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [deleted, setDeleted] = useState(false);
  const [reason, setReason] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 100;
  // A changed filter starts again at the first page.
  useEffect(() => setOffset(0), [volume, table, text, from, to, deleted, reason]);
  const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
  if (text) params.set("q", text);
  if (instant(from)) params.set("from", instant(from));
  if (instant(to)) params.set("to", instant(to));
  if (deleted) params.set("deleted", "1");
  if (table === "usn" && reason) params.set("reason", reason);
  const url = `${base}/${volume}/${table}`;
  const page = useQuery({
    queryKey: ["ntfs-page", url, params.toString()],
    queryFn: ({ signal }) => get<NtfsPage>(`${url}?${params.toString()}`, signal),
    enabled: open && !!volume,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  });
  const p = page.data;
  const index = (col: string) => p?.columns.indexOf(col) ?? -1;
  const value = (row: string[], col: string) => {
    if (col === "path") {
      const name = row[index(table === "mft" ? "FileName" : "Name")] ?? "";
      const parent = row[index("ParentPath")] ?? "";
      return parent.endsWith("\\") ? parent + name : `${parent}\\${name}`;
    }
    if (col === "InUse") return row[index(col)] === "true" ? "in use" : "deleted";
    if (col === "FileSize") return bytes(Number(row[index(col)]));
    return row[index(col)] ?? "";
  };
  const current = volumes.find((v) => v.volume[0] === volume);
  return (
    <Modal open={open} onOpenChange={(o) => !o && onClose()} title="NTFS artifacts" description={`${job.hostname || job.device_id.slice(0, 12)} · opening and CSV downloads are recorded ${recordedIn ?? "in the custody log"}`} width="max-w-[1300px]">
      {manifest.isPending ? <Spinner label="Opening the package" /> : null}
      {manifest.isError ? <ErrorNotice error={manifest.error} retry={() => void manifest.refetch()} /> : null}
      {manifest.data ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            {volumes.length > 1 ? (
              <Field label="Drive">
                <Select value={volume} onChange={(e) => setVolume(e.target.value)} aria-label="Drive">
                  {volumes.map((v) => (
                    <option key={v.volume} value={v.volume[0]}>
                      {v.volume}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : null}
            <Segmented
              label="Timeline"
              value={table}
              onChange={setTable}
              options={[
                { value: "mft", label: `$MFT (${(current?.mft_rows ?? 0).toLocaleString()})` },
                { value: "usn", label: `Change journal (${(current?.usn_rows ?? 0).toLocaleString()})` },
              ]}
            />
            <Field label="Path contains">
              <Input value={text} onChange={(e) => setText(e.target.value)} placeholder="\Users\ or .exe" maxLength={400} spellCheck={false} aria-label="Path contains" />
            </Field>
            <Field label="From (local time)">
              <Input type="datetime-local" step={1} value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
            </Field>
            <Field label="To">
              <Input type="datetime-local" step={1} value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
            </Field>
            {table === "usn" ? (
              <Field label="Reason">
                <Select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason">
                  <option value="">Any</option>
                  {reasons.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : null}
            <label className="flex items-center gap-1.5 pb-2 text-[12.5px] text-fg">
              <input type="checkbox" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} /> Deleted only
            </label>
            <a href={`${url}?format=csv`} download className="mb-1 inline-flex items-center gap-1 text-[12.5px] text-accent hover:underline">
              <Download className="size-3.5" /> {volume}: {table === "mft" ? "mft.csv" : "usn.csv"}
            </a>
          </div>
          {current ? (
            <p className="text-[12px] text-muted">
              {current.method === "snapshot" ? <Badge tone="ok">Shadow copy</Badge> : <Badge tone="warn">Read live</Badge>} Times are UTC; SI is $STANDARD_INFORMATION, FN is $FILE_NAME (SI earlier than FN can mean timestomping). {current.damaged ? `${current.damaged} damaged records were skipped. ` : ""}
              {current.excluded ? `${current.excluded} rows for OpenRMM's own files are left out. ` : ""}
              {current.files.map((f) => `${f.name.split("/")[1]} ${bytes(f.size)}`).join(" · ")}
            </p>
          ) : null}
          {page.isError ? <ErrorNotice error={page.error} retry={() => void page.refetch()} /> : null}
          <div className="max-h-[56vh] overflow-auto">
            {p ? (
              <table className="w-full border-collapse">
                <thead className="sticky top-0 bg-surface">
                  <tr>
                    {shown[table].map((c) => (
                      <th key={c.col} className={head}>
                        {c.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {p.rows.map((row, i) => (
                    <tr key={i}>
                      {shown[table].map((c) => (
                        <td key={c.col} className={cell}>
                          {c.col === "path" ? <Mono className="text-[11.5px]">{value(row, c.col)}</Mono> : value(row, c.col)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : page.isPending && volume ? (
              <Spinner label="Reading the timeline" />
            ) : null}
            {p && p.rows.length === 0 ? <p className="p-3 text-[12.5px] text-muted">No rows match.</p> : null}
          </div>
          <div className="flex items-center justify-end gap-2 text-[12px] text-muted">
            {page.isFetching ? <Spinner label="Reading" /> : null}
            <span>{p && p.rows.length ? `Rows ${offset + 1}–${offset + p.rows.length}${p.more ? " of more" : ""}` : ""}</span>
            <Button size="sm" variant="ghost" icon={<ChevronLeft className="size-3.5" />} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              Previous
            </Button>
            <Button size="sm" variant="ghost" icon={<ChevronRight className="size-3.5" />} disabled={!p?.more} onClick={() => setOffset(offset + limit)}>
              Next
            </Button>
          </div>
          {manifest.data.volumes.some((v) => v.error) ? (
            <p className="text-[12px] text-warn">
              {manifest.data.volumes
                .filter((v) => v.error)
                .map((v) => `${v.volume} not read: ${v.error}`)
                .join(" · ")}
            </p>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}
