import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, FileSearch } from "lucide-react";
import { csrfHeader, get } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Hunt, HuntProblem, HuntSummary } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { DataTable, type Column } from "../../components/DataTable";
import { TargetPicker, type Targets } from "../../components/TargetPicker";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, Select, Spinner, Tip } from "../../components/ui";
import { CaseChoice, useCaseChoice } from "../LiveResponse";
import { NewIndicatorHunt, SavedLists } from "./IndicatorHunt";

// Fleet log search. One search sends the same event log filter to
// every chosen device; offline devices answer when they return (up to 7 days).
// The page also runs indicator hunts and keeps saved indicator lists.

const MAX_HUNT_TARGETS = 500;
const ranges = [
  { value: "3600", label: "Last hour" },
  { value: "86400", label: "Last 24 hours" },
  { value: "604800", label: "Last 7 days" },
  { value: "2678400", label: "Last 31 days" },
];
export const commonChannels = [
  "Security",
  "System",
  "Application",
  "Windows PowerShell",
  "Microsoft-Windows-PowerShell/Operational",
  "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-TaskScheduler/Operational",
  "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
  "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
  "Microsoft-Windows-WinRM/Operational",
  "Microsoft-Windows-Windows Defender/Operational",
  "Microsoft-Windows-Bits-Client/Operational",
];

function NewLogSearch() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [targets, setTargets] = useState<Targets>({ devices: [], groups: [] });
  const [channel, setChannel] = useState("Security");
  const [range, setRange] = useState("86400");
  const [level, setLevel] = useState("-1");
  const [eventId, setEventId] = useState("");
  const [provider, setProvider] = useState("");
  const [xpath, setXpath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problems, setProblems] = useState<HuntProblem[]>([]);
  const c = useCaseChoice("none");

  const submit = async () => {
    const id = eventId.trim() === "" ? -1 : Number(eventId);
    if (!Number.isInteger(id) || id < -1 || id > 65535) {
      setError(new Error("Event ID must be a number from 0 to 65535."));
      return;
    }
    if (!c.body) return;
    setBusy(true);
    setError(null);
    setProblems([]);
    try {
      const to = Math.floor(Date.now() / 1000);
      const filter = { channel: channel.trim(), from: to - Number(range), to, level: Number(level), provider: provider.trim(), event_id: id, xpath: xpath.trim() };
      const r = await fetch("/api/v1/hunts/log-search", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", ...csrfHeader() },
        credentials: "same-origin",
        body: JSON.stringify({ ...c.body, ...targets, filter }),
      });
      const body = (await r.json().catch(() => ({}))) as Hunt & { error?: string; problems?: HuntProblem[] };
      if (!r.ok) {
        setProblems(body.problems ?? []);
        setError(new Error(body.error ?? "The search could not start."));
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
    <Panel title="New log search" className="mb-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div>
          <p className="mb-2 text-[12.5px] text-muted">Devices and groups (up to {MAX_HUNT_TARGETS} devices including group members)</p>
          <TargetPicker value={targets} onChange={setTargets} include={(d) => d.os === "windows"} height="max-h-72" max={MAX_HUNT_TARGETS} />
        </div>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Log">
              <Input value={channel} onChange={(e) => setChannel(e.target.value)} list="hunt-channels" maxLength={256} spellCheck={false} aria-label="Log" />
              <datalist id="hunt-channels">
                {commonChannels.map((c) => (
                  <option key={c} value={c} />
                ))}
              </datalist>
            </Field>
            <Field label="Time range">
              <Select className="w-full" value={range} onChange={(e) => setRange(e.target.value)} aria-label="Time range">
                {ranges.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Level">
              <Select className="w-full" value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
                <option value="-1">Any level</option>
                <option value="1">Critical</option>
                <option value="2">Error</option>
                <option value="3">Warning</option>
                <option value="4">Information</option>
                <option value="5">Verbose</option>
              </Select>
            </Field>
            <Field label="Event ID">
              <Input value={eventId} onChange={(e) => setEventId(e.target.value)} placeholder="Any" inputMode="numeric" maxLength={5} aria-label="Event ID" />
            </Field>
          </div>
          <Field label="Provider">
            <Input value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="Any" maxLength={256} aria-label="Provider" />
          </Field>
          <Field label="XPath filter">
            <Input value={xpath} onChange={(e) => setXpath(e.target.value)} placeholder="*[EventData[Data[@Name='LogonType']='10']]" className="font-mono text-[12.5px]" maxLength={4096} spellCheck={false} aria-label="XPath filter" />
          </Field>
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
          <div className="flex items-center justify-between gap-3">
            <span className="text-[12px] text-faint">The 250 newest matching events per device. Devices that are offline answer when they come back, for up to 7 days.</span>
            <Button variant="primary" icon={<FileSearch className="size-4" />} loading={busy} disabled={!c.body || targets.devices.length + targets.groups.length === 0 || !channel.trim()} onClick={() => void submit()}>
              Search
            </Button>
          </div>
        </div>
      </div>
    </Panel>
  );
}

const tabs = [
  { value: "logs", label: "Log search" },
  { value: "indicators", label: "Indicators" },
  { value: "lists", label: "Saved lists" },
] as const;

export function HuntingPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = (tabs.find((t) => t.value === params.get("tab"))?.value ?? "logs") as (typeof tabs)[number]["value"];
  const setTab = (t: string, extra: Record<string, string> = {}) => setParams(t === "logs" ? extra : { tab: t, ...extra }, { replace: true });
  const q = useQuery({ queryKey: ["hunts"], queryFn: ({ signal }) => get<{ hunts: HuntSummary[] }>("/api/v1/hunts", signal), refetchInterval: 15_000 });
  const columns: Column<HuntSummary>[] = [
    {
      key: "channel",
      header: "Search",
      sort: (h) => (h.kind === "indicators" ? `~${h.indicators}` : h.channel),
      cell: (h) =>
        h.kind === "indicators" ? (
          <span className="font-medium text-fg">
            {h.indicators} {h.indicators === 1 ? "indicator" : "indicators"}
            <span className="font-normal text-muted">{h.files ? " · with files" : ""}</span>
          </span>
        ) : (
          <span className="font-medium text-fg">
            <span className="font-normal text-muted">Log </span>
            {h.channel}
          </span>
        ),
    },
    {
      key: "progress",
      header: "Devices",
      sort: (h) => h.finished,
      cell: (h) => (
        <span className="flex items-center gap-2">
          <span className="text-muted tabular-nums">
            {h.finished} of {h.targets} answered
          </span>
          {h.cancelled_at ? <Badge tone="neutral">Cancelled</Badge> : h.waiting ? <Badge tone="info" dot>Waiting</Badge> : <Badge tone="ok">Done</Badge>}
          {h.problems ? <Badge tone="warn">{h.problems} not searched</Badge> : null}
        </span>
      ),
    },
    { key: "case", header: "Case", cell: (h) => (h.case_id === "00000000000000000000000000000000" ? <span className="text-faint">None (kept 24 hours)</span> : <span className="text-muted">Recorded to a case</span>) },
    {
      key: "created",
      header: "Started",
      sort: (h) => h.created_at,
      headerClassName: "text-right",
      className: "text-right",
      cell: (h) => (
        <Tip label={absoluteTime(h.created_at)}>
          <span className="text-muted">
            {relativeTime(h.created_at)} · {h.actor}
          </span>
        </Tip>
      ),
    },
  ];
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Hunting" subtitle="Search event logs, files, processes, network activity and autostart entries across many devices at once." />
      <div className="mb-5 flex gap-1 border-b border-border" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.value}
            type="button"
            role="tab"
            aria-selected={tab === t.value}
            onClick={() => setTab(t.value)}
            className={`-mb-px border-b-2 px-3 py-2 text-[13px] font-medium ${tab === t.value ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "logs" ? <NewLogSearch /> : null}
      {tab === "indicators" ? <NewIndicatorHunt initialList={params.get("list") ?? undefined} /> : null}
      {tab === "lists" ? (
        <div className="mb-5">
          <SavedLists onUse={(id) => setTab("indicators", { list: id })} />
        </div>
      ) : null}
      <Panel title="Searches" bodyClassName="p-0">
        {q.isPending ? (
          <div className="p-6">
            <Spinner label="Loading searches" />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorNotice error={q.error} retry={() => void q.refetch()} />
          </div>
        ) : (
          <DataTable
            columns={columns}
            rows={q.data.hunts}
            rowKey={(h) => h.id}
            onRowClick={(h) => navigate(`/hunting/${h.id}`)}
            empty={<EmptyState icon={<Crosshair />} title="No searches yet">Choose devices and a filter or indicators above to search them.</EmptyState>}
          />
        )}
      </Panel>
    </div>
  );
}
