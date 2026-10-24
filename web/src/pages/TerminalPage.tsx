import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ArrowLeft, Briefcase, Square } from "lucide-react";
import { csrfHeader, get, postKeepalive } from "../lib/api";
import type { DeviceDetail, TerminalView } from "../lib/types";
import { Modal } from "../components/Dialog";
import { Badge, Button, Tip, cx } from "../components/ui";
import { AttachCase, LiveConsole } from "./LiveResponse";

const endMessages: Record<string, string> = {
  idle: "Ended after too long without input (15 minutes; 2 on agents before release 25).",
  expired: "Reached the session time limit (2 hours; 15 minutes on agents before release 25).",
  administrator_stopped: "You ended the session.",
  agent_disconnected: "The agent disconnected.",
  viewer_disconnected: "The browser connection expired.",
  agent_changed: "The agent restarted or its identity changed.",
  agent_reset: "The agent reset the shell.",
  output_limit: "Too much unread output; the session ended.",
  sequence_error: "The stream went out of order; ended without replaying input.",
  authorization_ended: "Your access to this device changed.",
  audit_failed: "The session could not be recorded in the audit log.",
  server_stopped: "The server stopped.",
  recording_failed: "The transcript could not be written, so the recorded session ended. Check the evidence volume.",
  failed: "The Windows shell failed or terminal access was turned off on the device.",
  ended: "The PowerShell session exited.",
};

const MAX_INPUT = 4096;
const encoder = new TextEncoder();
// Hidden control characters other than tab and line breaks are refused in
// pasted text, so a paste cannot carry escape sequences or Ctrl chords.
const hiddenControl = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/;

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function TerminalPage() {
  const { id: deviceId = "", session = "" } = useParams();
  const navigate = useNavigate();
  const host = useRef<HTMLDivElement>(null);
  const control = useRef<{ end: (message: string) => void; send: (text: string) => boolean } | null>(null);
  const [state, setState] = useState<"connecting" | "active" | "ended">("connecting");
  const [ended, setEnded] = useState("");
  const [expires, setExpires] = useState(0);
  const [caseId, setCaseId] = useState("");
  const [notice, setNotice] = useState("");
  const [paste, setPaste] = useState<string | null>(null);
  const [attaching, setAttaching] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const device = useQuery({ queryKey: ["device", deviceId], queryFn: ({ signal }) => get<DeviceDetail>(`/api/v1/devices/${deviceId}`, signal), staleTime: 60_000 });

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const base = `/api/v1/terminal/${encodeURIComponent(session)}`;
    const term = new Terminal({
      cols: 100,
      rows: 30,
      scrollback: 1000,
      cursorBlink: true,
      disableStdin: true,
      fontFamily: '"Cascadia Mono", Consolas, ui-monospace, monospace',
      fontSize: 14,
      theme: { background: "#0b0e13", foreground: "#e6e9ef", cursor: cssVar("--accent") || "#6d8bff", selectionBackground: "#2c3a5c" },
    });
    term.open(el);
    let offset = 0;
    let sequence = 0;
    let pending = "";
    let sending = false;
    let scheduled = false;
    let stopped = false;
    let active = false;
    let lastPoll = performance.now();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const end = (message: string, notifyServer = true) => {
      if (stopped) return;
      stopped = true;
      active = false;
      term.options.disableStdin = true;
      if (timer) clearTimeout(timer);
      if (notifyServer) postKeepalive(`${base}/stop`);
      setState("ended");
      setEnded(message);
    };

    const flush = async () => {
      scheduled = false;
      if (sending || !pending || stopped) return;
      sending = true;
      const data = pending;
      pending = "";
      try {
        const r = await fetch(`${base}/input`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...csrfHeader() },
          body: JSON.stringify({ sequence: ++sequence, data }),
          credentials: "same-origin",
          signal: AbortSignal.timeout(3000),
        });
        if (!r.ok) end("Input could not be delivered. The terminal ended without retrying it.");
      } catch {
        end("The connection dropped while sending input. Input is never retried.");
      } finally {
        sending = false;
        if (pending && !stopped) void flush();
      }
    };

    const send = (text: string): boolean => {
      if (!active || stopped || !text) return false;
      if (encoder.encode(pending + text).length > MAX_INPUT) {
        setNotice("Input queue is full (4 KB). Wait a moment before sending more.");
        return false;
      }
      setNotice("");
      pending += text;
      if (!scheduled) {
        scheduled = true;
        setTimeout(() => void flush(), 25);
      }
      return true;
    };
    control.current = { end, send };

    const poll = async () => {
      if (stopped) return;
      try {
        const r = await fetch(`${base}/output?after=${offset}`, { credentials: "same-origin", cache: "no-store", signal: AbortSignal.timeout(3000) });
        if (stopped) return;
        if (r.status === 410) {
          const body = (await r.json().catch(() => ({}))) as { reason?: string };
          end(endMessages[body.reason ?? ""] ?? "The session ended.", false);
          return;
        }
        if (!r.ok) {
          end(r.status === 401 ? "Your sign-in expired." : r.status === 403 ? "Your account no longer has access." : "The session is no longer available.", r.status !== 404);
          return;
        }
        const v = (await r.json()) as TerminalView;
        const bytes = v.output ? Uint8Array.from(atob(v.output), (c) => c.charCodeAt(0)) : new Uint8Array();
        if (!["starting", "active"].includes(v.state) || bytes.length > 16384 || v.offset !== offset + bytes.length) {
          end("The output stream changed unexpectedly; the terminal ended without replay.");
          return;
        }
        if (bytes.length) term.write(bytes);
        offset = v.offset;
        lastPoll = performance.now();
        setExpires(v.expires);
        setCaseId(v.case_id ?? "");
        if (v.state === "active" && !active) {
          active = true;
          term.options.disableStdin = false;
          setState("active");
          term.focus();
        }
        if (!sending && !pending) sequence = Math.max(sequence, v.input_sequence);
        timer = setTimeout(() => void poll(), bytes.length ? 40 : 250);
      } catch {
        end("The connection to the server was lost.");
      }
    };

    const onData = term.onData((data) => {
      send(data);
    });
    // Ctrl+C copies when text is selected; otherwise it interrupts the shell.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === "keydown" && e.ctrlKey && (e.key === "c" || e.key === "C") && term.hasSelection()) {
        void navigator.clipboard.writeText(term.getSelection()).catch(() => undefined);
        term.clearSelection();
        return false;
      }
      return true;
    });
    const onPaste = (e: ClipboardEvent) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      const text = e.clipboardData?.getData("text") ?? "";
      if (text && active && !stopped) setPaste(text);
    };
    el.addEventListener("paste", onPaste, true);
    const stall = setInterval(() => {
      if (!stopped && performance.now() - lastPoll > 5000) end("The terminal stopped responding. Input stopped without retry.");
    }, 1000);
    const onHide = () => end("Disconnected.");
    window.addEventListener("pagehide", onHide);
    void poll();

    return () => {
      window.removeEventListener("pagehide", onHide);
      el.removeEventListener("paste", onPaste, true);
      clearInterval(stall);
      onData.dispose();
      end("Disconnected.");
      control.current = null;
      term.dispose();
    };
  }, [session]);

  const remaining = expires ? Math.max(0, expires - Math.floor(now / 1000)) : 0;
  const pasteError = paste !== null && (hiddenControl.test(paste) ? "The pasted text contains hidden control characters and can't be sent." : encoder.encode(paste).length > MAX_INPUT ? "Pasted text is larger than 4 KB." : "");
  const normalized = (paste ?? "").replace(/\r\n?/g, "\n").replace(/\n/g, "\r");

  return (
    <div className="flex h-screen flex-col bg-bg">
      <header className="flex h-13 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
        <Link to={caseId ? `/cases/${caseId}` : `/devices/${deviceId}`} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-muted hover:bg-surface-2 hover:text-fg">
          <ArrowLeft className="size-4" /> Back
        </Link>
        <div className="h-5 w-px bg-border" />
        <span className="font-semibold text-fg">{device.data?.device.hostname ?? "Device"}</span>
        <span className="text-muted">Live response</span>
        <Badge tone={state === "active" ? "ok" : state === "ended" ? "neutral" : "info"} dot>
          {state === "active" ? "Connected" : state === "ended" ? "Ended" : "Connecting"}
        </Badge>
        {caseId ? (
          <Tip label="Every input and output is recorded with its time and stored as case evidence when the session ends.">
            <Link to={`/cases/${caseId}`} className="inline-flex">
              <Badge tone="warn" dot>
                Recorded
              </Badge>
            </Link>
          </Tip>
        ) : state !== "connecting" ? (
          <>
            <Tip label="The console is not stored by OpenRMM; start, end and response commands are audited, and command results are kept 24 hours.">
              <span className="text-[12px] text-faint">Not recorded</span>
            </Tip>
            {state === "active" ? (
              <Button size="sm" variant="ghost" icon={<Briefcase className="size-3.5" />} onClick={() => setAttaching(true)}>
                Attach to case
              </Button>
            ) : null}
          </>
        ) : null}
        <div className="flex-1" />
        {state === "active" && expires ? (
          <span className={cx("text-[12px] tabular-nums", remaining < 120 ? "text-warn" : "text-muted")}>
            Ends in {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, "0")}
          </span>
        ) : null}
        {state !== "ended" ? (
          <Button variant="danger" size="sm" icon={<Square className="size-3.5" />} onClick={() => control.current?.end("You ended the session.")}>
            End session
          </Button>
        ) : (
          <Button size="sm" onClick={() => navigate(caseId ? `/cases/${caseId}` : `/devices/${deviceId}`)}>
            {caseId ? "Back to case" : "Back to device"}
          </Button>
        )}
      </header>
      {ended ? <div className="border-b border-border bg-surface-2 px-4 py-2 text-[13px] text-fg">Session ended — {ended}</div> : null}
      {notice ? <div className="border-b border-border bg-warn-soft px-4 py-2 text-[13px] text-warn">{notice}</div> : null}
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-auto p-4 2xl:flex-row 2xl:items-start">
        <div className={cx("w-fit max-w-full shrink-0 overflow-auto rounded-lg border border-border bg-[#0b0e13] p-2", state === "ended" && "opacity-70")}>
          <div ref={host} />
        </div>
        <div className="min-w-0 flex-1 2xl:max-w-[640px]">
          <LiveConsole session={session} caseId={caseId} active={state === "active"} />
        </div>
      </div>
      <AttachCase session={session} open={attaching} onOpenChange={setAttaching} onAttached={setCaseId} />
      <Modal
        open={paste !== null}
        onOpenChange={(o) => !o && setPaste(null)}
        title="Send pasted text?"
        description="Pasted text is shown here first so nothing runs unexpectedly."
        width="max-w-2xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setPaste(null)}>
              Cancel
            </Button>
            <Button disabled={!!pasteError} onClick={() => control.current?.send(normalized) && setPaste(null)}>
              Send
            </Button>
            <Button variant="primary" disabled={!!pasteError} onClick={() => control.current?.send(normalized.endsWith("\r") ? normalized : normalized + "\r") && setPaste(null)}>
              Send and press Enter
            </Button>
          </>
        }
      >
        <pre className="max-h-72 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[12.5px] whitespace-pre-wrap text-fg">{paste}</pre>
        <p className="mt-2 text-[12px] text-muted">{pasteError || `${encoder.encode(paste ?? "").length} bytes`}</p>
      </Modal>
    </div>
  );
}
