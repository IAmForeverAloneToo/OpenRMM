import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, MousePointer2, Pause, Send, Square } from "lucide-react";
import { csrfHeader, get, post, postKeepalive } from "../lib/api";
import { displayName, qualityNames } from "../lib/desktop";
import type { DesktopView, DeviceDetail } from "../lib/types";
import { Badge, Button, Input, Select, Tip, cx } from "../components/ui";

const endMessages: Record<string, string> = {
  denied: "The local user declined the request.",
  ended: "The local user stopped sharing.",
  unavailable: "The local desktop became unavailable or its display layout changed.",
  expired: "The session reached its time limit.",
  consent_timeout: "The companion on the device did not start the session in time. Check that a user is signed in at the console.",
  agent_disconnected: "The agent disconnected.",
  companion_disconnected: "The desktop companion on the device closed.",
  companion_reset: "The desktop companion reset.",
  viewer_disconnected: "The browser connection expired.",
  viewer_stopped: "You ended the session.",
  server_stopped: "The server stopped.",
};
const keys: Record<string, number> = { Backspace: 8, Tab: 9, Enter: 13, Escape: 27, " ": 32, PageUp: 33, PageDown: 34, End: 35, Home: 36, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Insert: 45, Delete: 46 };

type Event = { kind: string; x?: number; y?: number; button?: number; key?: number; text?: string; ctrl?: boolean; alt?: boolean; shift?: boolean };
type Phase = "connecting" | "waiting" | "active" | "stalled" | "ended";

export function DesktopPage() {
  const { id: deviceId = "", session = "" } = useParams();
  const navigate = useNavigate();
  const screen = useRef<HTMLImageElement>(null);
  const api = useRef<{ end: (m: string) => void; togglePause: () => void; sendText: (t: string) => string } | null>(null);
  const [phase, setPhase] = useState<Phase>("connecting");
  const [ended, setEnded] = useState("");
  const [paused, setPaused] = useState(true);
  const [canInput, setCanInput] = useState(false);
  const [control, setControl] = useState(false);
  const [zoom, setZoom] = useState("fit");
  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const [age, setAge] = useState<number | null>(null);
  // Display and quality are chosen here and can change while the session runs.
  const view = useQuery({ queryKey: ["desktop-view", session], queryFn: ({ signal }) => get<DesktopView>(`/api/v1/desktop/${encodeURIComponent(session)}`, signal), refetchInterval: 5000, retry: false });
  const configure = useMutation({
    mutationFn: (v: { display: number; quality: string }) => post(`/api/v1/desktop/${encodeURIComponent(session)}/configure`, v),
    onSettled: () => void view.refetch(),
  });
  const device = useQuery({ queryKey: ["device", deviceId], queryFn: ({ signal }) => get<DeviceDetail>(`/api/v1/devices/${deviceId}`, signal), staleTime: 60_000 });

  useEffect(() => {
    const img = screen.current;
    if (!img) return;
    const base = `/api/v1/desktop/${encodeURIComponent(session)}`;
    let stopped = false;
    let active = false;
    let isPaused = true;
    let allowControl = false;
    let sequence = 0;
    let busy = false;
    let lastMove = 0;
    let frameDeadline = 0;
    let frameBegan = 0;
    let serverAge = 0;
    let url: string | null = null;
    let pending: Event[] = [];
    let clickPending: { point: { x: number; y: number }; timer: ReturnType<typeof setTimeout> } | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const inputAllowed = () => allowControl && active && !isPaused && !stopped && performance.now() < frameDeadline;
    const refresh = () => {
      setPaused(isPaused);
      setCanInput(inputAllowed());
    };
    const discardClick = () => {
      if (clickPending) clearTimeout(clickPending.timer);
      clickPending = null;
    };
    const clearScreen = () => {
      active = false;
      isPaused = true;
      pending = [];
      discardClick();
      img.hidden = true;
      img.removeAttribute("src");
      if (url) URL.revokeObjectURL(url);
      url = null;
      refresh();
    };
    const end = (message: string, notify = true) => {
      if (stopped) return;
      stopped = true;
      if (timer) clearTimeout(timer);
      if (notify) postKeepalive(`${base}/stop`);
      clearScreen();
      setPhase("ended");
      setEnded(message);
    };

    const flush = async () => {
      if (busy || !inputAllowed() || !pending.length) return;
      busy = true;
      const events = pending.splice(0, 16);
      try {
        const r = await fetch(`${base}/input`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...csrfHeader() },
          body: JSON.stringify({ sequence: ++sequence, events }),
          credentials: "same-origin",
          signal: AbortSignal.timeout(3000),
        });
        if (!stopped && !r.ok) end("Input delivery stopped. Request a new session.");
      } catch {
        end("The control connection was lost. Input is never retried.");
      } finally {
        busy = false;
        if (pending.length && !stopped) queueMicrotask(() => void flush());
      }
    };
    const enqueue = (event: Event) => {
      if (!inputAllowed()) return;
      const last = pending[pending.length - 1];
      if (event.kind === "move" && last?.kind === "move") pending[pending.length - 1] = event;
      else pending.push(event);
      if (pending.length > 48) {
        end("Too much input queued. Request a new session.");
        return;
      }
      if (!busy) queueMicrotask(() => void flush());
    };
    const commitClick = () => {
      const c = clickPending;
      discardClick();
      if (c) enqueue({ kind: "click", button: 1, ...c.point });
    };
    const input = (event: Event) => {
      if (event.kind !== "move") commitClick();
      enqueue(event);
    };
    const point = (e: MouseEvent) => {
      const r = img.getBoundingClientRect();
      const w = img.clientWidth || r.width;
      const h = img.clientHeight || r.height;
      const x = e.clientX - r.left - (img.clientLeft || 0);
      const y = e.clientY - r.top - (img.clientTop || 0);
      if (!Number.isFinite(x + y) || w < 1 || h < 1 || x < 0 || y < 0 || x >= w || y >= h) return null;
      return { x: Math.min(65535, Math.round((x / Math.max(1, w - 1)) * 65535)), y: Math.min(65535, Math.round((y / Math.max(1, h - 1)) * 65535)) };
    };

    const poll = async () => {
      if (stopped) return;
      if (document.hidden) {
        end("Viewing stopped because the page was hidden.");
        return;
      }
      try {
        const began = performance.now();
        const r = await fetch(`${base}/frame`, { credentials: "same-origin", cache: "no-store", signal: AbortSignal.timeout(5000) });
        if (stopped) return;
        if (r.status === 204) {
          clearScreen();
          setPhase(r.headers.get("X-Desktop-State") === "waiting" ? "waiting" : "stalled");
        } else if (r.ok && r.headers.get("Content-Type") === "image/jpeg") {
          const blob = await r.blob();
          if (stopped) return;
          const raw = r.headers.get("X-Desktop-Frame-Age");
          const frameAge = Number(raw);
          if (raw === null || !/^\d+$/.test(raw) || !Number.isFinite(frameAge) || frameAge + performance.now() - began >= 3000 || blob.size > 1048576) {
            clearScreen();
            setPhase("stalled");
          } else {
            frameDeadline = began + 3000 - frameAge;
            frameBegan = began;
            serverAge = frameAge;
            const previous = url;
            url = URL.createObjectURL(blob);
            img.src = url;
            if (previous) URL.revokeObjectURL(previous);
            active = true;
            img.hidden = false;
            setPhase("active");
            refresh();
          }
        } else if (r.status === 410) {
          const body = (await r.json().catch(() => ({}))) as { reason?: string };
          end(endMessages[body.reason ?? ""] ?? "The session ended.", false);
          return;
        } else {
          end(r.status === 401 ? "Your sign-in expired." : r.status === 403 ? "Your account no longer has remote desktop access." : "The session is no longer available.", r.status !== 404);
          return;
        }
      } catch {
        end("The connection was lost. Request a new session to reconnect.");
        return;
      }
      timer = setTimeout(() => void poll(), 500);
    };

    const onClick = (e: MouseEvent) => {
      img.focus();
      if (!inputAllowed()) return;
      const p = point(e);
      if (!p) return;
      if (e.detail === 2 && clickPending) {
        discardClick();
        enqueue({ kind: "double-click", button: 1, ...p });
      } else if (e.detail === 1) {
        commitClick();
        clickPending = { point: p, timer: setTimeout(commitClick, 250) };
      } else input({ kind: "click", button: 1, ...p });
    };
    const onContext = (e: MouseEvent) => {
      e.preventDefault();
      const p = point(e);
      if (p) input({ kind: "click", button: 3, ...p });
    };
    const onAux = (e: MouseEvent) => {
      if (e.button === 1) {
        e.preventDefault();
        const p = point(e);
        if (p) input({ kind: "click", button: 2, ...p });
      }
    };
    const onMove = (e: MouseEvent) => {
      const p = point(e);
      if (p && performance.now() - lastMove > 150) {
        lastMove = performance.now();
        input({ kind: "move", ...p });
      }
    };
    const onWheel = (e: WheelEvent) => {
      const p = point(e);
      if (inputAllowed() && p && e.deltaY !== 0) {
        e.preventDefault();
        input({ kind: "wheel", button: e.deltaY > 0 ? -1 : 1, ...p });
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (!inputAllowed() || e.metaKey) return;
      if (e.isComposing || e.key === "Dead" || e.key === "Process") {
        setNote("Use the text box for accented or composed text.");
        return;
      }
      const altGraph = e.getModifierState("AltGraph");
      if ([...e.key].length === 1 && ((!e.ctrlKey && !e.altKey) || altGraph)) {
        e.preventDefault();
        input({ kind: "text", text: e.key });
        return;
      }
      let key = keys[e.key];
      if (!key && /^F([1-9]|1[0-2])$/.test(e.key)) key = 111 + Number(e.key.slice(1));
      if (!key && /^[a-z0-9]$/i.test(e.key)) key = e.key.toUpperCase().charCodeAt(0);
      if (key) {
        e.preventDefault();
        input({ kind: "key", key, ctrl: e.ctrlKey, alt: e.altKey, shift: e.shiftKey });
      }
    };
    const onBlur = () => {
      pending = [];
      discardClick();
    };
    const onWindowBlur = () => {
      isPaused = true;
      pending = [];
      discardClick();
      refresh();
    };
    const onVisibility = () => {
      if (document.hidden) end("Viewing stopped because the page was hidden.");
    };
    const onHide = () => end("Disconnected.");
    const onError = () => end("The screen image could not be decoded.");

    img.addEventListener("click", onClick);
    img.addEventListener("contextmenu", onContext);
    img.addEventListener("auxclick", onAux);
    img.addEventListener("mousemove", onMove);
    img.addEventListener("wheel", onWheel, { passive: false });
    img.addEventListener("keydown", onKey);
    img.addEventListener("blur", onBlur);
    img.addEventListener("error", onError);
    window.addEventListener("blur", onWindowBlur);
    window.addEventListener("pagehide", onHide);
    document.addEventListener("visibilitychange", onVisibility);
    const tick = setInterval(() => {
      if (active && performance.now() >= frameDeadline) {
        clearScreen();
        setPhase("stalled");
      }
      setAge(active ? (serverAge + performance.now() - frameBegan) / 1000 : null);
      setCanInput(inputAllowed());
    }, 250);

    api.current = {
      end,
      togglePause: () => {
        if (!active || !allowControl || stopped) return;
        isPaused = !isPaused;
        pending = [];
        discardClick();
        refresh();
        if (!isPaused) img.focus();
      },
      sendText: (value: string) => {
        if (!inputAllowed()) return "Enable input first.";
        const bytes = new TextEncoder();
        if (!value || value.includes("\0") || bytes.encode(value).length > 512) return "Type between 1 and 512 bytes of text.";
        let part = "";
        let size = 0;
        commitClick();
        for (const ch of value) {
          const n = bytes.encode(ch).length;
          if (size + n > 128) {
            enqueue({ kind: "text", text: part });
            part = "";
            size = 0;
          }
          part += ch;
          size += n;
        }
        if (part) enqueue({ kind: "text", text: part });
        return "";
      },
    };

    void (async () => {
      try {
        const v = await get<DesktopView>(base);
        allowControl = v.control;
        sequence = v.sequence;
        setControl(v.control);
        setPhase(v.state === "waiting" ? "waiting" : "connecting");
        void poll();
      } catch {
        end("The session is no longer available.", false);
      }
    })();

    return () => {
      clearInterval(tick);
      img.removeEventListener("click", onClick);
      img.removeEventListener("contextmenu", onContext);
      img.removeEventListener("auxclick", onAux);
      img.removeEventListener("mousemove", onMove);
      img.removeEventListener("wheel", onWheel);
      img.removeEventListener("keydown", onKey);
      img.removeEventListener("blur", onBlur);
      img.removeEventListener("error", onError);
      window.removeEventListener("blur", onWindowBlur);
      window.removeEventListener("pagehide", onHide);
      document.removeEventListener("visibilitychange", onVisibility);
      end("Disconnected.");
      api.current = null;
    };
  }, [session]);

  const phaseLabel: Record<Phase, { label: string; tone: "ok" | "info" | "warn" | "neutral" }> = {
    connecting: { label: "Connecting", tone: "info" },
    waiting: { label: "Starting on the device", tone: "info" },
    active: { label: "Connected", tone: "ok" },
    stalled: { label: "Waiting for a fresh screen", tone: "warn" },
    ended: { label: "Ended", tone: "neutral" },
  };

  return (
    <div className="flex h-screen flex-col bg-bg">
      <header className="flex h-13 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
        <Link to={`/devices/${deviceId}`} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-muted hover:bg-surface-2 hover:text-fg">
          <ArrowLeft className="size-4" /> Back
        </Link>
        <div className="h-5 w-px bg-border" />
        <span className="font-semibold text-fg">{device.data?.device.hostname ?? "Device"}</span>
        <Badge tone={phaseLabel[phase].tone} dot>
          {phaseLabel[phase].label}
        </Badge>
        <Badge tone={control ? "accent" : "neutral"}>{control ? "View and control" : "View only"}</Badge>
        {age !== null ? <span className="text-[12px] text-muted tabular-nums">frame {age.toFixed(1)}s old</span> : null}
        <div className="flex-1" />
        {control && phase !== "ended" ? (
          <Tip label={paused ? "Start sending your mouse and keyboard to the device" : "Stop sending input; viewing continues"}>
            <span>
              <Button size="sm" variant={paused ? "primary" : "secondary"} icon={paused ? <MousePointer2 className="size-3.5" /> : <Pause className="size-3.5" />} disabled={phase !== "active"} onClick={() => api.current?.togglePause()}>
                {paused ? "Enable input" : "Pause input"}
              </Button>
            </span>
          </Tip>
        ) : null}
        {phase !== "ended" ? (
          <>
            <Select value={String(view.data?.display ?? 0)} onChange={(e) => configure.mutate({ display: Number(e.target.value), quality: view.data?.quality ?? "" })} aria-label="Display" className="h-7 text-[12.5px]">
              {(view.data?.displays.length ? view.data.displays : [{ index: 0, left: 0, top: 0, width: 0, height: 0, primary: true }]).map((d) => (
                <option key={d.index} value={d.index}>
                  {displayName(d)}
                </option>
              ))}
            </Select>
            <Select value={view.data?.quality || "balanced"} onChange={(e) => configure.mutate({ display: view.data?.display ?? 0, quality: e.target.value })} aria-label="Quality" className="h-7 text-[12.5px]">
              {Object.entries(qualityNames).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          </>
        ) : null}
        <Select value={zoom} onChange={(e) => setZoom(e.target.value)} aria-label="Zoom" className="h-7 text-[12.5px]">
          <option value="fit">Fit</option>
          <option value="100">100%</option>
          <option value="150">150%</option>
        </Select>
        {phase !== "ended" ? (
          <Button variant="danger" size="sm" icon={<Square className="size-3.5" />} onClick={() => api.current?.end("You ended the session.")}>
            End session
          </Button>
        ) : (
          <Button size="sm" onClick={() => navigate(`/devices/${deviceId}`)}>
            Back to device
          </Button>
        )}
      </header>
      {ended ? <div className="border-b border-border bg-surface-2 px-4 py-2 text-[13px] text-fg">Session ended — {ended}</div> : null}
      <div className="relative flex min-h-0 flex-1 items-center justify-center overflow-auto bg-[#05070a] p-3">
        {phase !== "active" && phase !== "ended" ? (
          <p className="absolute text-[13px] text-muted">
            {phase === "waiting" ? "Waiting for the OpenRMM companion on the device to start sharing." : "Waiting for the screen…"}
          </p>
        ) : null}
        <img
          ref={screen}
          hidden
          tabIndex={0}
          alt="Remote screen"
          draggable={false}
          className={cx("select-none outline-none", canInput && "ring-2 ring-accent", zoom === "fit" && "max-h-full max-w-full object-contain")}
          style={zoom === "fit" ? undefined : { width: `${Number(zoom)}%`, maxWidth: "none" }}
        />
      </div>
      {control && phase !== "ended" ? (
        <footer className="flex shrink-0 items-center gap-2 border-t border-border bg-surface px-4 py-2">
          <Input
            value={text}
            onChange={(e) => setText(e.target.value)}
            onPaste={(e) => {
              e.preventDefault();
              setNote("Clipboard sharing is off. Type the text here instead.");
            }}
            placeholder={canInput ? "Type text to send to the device" : "Enable input to send text"}
            disabled={!canInput}
            className="max-w-xl"
            maxLength={512}
            aria-label="Text to send"
          />
          <Button
            size="sm"
            icon={<Send className="size-3.5" />}
            disabled={!canInput || !text}
            onClick={() => {
              const err = api.current?.sendText(text) ?? "";
              setNote(err || "Text sent. Interrupted input is never retried.");
              if (!err) setText("");
            }}
          >
            Send text
          </Button>
          <span className="text-[12px] text-muted">{note || (canInput ? "Keyboard and mouse go to the device while the screen has focus." : paused ? "Input is paused." : "Input is unavailable until a fresh screen arrives.")}</span>
        </footer>
      ) : null}
    </div>
  );
}
