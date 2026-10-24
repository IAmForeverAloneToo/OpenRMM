import { useState, type FormEvent } from "react";
import { Check, Copy } from "lucide-react";
import { post } from "../lib/api";
import { Button, Field, Input, Mono } from "../components/ui";

type Provision = { username: string; secret: string; uri: string; recovery_codes: string[]; confirmation: string };

/**
 * Technician activation from an invitation link (/activate#<invitation>). The
 * invitation sits in the URL fragment, so it never reaches server logs; it is
 * cleared from the address bar once read.
 */
export function Activate({ onDone }: { onDone: () => void }) {
  const [fromLink] = useState(() => {
    const value = window.location.hash.slice(1);
    if (value) window.history.replaceState(null, "", "/activate");
    return value;
  });
  const [typed, setTyped] = useState("");
  const invitation = fromLink || typed.trim();
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [provision, setProvision] = useState<Provision | null>(null);
  const [saved, setSaved] = useState(false);
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const run = async (e: FormEvent, fn: () => Promise<void>) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Activation failed.");
    } finally {
      setBusy(false);
    }
  };
  const copy = (label: string, text: string) => void navigator.clipboard.writeText(text).then(() => setCopied(label));
  const passwordOk = [...password].length >= 15 && password === again;

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6">
          <h1 className="text-[18px] font-semibold tracking-tight text-fg">Activate your OpenRMM account</h1>
          <p className="text-[13px] text-muted">{done ? "All set." : provision ? `Step 2 of 2 · authenticator for ${provision.username}` : "Step 1 of 2 · choose a password"}</p>
        </div>
        <div className="space-y-4 rounded-lg border border-border bg-surface p-6 shadow-panel">
          {done ? (
            <>
              <p className="text-[13px] text-fg">Your account is active. Sign in with your username, password and an authenticator code.</p>
              <Button variant="primary" className="w-full" onClick={onDone}>
                Go to sign in
              </Button>
            </>
          ) : !provision ? (
            <form className="space-y-4" onSubmit={(e) => void run(e, async () => setProvision(await post<Provision>("/api/v1/activation/begin", { invitation, password })))}>
              {fromLink ? null : (
                <Field label="Invitation code" hint="From your administrator. Or open the invitation link they sent.">
                  <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} maxLength={128} className="font-mono text-[12.5px]" />
                </Field>
              )}
              <Field label="New password" hint="At least 15 characters. A passphrase works well.">
                <Input type="password" autoFocus={!!fromLink} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} maxLength={256} />
              </Field>
              <Field label="Repeat password">
                <Input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} maxLength={256} className={again && again !== password ? "border-danger" : undefined} />
              </Field>
              {error ? <p className="rounded-md bg-danger-soft px-3 py-2 text-[13px] text-danger" role="alert">{error}</p> : null}
              <Button type="submit" variant="primary" className="w-full" loading={busy} disabled={!passwordOk || !invitation}>
                Continue
              </Button>
            </form>
          ) : (
            <form className="space-y-4" onSubmit={(e) => void run(e, async () => (await post("/api/v1/activation/confirm", { confirmation: provision.confirmation, code: code.trim() }), setDone(true)))}>
              <div className="space-y-1.5 text-[13px]">
                <p className="text-fg">Add this key to your authenticator app (time-based, 6 digits):</p>
                <div className="flex items-center gap-2">
                  <Mono className="flex-1 rounded-md bg-surface-2 px-2.5 py-1.5 break-all text-fg">{provision.secret.replace(/(.{4})/g, "$1 ").trim()}</Mono>
                  <Button size="sm" icon={copied === "key" ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} onClick={() => copy("key", provision.secret)}>
                    Copy
                  </Button>
                </div>
                <a href={provision.uri} className="text-[12.5px] text-accent hover:underline">
                  Open in an authenticator app on this device
                </a>
              </div>
              <div className="space-y-1.5 text-[13px]">
                <p className="text-fg">Recovery codes — each works once if you lose the authenticator. Store them safely; they won't be shown again.</p>
                <div className="grid gap-1 rounded-md bg-surface-2 p-2.5">
                  {provision.recovery_codes.map((c) => (
                    <Mono key={c} className="text-[12.5px] text-fg">
                      {c}
                    </Mono>
                  ))}
                </div>
                <Button size="sm" icon={copied === "codes" ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} onClick={() => copy("codes", provision.recovery_codes.join("\n"))}>
                  Copy codes
                </Button>
                <label className="flex items-center gap-2 pt-1 text-fg">
                  <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                  I've saved my recovery codes
                </label>
              </div>
              <Field label="Code from your authenticator">
                <Input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" inputMode="numeric" maxLength={12} className="font-mono tracking-widest" />
              </Field>
              {error ? <p className="rounded-md bg-danger-soft px-3 py-2 text-[13px] text-danger" role="alert">{error}</p> : null}
              <Button type="submit" variant="primary" className="w-full" loading={busy} disabled={!saved || code.trim().length < 6}>
                Activate
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
