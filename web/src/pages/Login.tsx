import { useEffect, useState, type FormEvent } from "react";
import { get } from "../lib/api";
import { useSession } from "../lib/session";
import { Button, Field, Input } from "../components/ui";

export function Login() {
  const { signIn } = useSession();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // Before the first administrator exists, point to the setup link.
  const [setupNeeded, setSetupNeeded] = useState(false);
  useEffect(() => {
    get<{ needed: boolean }>("/api/v1/setup")
      .then((r) => setSetupNeeded(r.needed))
      .catch(() => undefined);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await signIn(username.trim(), password, code.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="size-9" aria-hidden>
            <rect width="32" height="32" rx="7" className="fill-surface-3" />
            <path d="M9 9h6v6H9zM17 9h6v6h-6zM9 17h6v6H9z" className="fill-accent" />
            <path d="M17 17h6v6h-6z" className="fill-ok" />
          </svg>
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight text-fg">Sign in to OpenRMM</h1>
            <p className="text-[13px] text-muted">Password and authenticator code required</p>
          </div>
        </div>
        {setupNeeded ? (
          <p className="mb-4 rounded-md border border-border bg-surface px-3 py-2 text-[13px] text-muted">
            No administrator exists yet. Open the setup link printed by the install command (it works for one hour); run the command again for a new link.
          </p>
        ) : null}
        <form onSubmit={submit} className="space-y-4 rounded-lg border border-border bg-surface p-6 shadow-panel">
          <Field label="Username">
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required maxLength={64} />
          </Field>
          <Field label="Password">
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required maxLength={256} />
          </Field>
          <Field label="Authenticator code" hint="Or one of your recovery codes">
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              inputMode="text"
              required
              maxLength={64}
              className="font-mono tracking-widest"
            />
          </Field>
          {error ? (
            <p className="rounded-md bg-danger-soft px-3 py-2 text-[13px] text-danger" role="alert">
              {error}
            </p>
          ) : null}
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Sign in
          </Button>
        </form>
      </div>
    </div>
  );
}
