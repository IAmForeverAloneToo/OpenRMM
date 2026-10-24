import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Download } from "lucide-react";
import { downloadFile, get, post, put } from "../lib/api";
import { absoluteTime, plural } from "../lib/format";
import type { EnrollmentToken, InstallerSettings, InstallerView } from "../lib/types";
import { Modal } from "../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Segmented, Select, Spinner } from "../components/ui";

// The owner downloads a pre-configured installer ZIP (signed MSI,
// enrollment file, install.cmd) for one device or for a deployment.

const SILENT = "install.cmd /quiet";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
        } catch {
          setCopied(false);
        }
      }}
      icon={copied ? <Check className="size-3.5 text-ok" /> : <Copy className="size-3.5" />}
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function tokenState(t: EnrollmentToken, nowSeconds: number): { tone: "ok" | "neutral" | "warn"; label: string } {
  if (t.revoked_at) return { tone: "neutral", label: "Revoked" };
  if (t.expires_at <= nowSeconds) return { tone: "neutral", label: "Expired" };
  if (t.used >= t.max_devices) return { tone: "warn", label: "Limit reached" };
  return { tone: "ok", label: "Active" };
}

function Deployments({ tokens }: { tokens: EnrollmentToken[] }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState("");
  const revoke = useMutation({
    mutationFn: (id: string) => post(`/api/v1/installer/tokens/${id}/revoke`),
    onSettled: () => {
      setConfirm("");
      void qc.invalidateQueries({ queryKey: ["installer"] });
    },
  });
  const now = Date.now() / 1000;
  if (tokens.length === 0) return null;
  return (
    <div>
      <div className="mb-1.5 text-[12.5px] font-medium text-muted">Deployments</div>
      {revoke.isError ? <ErrorNotice error={revoke.error} /> : null}
      <ul className="divide-y divide-border rounded-md border border-border">
        {tokens.map((t) => {
          const s = tokenState(t, now);
          return (
            <li key={t.id} className="flex items-center gap-3 px-3 py-2 text-[12.5px]">
              <div className="min-w-0 flex-1">
                <div className="truncate text-fg">{t.label}</div>
                <div className="text-[11.5px] text-faint">
                  {t.used} of {plural(t.max_devices, "device")} · {t.revoked_at ? `revoked ${absoluteTime(t.revoked_at)}` : `expires ${absoluteTime(t.expires_at)}`} · {t.actor}
                </div>
              </div>
              <Badge tone={s.tone}>{s.label}</Badge>
              {s.label === "Active" || s.label === "Limit reached" ? (
                confirm === t.id ? (
                  <Button size="sm" variant="danger" loading={revoke.isPending} onClick={() => revoke.mutate(t.id)}>
                    Confirm revoke
                  </Button>
                ) : (
                  <Button size="sm" variant="ghost" onClick={() => setConfirm(t.id)}>
                    Revoke
                  </Button>
                )
              ) : null}
            </li>
          );
        })}
      </ul>
      <p className="mt-1.5 text-[12px] text-faint">Revoking stops new enrollments with that installer; devices it already enrolled stay.</p>
    </div>
  );
}

function InstallerForm({ view, onDownloaded }: { view: InstallerView; onDownloaded: (name: string) => void }) {
  const qc = useQueryClient();
  const host = window.location.hostname;
  const [addresses, setAddresses] = useState<InstallerSettings>(() => ({
    server_url: view.settings.server_url || window.location.origin,
    device_url: view.settings.device_url || `https://${host.includes(":") ? `[${host}]` : host}:${view.device_port || 8444}`,
  }));
  const [kind, setKind] = useState<"single" | "deployment">("single");
  const [label, setLabel] = useState("");
  const [maxDevices, setMaxDevices] = useState("50");
  const [days, setDays] = useState("30");
  const download = useMutation({
    mutationFn: async () => {
      if (addresses.server_url !== view.settings.server_url || addresses.device_url !== view.settings.device_url) {
        await put("/api/v1/installer/settings", addresses);
      }
      const body = kind === "single" ? { kind, label: "" } : { kind, label: label.trim(), max_devices: Number(maxDevices), days: Number(days) };
      return downloadFile("/api/v1/installer/download", body, "OpenRMM-Agent-Setup.zip");
    },
    onSuccess: (name) => onDownloaded(name),
    onSettled: () => void qc.invalidateQueries({ queryKey: ["installer"] }),
  });
  const deploymentValid = label.trim() !== "" && Number(maxDevices) >= 1 && Number(maxDevices) <= 10000;
  const release = view.release;
  return (
    <div className="space-y-5">
      <div className="space-y-3">
        <Field label="Server address" hint="Agents enroll here: the address of this console as the devices reach it.">
          <Input value={addresses.server_url} onChange={(e) => setAddresses({ ...addresses, server_url: e.target.value })} maxLength={253} spellCheck={false} aria-label="Server address" />
        </Field>
        <Field label="Device address" hint="The agent connection port (device listener) at the same or another host name.">
          <Input value={addresses.device_url} onChange={(e) => setAddresses({ ...addresses, device_url: e.target.value })} maxLength={253} spellCheck={false} aria-label="Device address" />
        </Field>
        <p className="text-[12px] text-faint">
          {view.trust === "ca"
            ? "Installers trust this server's own certificate authority."
            : "Installers rely on the certificate authorities Windows trusts; the server certificate must be publicly trusted."}{" "}
          The addresses are saved for future installers.
        </p>
      </div>
      <div className="space-y-3">
        <Segmented
          label="Installer type"
          value={kind}
          onChange={setKind}
          options={[
            { value: "single", label: "One device" },
            { value: "deployment", label: "Deployment (many devices)" },
          ]}
        />
        {kind === "single" ? (
          <p className="text-[12.5px] text-muted">Enrolls one machine. Valid for 24 hours; it cannot be used twice.</p>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="sm:col-span-3">
              <Field label="Name" hint="Shown in the deployment list, for example the site or group.">
                <Input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} aria-label="Deployment name" />
              </Field>
            </div>
            <Field label="Device limit">
              <Input type="number" min={1} max={10000} value={maxDevices} onChange={(e) => setMaxDevices(e.target.value)} aria-label="Device limit" />
            </Field>
            <Field label="Valid for">
              <Select value={days} onChange={(e) => setDays(e.target.value)} aria-label="Valid for">
                {[1, 7, 30, 90, 365].map((d) => (
                  <option key={d} value={String(d)}>
                    {plural(d, "day")}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        )}
      </div>
      {release && release.msi ? (
        <p className="text-[12px] text-faint">
          Agent {release.version} (release {release.sequence}). Installed agents update themselves afterwards.
        </p>
      ) : (
        <p className="text-[12.5px] text-warn">No signed agent MSI release is available yet; publish an agent release first.</p>
      )}
      {download.isError ? <ErrorNotice error={download.error} /> : null}
      <div className="flex justify-end">
        <Button
          variant="primary"
          icon={<Download className="size-4" />}
          loading={download.isPending}
          disabled={!release?.msi || (kind === "deployment" && !deploymentValid)}
          onClick={() => download.mutate()}
        >
          Download installer
        </Button>
      </div>
    </div>
  );
}

export function AddDeviceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [downloaded, setDownloaded] = useState("");
  const q = useQuery({ queryKey: ["installer"], queryFn: ({ signal }) => get<InstallerView>("/api/v1/installer", signal), enabled: open });
  const close = (o: boolean) => {
    if (!o) setDownloaded("");
    onOpenChange(o);
  };
  return (
    <Modal
      open={open}
      onOpenChange={close}
      width="max-w-2xl"
      title="Add Windows devices"
      description="Download a pre-configured installer. It installs the agent, enrolls the machine and keeps it up to date."
      footer={
        <Button variant={downloaded ? "primary" : "ghost"} onClick={() => close(false)}>
          {downloaded ? "Done" : "Close"}
        </Button>
      }
    >
      {q.isPending ? (
        <Spinner label="Loading installer settings" />
      ) : q.isError ? (
        <ErrorNotice error={q.error} retry={() => void q.refetch()} />
      ) : (
        <div className="space-y-5">
          {downloaded ? (
            <div className="space-y-3 rounded-md border border-border bg-surface-2 p-3 text-[12.5px]">
              <p className="text-fg">
                Downloaded <span className="font-medium">{downloaded}</span>. Keep it private: it contains an enrollment token.
              </p>
              <p className="text-muted">On the device, extract the ZIP and double-click install.cmd. The device appears here within a minute.</p>
              <div>
                <div className="mb-1 text-muted">Intune, Group Policy or a remote shell (as administrator or SYSTEM, in the extracted folder):</div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 truncate rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-[12.5px] text-fg">{SILENT}</code>
                  <CopyButton text={SILENT} />
                </div>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setDownloaded("")}>
                Download another installer
              </Button>
            </div>
          ) : (
            <InstallerForm view={q.data} onDownloaded={setDownloaded} />
          )}
          <Deployments tokens={q.data.tokens} />
        </div>
      )}
    </Modal>
  );
}
