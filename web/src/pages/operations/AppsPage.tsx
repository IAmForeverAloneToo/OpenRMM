import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Package, Plus, Send } from "lucide-react";
import { post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, short } from "../../lib/format";
import { versionCompare } from "../../lib/parse";
import type { AppDefinition, AppVersion } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { PageHeader } from "../../app/AppShell";
import { Modal } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Segmented, Spinner, Tip } from "../../components/ui";
import { DeployDialog, DeploymentsTable, useCatalog } from "./deployments";

const blank: AppDefinition = { name: "", description: "", version: "", product_code: "", url: "", sha256: "" };

function validDefinition(d: AppDefinition): Record<keyof AppDefinition, boolean> {
  let url = false;
  try {
    const u = new URL(d.url);
    url = u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash && u.pathname.toLowerCase().endsWith(".msi");
  } catch {
    url = false;
  }
  return {
    name: d.name.trim().length > 0 && d.name.trim() === d.name && d.name.length <= 100,
    description: d.description.length <= 2000,
    version: /^(\d{1,3})\.(\d{1,3})\.(\d{1,5})$/.test(d.version) && d.version.split(".").every((p, i) => String(Number(p)) === p && (i === 2 ? Number(p) <= 65535 : Number(p) <= 255)),
    product_code: /^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/i.test(d.product_code.trim()),
    url,
    sha256: /^[0-9a-f]{64}$/i.test(d.sha256.trim()),
  };
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="ghost"
      icon={done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {label}
    </Button>
  );
}

/** Adds a version to the catalog: a new application, or a new version of one. */
function VersionEditor({ open, onOpenChange, base, revision }: { open: boolean; onOpenChange: (o: boolean) => void; base: AppVersion | null; revision: number }) {
  const client = useQueryClient();
  const [draft, setDraft] = useState<AppDefinition>(base ? { ...blank, name: base.definition.name, description: base.definition.description } : blank);
  const [ids] = useState(() => ({ id: newOperationID(), application_id: base?.application_id ?? newOperationID() }));
  const [review, setReview] = useState<{ version: AppVersion; digest: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const valid = validDefinition(draft);
  const ok = Object.values(valid).every(Boolean);
  const set = (p: Partial<AppDefinition>) => (setDraft({ ...draft, ...p }), setReview(null));
  const body = (digest: string) => ({ ...ids, revision, definition: { ...draft, product_code: draft.product_code.trim().toUpperCase(), sha256: draft.sha256.trim().toLowerCase(), url: draft.url.trim() }, digest });
  const step = async (op: "review" | "apply") => {
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ version: AppVersion; digest: string }>(`/api/v1/applications/${op}`, body(op === "apply" ? review!.digest : ""));
      if (op === "review") setReview(r);
      else {
        await client.invalidateQueries({ queryKey: ["applications"] });
        onOpenChange(false);
      }
    } catch (e) {
      setError(e);
      setReview(null);
    } finally {
      setBusy(false);
    }
  };
  const field = (k: keyof AppDefinition) => (draft[k] && !valid[k] ? "border-danger" : undefined);
  return (
    <Modal
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title={base ? `New version of ${base.definition.name}` : "Add an application"}
      description="An MSI package from an HTTPS URL, pinned by SHA-256. Versions are immutable once saved."
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {review ? (
            <Button variant="primary" loading={busy} onClick={() => void step("apply")}>
              Save to catalog
            </Button>
          ) : (
            <Button variant="primary" loading={busy} disabled={!ok} onClick={() => void step("review")}>
              Review
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-[1fr_140px] gap-3">
          <Field label="Name">
            <Input autoFocus={!base} value={draft.name} disabled={!!base} onChange={(e) => set({ name: e.target.value })} maxLength={100} placeholder="e.g. 7-Zip" className={field("name")} />
          </Field>
          <Field label="Version" hint="x.y.z">
            <Input autoFocus={!!base} value={draft.version} onChange={(e) => set({ version: e.target.value.trim() })} placeholder="24.9.0" className={field("version")} />
          </Field>
        </div>
        <Field label="Description" hint="Optional">
          <Input value={draft.description} onChange={(e) => set({ description: e.target.value })} maxLength={2000} />
        </Field>
        <Field label="MSI download URL" hint="HTTPS, ending in .msi, no query string">
          <Input value={draft.url} onChange={(e) => set({ url: e.target.value })} placeholder="https://…/package.msi" spellCheck={false} className={field("url")} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="SHA-256 of the MSI">
            <Input value={draft.sha256} onChange={(e) => set({ sha256: e.target.value })} spellCheck={false} className={`font-mono text-[12px] ${field("sha256") ?? ""}`} />
          </Field>
          <Field label="MSI product code">
            <Input value={draft.product_code} onChange={(e) => set({ product_code: e.target.value })} placeholder="{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" spellCheck={false} className={`font-mono text-[12px] ${field("product_code") ?? ""}`} />
          </Field>
        </div>
        {review ? (
          <div className="space-y-2 rounded-md border border-border bg-surface-2 p-3 text-[13px]">
            <div className="text-fg">Saving creates version {review.version.number} with its generated install script (runs as SYSTEM), identified by this hash:</div>
            <div className="flex items-center gap-2">
              <Mono className="break-all text-fg">{review.version.mutation.sha256}</Mono>
              <CopyButton text={review.version.mutation.sha256} label="Copy" />
            </div>
          </div>
        ) : null}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

function VersionDetail({ version, onClose }: { version: AppVersion | null; onClose: () => void }) {
  return (
    <Modal open={version !== null} onOpenChange={(o) => !o && onClose()} title={version ? `${version.definition.name} ${version.definition.version}` : ""} width="max-w-3xl">
      {version ? (
        <div className="space-y-4 text-[13px]">
          <dl className="grid grid-cols-[150px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-muted">Product code</dt>
            <dd>
              <Mono className="text-fg">{version.definition.product_code}</Mono>
            </dd>
            <dt className="text-muted">Download</dt>
            <dd className="break-all text-fg">{version.definition.url}</dd>
            <dt className="text-muted">SHA-256</dt>
            <dd>
              <Mono className="break-all text-fg">{version.definition.sha256}</Mono>
            </dd>
            <dt className="text-muted">Added</dt>
            <dd className="text-fg">
              {absoluteTime(version.created_at)} by {version.actor}
            </dd>
          </dl>
          <p className="text-muted">
            Install, update and uninstall run this version's generated script as SYSTEM on each device (hash <Mono className="text-fg">{short(version.mutation.sha256)}</Mono>).
          </p>
          <details>
            <summary className="cursor-pointer text-muted hover:text-fg">Generated install script</summary>
            <pre className="mt-2 max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-fg">{version.mutation.definition.body}</pre>
          </details>
        </div>
      ) : null}
    </Modal>
  );
}

function Catalog() {
  const q = useCatalog();
  const [editor, setEditor] = useState<{ base: AppVersion | null; key: number } | null>(null);
  const [deploy, setDeploy] = useState<{ version: string; key: number } | null>(null);
  const [detail, setDetail] = useState<AppVersion | null>(null);
  const apps = useMemo(() => {
    const m = new Map<string, AppVersion[]>();
    for (const v of q.data?.versions ?? []) m.set(v.application_id, [...(m.get(v.application_id) ?? []), v]);
    return [...m.values()].map((l) => l.sort((a, b) => versionCompare(b.definition.version, a.definition.version))).sort((a, b) => a[0]!.definition.name.localeCompare(b[0]!.definition.name));
  }, [q.data]);
  if (q.isPending) return <Spinner label="Loading catalog" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  return (
    <>
      <div className="mb-3 flex justify-end gap-2">
        <Button icon={<Send className="size-4" />} disabled={apps.length === 0} onClick={() => setDeploy({ version: "", key: Date.now() })}>
          Deploy
        </Button>
        <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditor({ base: null, key: Date.now() })}>
          Add application
        </Button>
      </div>
      {apps.length === 0 ? (
        <Panel>
          <EmptyState icon={<Package />} title="No applications yet">
            Add an MSI package with its HTTPS download URL, SHA-256 and product code.
          </EmptyState>
        </Panel>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {apps.map((list) => {
            const latest = list[0]!;
            return (
              <Panel
                key={latest.application_id}
                title={latest.definition.name}
                bodyClassName="p-0"
                actions={
                  <div className="flex gap-1.5">
                    <Button size="sm" variant="ghost" icon={<Plus className="size-3.5" />} onClick={() => setEditor({ base: latest, key: Date.now() })}>
                      New version
                    </Button>
                    <Button size="sm" icon={<Send className="size-3.5" />} onClick={() => setDeploy({ version: latest.id, key: Date.now() })}>
                      Deploy
                    </Button>
                  </div>
                }
              >
                {latest.definition.description ? <p className="border-b border-border px-4 py-2 text-[12.5px] text-muted">{latest.definition.description}</p> : null}
                <ul className="divide-y divide-border">
                  {list.map((v, i) => (
                    <li key={v.id} className="flex items-center gap-3 px-4 py-2">
                      <button type="button" className="font-medium text-fg hover:text-accent" onClick={() => setDetail(v)}>
                        {v.definition.version}
                      </button>
                      {i === 0 ? <Badge tone="ok">Latest</Badge> : null}
                      <Tip label={`Install script hash ${v.mutation.sha256}`}>
                        <Mono className="text-[11.5px] text-faint">{short(v.mutation.sha256)}</Mono>
                      </Tip>
                      <span className="flex-1" />
                      <span className="text-[12px] text-muted">{absoluteTime(v.created_at)}</span>
                      <Button size="sm" variant="ghost" onClick={() => setDeploy({ version: v.id, key: Date.now() })}>
                        Deploy
                      </Button>
                    </li>
                  ))}
                </ul>
              </Panel>
            );
          })}
        </div>
      )}
      {editor ? <VersionEditor key={editor.key} open onOpenChange={(o) => !o && setEditor(null)} base={editor.base} revision={q.data!.revision} /> : null}
      {deploy ? <DeployDialog key={deploy.key} open onOpenChange={(o) => !o && setDeploy(null)} versionId={deploy.version} /> : null}
      <VersionDetail version={detail} onClose={() => setDetail(null)} />
    </>
  );
}

export function AppsPage() {
  const account = useAccount();
  const [params, setParams] = useSearchParams();
  const owner = account.permissions.owner;
  const view = owner && params.get("view") !== "deployments" ? "catalog" : "deployments";
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="App deployment"
        subtitle="Install, update, remove or verify MSI packages on Windows devices."
        actions={
          owner ? (
            <Segmented
              label="View"
              value={view}
              onChange={(v) => setParams(v === "catalog" ? {} : { view: v }, { replace: true })}
              options={[
                { value: "catalog", label: "Catalog" },
                { value: "deployments", label: "Deployments" },
              ]}
            />
          ) : null
        }
      />
      {view === "catalog" ? (
        <Catalog />
      ) : (
        <Panel bodyClassName="p-0">
          <DeploymentsTable />
        </Panel>
      )}
    </div>
  );
}
