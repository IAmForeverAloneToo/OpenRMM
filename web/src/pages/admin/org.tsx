import { useEffect, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "../../lib/api";
import { plural } from "../../lib/format";
import { parseTags, tagPattern } from "../../lib/parse";
import { featureLabel } from "../../lib/features";
import type { Organization, OrganizationChange, OrganizationReview } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Button, Field, Input, Select } from "../../components/ui";
import { ReviewDialog } from "../operations/shared";

export function useOrganization(enabled = true) {
  return useQuery({ queryKey: ["organization"], queryFn: ({ signal }) => get<Organization>("/api/v1/organization", signal), enabled });
}

type Reviewed = OrganizationReview & { change: OrganizationChange & { revision: number } };

/**
 * Reviewed organization change: the server previews the effect (which devices'
 * alert rules change) against the current revision; confirming applies exactly
 * that preview.
 */
export function OrgChangeDialog({
  change,
  onClose,
  title,
  confirmLabel,
  danger,
  children,
}: {
  change: OrganizationChange | null;
  onClose: (applied: boolean) => void;
  title: string;
  confirmLabel: string;
  danger?: boolean;
  children?: ReactNode;
}) {
  const client = useQueryClient();
  return (
    <ReviewDialog<Reviewed>
      open={change !== null}
      onOpenChange={(o) => !o && onClose(false)}
      title={title}
      confirmLabel={confirmLabel}
      danger={danger}
      width="max-w-xl"
      review={async () => {
        const o = await get<Organization>("/api/v1/organization");
        const c = { ...change!, revision: o.revision };
        const r = await post<OrganizationReview>("/api/v1/organization/review", { change: c, digest: "" });
        return { ...r, change: c };
      }}
      apply={async (r) => {
        await post("/api/v1/organization/apply", { change: r.change, digest: r.digest });
        await Promise.all([client.invalidateQueries({ queryKey: ["organization"] }), client.invalidateQueries({ queryKey: ["devices"] }), client.invalidateQueries({ queryKey: ["device"] })]);
        onClose(true);
      }}
      render={(r) => (
        <>
          {children}
          {r.impacts.length === 0 ? (
            <p>No device's alert rules or agent features change.</p>
          ) : (
            <div>
              <p className="mb-1.5">
                Settings change on {plural(r.impacts.length, "device")}. Open alerts of changed rules close as “settings changed” and re-evaluate; changed agent features apply within a heartbeat.
              </p>
              <ul className="max-h-48 divide-y divide-border overflow-y-auto rounded-md border border-border">
                {r.impacts.map((i) => (
                  <li key={i.id} className="flex items-center gap-3 px-3 py-1.5 text-[12.5px]">
                    <span className="w-40 truncate text-fg">{i.hostname}</span>
                    <span className="min-w-0 flex-1 truncate text-muted">
                      {i.before} → {i.after}
                      {i.features?.length ? ` · features: ${i.features.map(featureLabel).join(", ")}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    />
  );
}

/** Group, device policy and tags for one device. */
export function OrganizeDialog({ deviceId, onClose }: { deviceId: string; onClose: () => void }) {
  const org = useOrganization();
  const device = org.data?.devices.find((d) => d.id === deviceId);
  const [draft, setDraft] = useState<{ group: string; policy: string; tags: string } | null>(null);
  const [change, setChange] = useState<OrganizationChange | null>(null);
  useEffect(() => {
    if (device && !draft) setDraft({ group: device.group_id, policy: device.policy_id, tags: device.tags.join(", ") });
  }, [device, draft]);
  const tags = parseTags(draft?.tags ?? "");
  const valid = tags.length <= 16 && tags.every((t) => tagPattern.test(t));
  return (
    <>
      <OrgChangeDialog change={change} onClose={(applied) => (setChange(null), applied && onClose())} title={`Organize ${device?.hostname ?? ""}?`} confirmLabel="Save" />
      {change === null ? (
        <ReviewlessModal
          title={`Organize ${device?.hostname ?? "device"}`}
          onClose={onClose}
          disabled={!draft || !valid}
          onContinue={() => setChange({ action: "device", id: deviceId, group_id: draft!.group, policy_id: draft!.policy, tags })}
        >
          {draft && org.data ? (
            <div className="space-y-3">
              <Field label="Group">
                <Select value={draft.group} onChange={(e) => setDraft({ ...draft, group: e.target.value })} className="w-full">
                  <option value="">Ungrouped</option>
                  {org.data.groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Monitoring policy" hint="A device policy overrides its group's policy.">
                <Select value={draft.policy} onChange={(e) => setDraft({ ...draft, policy: e.target.value })} className="w-full">
                  <option value="">Inherit from group (or defaults)</option>
                  {org.data.policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Tags" hint="Comma-separated, up to 16. Letters, digits, . - _">
                <Input value={draft.tags} onChange={(e) => setDraft({ ...draft, tags: e.target.value })} placeholder="e.g. finance, laptop" className={valid ? undefined : "border-danger"} />
              </Field>
            </div>
          ) : null}
        </ReviewlessModal>
      ) : null}
    </>
  );
}

/** Form step before a reviewed change: Continue asks the server to review it. */
export function ReviewlessModal({ title, children, onClose, onContinue, disabled, width }: { title: string; children: ReactNode; onClose: () => void; onContinue: () => void; disabled?: boolean; width?: string }) {
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={title}
      width={width}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={disabled} onClick={onContinue}>
            Review
          </Button>
        </>
      }
    >
      {children}
    </Modal>
  );
}

/** Group, device policy and tag changes for many devices in one reviewed change. */
export function BulkOrganizeDialog({ devices, onClose }: { devices: { id: string; hostname: string }[]; onClose: (applied: boolean) => void }) {
  const org = useOrganization();
  const [group, setGroup] = useState("keep");
  const [policy, setPolicy] = useState("keep");
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [change, setChange] = useState<OrganizationChange | null>(null);
  const addTags = parseTags(add);
  const removeTags = parseTags(remove);
  const valid =
    [...addTags, ...removeTags].every((t) => tagPattern.test(t)) &&
    addTags.length <= 16 &&
    removeTags.length <= 16 &&
    !addTags.some((t) => removeTags.includes(t)) &&
    (group !== "keep" || policy !== "keep" || addTags.length + removeTags.length > 0);
  const n = devices.length;
  return (
    <>
      <OrgChangeDialog change={change} onClose={(applied) => (setChange(null), applied && onClose(true))} title={`Update ${plural(n, "device")}?`} confirmLabel={`Update ${plural(n, "device")}`}>
        <p className="text-fg">{devices.slice(0, 6).map((d) => d.hostname).join(", ") + (n > 6 ? ` and ${n - 6} more` : "")}</p>
      </OrgChangeDialog>
      {change === null ? (
        <ReviewlessModal
          title={`Organize ${plural(n, "device")}`}
          onClose={() => onClose(false)}
          disabled={!valid || !org.data}
          onContinue={() =>
            setChange({
              action: "devices",
              devices: devices.map((d) => d.id),
              set_group: group !== "keep",
              group_id: group === "keep" ? "" : group,
              set_policy: policy !== "keep",
              policy_id: policy === "keep" ? "" : policy,
              add_tags: addTags,
              remove_tags: removeTags,
            })
          }
        >
          <div className="space-y-3">
            <Field label="Group">
              <Select value={group} onChange={(e) => setGroup(e.target.value)} className="w-full">
                <option value="keep">Leave unchanged</option>
                <option value="">Ungrouped</option>
                {(org.data?.groups ?? []).map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Device monitoring policy">
              <Select value={policy} onChange={(e) => setPolicy(e.target.value)} className="w-full">
                <option value="keep">Leave unchanged</option>
                <option value="">Inherit from group (or defaults)</option>
                {(org.data?.policies ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </Select>
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Add tags" hint="Comma-separated">
                <Input value={add} onChange={(e) => setAdd(e.target.value)} placeholder="e.g. pilot" />
              </Field>
              <Field label="Remove tags" hint="Comma-separated">
                <Input value={remove} onChange={(e) => setRemove(e.target.value)} />
              </Field>
            </div>
            {!valid && (add || remove) ? <p className="text-[12.5px] text-danger">Tags use letters, digits, “.”, “-” or “_”, and can't be both added and removed.</p> : null}
          </div>
        </ReviewlessModal>
      ) : null}
    </>
  );
}
