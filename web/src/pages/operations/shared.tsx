import { useEffect, useRef, useState, type ReactNode } from "react";
import { Modal } from "../../components/Dialog";
import { Button, ErrorNotice, Spinner } from "../../components/ui";

/**
 * Reviewed change: opening the dialog asks the server to resolve exactly what
 * will happen (targets, digest); confirming applies that review. If the apply
 * is refused (something changed), the operator must review again.
 */
export function ReviewDialog<R>({
  open,
  onOpenChange,
  title,
  review,
  apply,
  render,
  confirmLabel,
  danger,
  width,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  review: () => Promise<R>;
  apply: (r: R) => Promise<void>;
  render: (r: R) => ReactNode;
  confirmLabel: string;
  danger?: boolean;
  width?: string;
}) {
  const [result, setResult] = useState<R | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const reviewRef = useRef(review);
  reviewRef.current = review;
  const load = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await reviewRef.current());
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (open) void load();
    else {
      setResult(null);
      setError(null);
    }
  }, [open]);
  const confirm = async () => {
    if (!result) return;
    setBusy(true);
    setError(null);
    try {
      await apply(result);
      onOpenChange(false);
    } catch (e) {
      setError(e);
      setResult(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title={title}
      width={width}
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {result ? (
            <Button variant={danger ? "danger" : "primary"} loading={busy} onClick={() => void confirm()}>
              {confirmLabel}
            </Button>
          ) : (
            <Button loading={busy} disabled={busy} onClick={() => void load()}>
              Review again
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3 text-[13px] text-muted">
        {result ? render(result) : busy ? <Spinner label="Checking what will change" /> : null}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

export function TargetList({ targets, extra }: { targets: { id: string; hostname: string }[]; extra?: (id: string) => ReactNode }) {
  if (targets.length === 0) return <p className="text-muted">No devices.</p>;
  return (
    <ul className="max-h-56 divide-y divide-border overflow-y-auto rounded-md border border-border">
      {targets.map((t) => (
        <li key={t.id} className="flex items-center gap-3 px-3 py-1.5">
          <span className="flex-1 truncate text-fg">{t.hostname}</span>
          {extra?.(t.id)}
        </li>
      ))}
    </ul>
  );
}

