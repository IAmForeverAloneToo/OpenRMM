import { useState, type ReactNode } from "react";
import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { Button, Input, cx } from "./ui";

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-[var(--overlay)]" />
        <D.Content
          {...(description ? {} : { "aria-describedby": undefined })}
          className={cx(
            "fixed top-[12vh] left-1/2 z-50 w-[calc(100vw-2rem)] -translate-x-1/2 rounded-lg border border-border-strong bg-surface shadow-panel focus:outline-none",
            width,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="space-y-1">
              <D.Title className="text-[15px] font-semibold text-fg">{title}</D.Title>
              {description ? <D.Description className="text-[13px] text-muted">{description}</D.Description> : null}
            </div>
            <D.Close className="rounded p-1 text-muted hover:bg-surface-2 hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </D.Close>
          </div>
          {children ? <div className="px-5 py-4">{children}</div> : null}
          {footer ? <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div> : null}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

/**
 * Confirmation for an operation. Routine actions confirm with one click; when
 * `typed` is set (revocation, isolation) the exact value must be typed first.
 * The server repeats the check, so this is a guard, not the only one.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel,
  danger,
  typed,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  typed?: string;
  onConfirm: () => Promise<void>;
}) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const ready = !typed || value === typed;
  const close = (o: boolean) => {
    if (busy) return;
    if (!o) {
      setValue("");
      setError("");
    }
    onOpenChange(o);
  };
  const run = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError("");
    try {
      await onConfirm();
      setValue("");
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The operation failed.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={() => close(false)} disabled={busy}>
            Cancel
          </Button>
          <Button variant={danger ? "danger" : "primary"} onClick={run} disabled={!ready} loading={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px] text-muted">
        {children}
        {typed ? (
          <label className="block space-y-1.5">
            <span className="block text-fg">
              Type <span className="font-mono font-semibold">{typed}</span> to confirm
            </span>
            <Input
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void run();
              }}
              spellCheck={false}
              autoComplete="off"
              aria-label="Confirmation"
            />
          </label>
        ) : null}
        {error ? (
          <p className="rounded-md bg-danger-soft px-3 py-2 text-danger" role="alert">
            {error}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
