/** A fresh 32-hex-digit operation ID, used by the server as an idempotency key. */
export function newOperationID(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
