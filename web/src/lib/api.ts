// Thin same-origin JSON client. Mutations carry the session CSRF token; a 401
// from any call signs the browser out locally so the login screen appears.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(message: string, status: number, code: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let csrfToken = "";
let onUnauthenticated: (() => void) | null = null;

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function setUnauthenticatedHandler(handler: () => void) {
  onUnauthenticated = handler;
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export async function request<T>(path: string, options: { method?: Method; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: options.signal,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError("The server could not be reached.", 0, "network");
  }
  if (response.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    const body = (data ?? {}) as { error?: string; code?: string };
    if (response.status === 401 && path !== "/api/v1/session") onUnauthenticated?.();
    throw new ApiError(body.error ?? `Request failed (${response.status}).`, response.status, body.code ?? "error");
  }
  return data as T;
}

export const get = <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal });
export const post = <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body: body ?? {} });
export const put = <T>(path: string, body: unknown) => request<T>(path, { method: "PUT", body });
export const del = <T>(path: string) => request<T>(path, { method: "DELETE" });

/**
 * POSTs body and saves the binary response as a file (installer downloads).
 * Returns the saved file name. Errors are JSON, as for request().
 */
export async function downloadFile(path: string, body: unknown, fallbackName: string): Promise<string> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { Accept: "application/zip, application/json", "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    throw new ApiError("The server could not be reached.", 0, "network");
  }
  if (!response.ok) {
    let data: { error?: string; code?: string } = {};
    try {
      data = (await response.json()) as typeof data;
    } catch {
      data = {};
    }
    if (response.status === 401) onUnauthenticated?.();
    throw new ApiError(data.error ?? `Request failed (${response.status}).`, response.status, data.code ?? "error");
  }
  const blob = await response.blob();
  const name = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return name;
}

/**
 * Best-effort POST that survives page unload (pagehide), used to end live
 * sessions promptly. Never retried; the server also ends them on lease expiry.
 */
export function postKeepalive(path: string) {
  try {
    void fetch(path, { method: "POST", headers: { "X-CSRF-Token": csrfToken }, credentials: "same-origin", keepalive: true });
  } catch {
    // The server-side lease ends the session if this cannot be sent.
  }
}

export function csrfHeader(): Record<string, string> {
  return { "X-CSRF-Token": csrfToken };
}
