import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import { ApiError, get, post, request, setCsrfToken, setUnauthenticatedHandler } from "./api.ts";
import { newOperationID } from "./id.ts";

type Call = { url: string; init: RequestInit };
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  setUnauthenticatedHandler(() => {});
});

function respond(status: number, body?: unknown): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  }) as typeof fetch;
  return calls;
}

test("GET sends no CSRF token; POST sends it with a JSON body", async () => {
  setCsrfToken("token-1");
  const calls = respond(200, { ok: true });
  assert.deepEqual(await get("/api/v1/devices"), { ok: true });
  await post("/api/v1/x", { a: 1 });
  const getHeaders = calls[0]!.init.headers as Record<string, string>;
  const postHeaders = calls[1]!.init.headers as Record<string, string>;
  assert.equal(getHeaders["X-CSRF-Token"], undefined);
  assert.equal(postHeaders["X-CSRF-Token"], "token-1");
  assert.equal(postHeaders["Content-Type"], "application/json");
  assert.equal(calls[1]!.init.body, '{"a":1}');
  assert.equal(calls[0]!.init.redirect, "error");
  assert.equal(calls[0]!.init.credentials, "same-origin");
});

test("204 resolves to undefined", async () => {
  respond(204);
  assert.equal(await post("/api/v1/x"), undefined);
});

test("errors carry the server message and code", async () => {
  respond(409, { error: "Changed since review.", code: "stale" });
  await assert.rejects(post("/api/v1/x"), (e: unknown) => e instanceof ApiError && e.status === 409 && e.code === "stale" && e.message === "Changed since review.");
  respond(500);
  await assert.rejects(get("/api/v1/x"), (e: unknown) => e instanceof ApiError && e.message === "Request failed (500)." && e.code === "error");
});

test("401 signs out, except for the session probe", async () => {
  let signedOut = 0;
  setUnauthenticatedHandler(() => signedOut++);
  respond(401, { error: "Sign in." });
  await assert.rejects(get("/api/v1/session"));
  assert.equal(signedOut, 0);
  await assert.rejects(get("/api/v1/devices"));
  assert.equal(signedOut, 1);
});

test("network failure becomes a network ApiError; abort is rethrown", async () => {
  globalThis.fetch = (async () => {
    throw new TypeError("fetch failed");
  }) as typeof fetch;
  await assert.rejects(get("/api/v1/x"), (e: unknown) => e instanceof ApiError && e.code === "network" && e.status === 0);
  globalThis.fetch = (async () => {
    throw new DOMException("aborted", "AbortError");
  }) as typeof fetch;
  await assert.rejects(request("/api/v1/x"), (e: unknown) => e instanceof DOMException && e.name === "AbortError");
});

test("operation IDs are 32 lowercase hex digits and distinct", () => {
  const a = newOperationID();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, newOperationID());
});
