import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { ApiError } from "./lib/api";
import { SessionProvider } from "./lib/session";
import { applyTheme, storedTheme } from "./lib/theme";
import { App } from "./App";
import "./index.css";

// UI primitives that insert <style> elements read this nonce, which the
// server issues per page load and allows in its Content-Security-Policy.
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;
if (nonce) {
  (globalThis as { __webpack_nonce__?: string }).__webpack_nonce__ = nonce;
  // Bundled libraries without a nonce option (xterm.js) create <style> elements
  // through document.createElement; stamp them with the page nonce before they
  // are inserted. Only same-origin bundled scripts can run, so markup injected
  // into the page still cannot add styles.
  const create = document.createElement.bind(document);
  document.createElement = ((tag: string, options?: ElementCreationOptions) => {
    const el = create(tag, options);
    if (tag.toLowerCase() === "style") el.setAttribute("nonce", nonce);
    return el;
  }) as typeof document.createElement;
}

applyTheme(storedTheme());

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Live views keep their last good data visible while a refresh fails.
      retry: (count, error) => !(error instanceof ApiError && [401, 403, 404].includes(error.status)) && count < 2,
      refetchOnWindowFocus: true,
      staleTime: 5_000,
    },
    mutations: { retry: false },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Tooltip.Provider delayDuration={300}>
          <SessionProvider>
            <App />
          </SessionProvider>
        </Tooltip.Provider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
