import { createContext, useContext, useEffect, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, del, get, post, setCsrfToken, setUnauthenticatedHandler } from "./api";
import type { SessionInfo } from "./types";

type SessionState = {
  session: SessionInfo | null;
  loading: boolean;
  signIn: (username: string, password: string, code: string) => Promise<void>;
  signOut: () => Promise<void>;
};

const SessionContext = createContext<SessionState | null>(null);

async function loadSession(): Promise<SessionInfo | null> {
  try {
    return await get<SessionInfo>("/api/v1/session");
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ["session"], queryFn: loadSession, staleTime: 60_000, refetchInterval: 60_000, retry: 1 });
  const session = query.data ?? null;

  useEffect(() => {
    setCsrfToken(session?.csrf ?? "");
  }, [session]);

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      client.setQueryData(["session"], null);
      client.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
    });
  }, [client]);

  const login = useMutation({
    mutationFn: (v: { username: string; password: string; code: string }) => post<SessionInfo>("/api/v1/session", v),
    onSuccess: (s) => {
      setCsrfToken(s.csrf);
      client.setQueryData(["session"], s);
    },
  });

  const value: SessionState = {
    session,
    loading: query.isPending,
    signIn: async (username, password, code) => {
      await login.mutateAsync({ username, password, code });
    },
    signOut: async () => {
      try {
        await del("/api/v1/session");
      } finally {
        setCsrfToken("");
        client.clear();
        client.setQueryData(["session"], null);
      }
    },
  };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const v = useContext(SessionContext);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

/** The signed-in session; only call beneath the authenticated shell. */
export function useAccount(): SessionInfo {
  const { session } = useSession();
  if (!session) throw new Error("useAccount without a session");
  return session;
}
