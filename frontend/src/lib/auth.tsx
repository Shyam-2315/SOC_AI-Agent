import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, decodeJwtPayload, ENDPOINTS, getToken, setToken, USER_KEY } from "./api";

export type SocUser = {
  id?: string | number;
  email?: string;
  username?: string;
  role?: string;
  organization_id?: string | number;
  [k: string]: any;
};

type AuthCtx = {
  user: SocUser | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
};

const Ctx = createContext<AuthCtx | null>(null);

function readUser(): SocUser | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SocUser | null>(null);
  const [token, setTok] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setTok(getToken());
    setUser(readUser());
    setLoading(false);
  }, []);

  async function refreshUser() {
    const currentToken = getToken();
    if (!currentToken) return;
    const claims = decodeJwtPayload<SocUser>(currentToken);
    if (!claims) return;
    const me: SocUser = {
      id: claims.user_id || claims.sub,
      email: claims.email,
      role: claims.role,
      organization_id: claims.organization_id,
      ...claims,
    };
    setUser(me);
    localStorage.setItem(USER_KEY, JSON.stringify(me));
  }

  async function login(email: string, password: string) {
    const payload = await api<any>(ENDPOINTS.login, {
      method: "POST",
      body: { email, password },
      auth: false,
    });
    const access_token = payload?.access_token || payload?.token;
    if (!access_token) throw new Error("Login response did not include access_token");
    setToken(access_token);
    setTok(access_token);

    const claims = decodeJwtPayload<SocUser>(access_token);
    const u: SocUser = payload?.user || {
      id: claims?.user_id || claims?.sub,
      email,
      role: claims?.role || payload?.role,
      organization_id: claims?.organization_id,
      ...(payload?.user_info || {}),
    };
    setUser(u);
    localStorage.setItem(USER_KEY, JSON.stringify(u));
    // Best-effort fetch full profile
    refreshUser();
  }

  function logout() {
    setToken(null);
    localStorage.removeItem(USER_KEY);
    setUser(null);
    setTok(null);
    if (typeof window !== "undefined") window.location.href = "/login";
  }

  return (
    <Ctx.Provider value={{ user, token, loading, login, logout, refreshUser }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
