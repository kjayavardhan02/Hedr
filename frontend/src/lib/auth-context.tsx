"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { AUTH_EVENT, api } from "./api";
import type { User } from "./types";
import { clearSavedFilters } from "./savedFilters";
import { applyTheme } from "./theme";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    email: string,
    password: string,
    firstName: string,
    lastName: string
  ) => Promise<void>;
  logout: () => Promise<void>;
  /** Re-fetches the current user - call after a profile/preferences edit so
   * the sidebar and anything else reading `user` picks up the change
   * without needing a full page reload. */
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // The blocking script in layout.tsx already applied last time's remembered
  // theme before paint (see lib/theme.ts) - once the account's own value
  // loads, it's the source of truth, so reconcile in case they differ (a
  // new browser with no localStorage entry, or the preference changed on
  // another device).
  const setUserAndApplyTheme = useCallback((loaded: User | null) => {
    setUser(loaded);
    if (loaded) applyTheme(loaded.theme);
  }, []);

  useEffect(() => {
    api
      .me()
      .then(setUserAndApplyTheme)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    function onUnauthorized() {
      setUser(null);
    }
    window.addEventListener(AUTH_EVENT, onUnauthorized);
    return () => window.removeEventListener(AUTH_EVENT, onUnauthorized);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const loggedIn = await api.login({ email, password });
    setUserAndApplyTheme(loggedIn);
  }, []);

  const register = useCallback(
    async (email: string, password: string, firstName: string, lastName: string) => {
      const created = await api.register({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      });
      setUserAndApplyTheme(created);
    },
    []
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Even if the request fails, drop the local session state below.
    }
    clearSavedFilters();
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const refreshed = await api.me();
    setUserAndApplyTheme(refreshed);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider.");
  return ctx;
}
