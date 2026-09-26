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
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .me()
      .then(setUser)
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
    setUser(loggedIn);
  }, []);

  const register = useCallback(
    async (email: string, password: string, firstName: string, lastName: string) => {
      const created = await api.register({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      });
      setUser(created);
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

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider.");
  return ctx;
}
