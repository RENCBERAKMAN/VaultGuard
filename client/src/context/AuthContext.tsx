import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import { authApi } from "../api/auth";
import { setTokens, clearTokens, getAccessToken } from "../api/client";
import { extractErrorMessage } from "../lib/errors";
import type { User, LoginRequest, RegisterRequest } from "../types";

interface AuthResult {
  success: boolean;
  message: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (data: LoginRequest) => Promise<AuthResult>;
  register: (data: RegisterRequest) => Promise<AuthResult>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = async () => {
    try {
      const res = await authApi.me();
      if (res.data.success && res.data.data) {
        setUser(res.data.data);
      }
    } catch {
      // silently ignore; caller keeps stale user data on failure
    }
  };

  useEffect(() => {
    const bootstrap = async () => {
      if (getAccessToken()) {
        try {
          const res = await authApi.me();
          if (res.data.success && res.data.data) {
            setUser(res.data.data);
          } else {
            clearTokens();
          }
        } catch {
          clearTokens();
        }
      }
      setLoading(false);
    };
    bootstrap();
  }, []);

  const login = async (data: LoginRequest): Promise<AuthResult> => {
    try {
      const res = await authApi.login(data);
      if (res.data.success && res.data.data) {
        setTokens(res.data.data);
        const meRes = await authApi.me();
        if (meRes.data.success && meRes.data.data) {
          setUser(meRes.data.data);
        }
        return { success: true, message: res.data.message };
      }
      return { success: false, message: res.data.message || "Sign in failed." };
    } catch (err) {
      return { success: false, message: extractErrorMessage(err, "Invalid email or password.") };
    }
  };

  const register = async (data: RegisterRequest): Promise<AuthResult> => {
    try {
      const res = await authApi.register(data);
      return { success: res.data.success, message: res.data.message };
    } catch (err) {
      return { success: false, message: extractErrorMessage(err, "Could not create the account.") };
    }
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch {
      // clear the local session even if the server call fails
    }
    clearTokens();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}