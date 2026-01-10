// src/context/AuthContext.jsx (FULL FILE)

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { loginRequest, getMe } from "../services/api";
// --------------------------------------------
// Helpers for token storage
// --------------------------------------------
function readToken() {
  return localStorage.getItem("token") || sessionStorage.getItem("token");
}

function saveToken(token, remember = true) {
  // clear both first
  localStorage.removeItem("token");
  sessionStorage.removeItem("token");

  if (remember) localStorage.setItem("token", token);
  else sessionStorage.setItem("token", token);
}

function clearToken() {
  localStorage.removeItem("token");
  sessionStorage.removeItem("token");
}

// --------------------------------------------
// Context
// --------------------------------------------
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(readToken());
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const isLoggedIn = !!token;

  // Login (calls POST /login)
  // backend returns: { ok:true, token, user }
  const login = async ({ email, password, remember = true }) => {
    const data = await loginRequest(email, password);

    // if your backend returns ok:false, apiFetch already throws
    saveToken(data.token, remember);
    setToken(data.token);
    setUser(data.user || null);

    return data;
  };

  // Logout
  const logout = () => {
    clearToken();
    setToken(null);
    setUser(null);
  };

  // On app load/refresh:
  // If token exists -> call /api/me to validate + load user
  useEffect(() => {
    const init = async () => {
      const t = readToken();

      if (!t) {
        setLoading(false);
        return;
      }

      // token exists locally; validate by calling /api/me
      try {
        const me = await getMe(); // expected: { ok:true, user }
        setToken(t);
        setUser(me.user || null);
      } catch (err) {
        // token invalid/expired or backend error
        clearToken();
        setToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    init();
  }, []);

  const value = useMemo(
    () => ({
      token,
      user,
      isLoggedIn,
      loading,
      login,
      logout,
    }),
    [token, user, isLoggedIn, loading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
