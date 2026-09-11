import { createContext, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import * as authApi from '../api/authApi.js';
import { getMe } from '../api/usersApi.js';
import { clearStoredToken, getStoredToken, setStoredToken, getSessionVersion, subscribeToSession } from '../utils/tokenStorage.js';

export const AuthContext = createContext(null);

/** Keep identity and pending authentication work tied to the current session. */
export function AuthProvider({ children }) {
  const session = useSyncExternalStore(subscribeToSession, getSessionVersion);
  const token = getStoredToken();
  const [identity, setIdentity] = useState(null);
  const user = identity?.session === session ? identity.user : null;
  const [loading, setLoading] = useState(Boolean(token));
  const [error, setError] = useState(null);
  const refreshRequest = useRef(0);
  const authRequest = useRef(0);

  const refreshUser = useCallback(async () => {
    const version = getSessionVersion();
    const request = ++refreshRequest.current;
    const isCurrent = () => version === getSessionVersion() && request === refreshRequest.current;
    if (!getStoredToken()) {
      setIdentity(null);
      setLoading(false);
      return null;
    }
    setLoading(true);
    try {
      const currentUser = await getMe();
      if (!isCurrent()) return null;
      setIdentity({ session: version, user: currentUser });
      setError(null);
      return currentUser;
    } catch (err) {
      if (isCurrent()) {
        clearStoredToken();
        setIdentity(null);
        setError(err.message);
      }
      return null;
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!user) refreshUser();
    return () => { refreshRequest.current += 1; authRequest.current += 1; };
    // Validate once per session; login already supplies a verified identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, refreshUser]);

  const authenticate = useCallback(async (action, payload) => {
    const version = getSessionVersion();
    const request = ++authRequest.current;
    const result = await action(payload);
    if (version !== getSessionVersion() || request !== authRequest.current) return null;
    setStoredToken(result.token);
    setIdentity({ session: getSessionVersion(), user: result.user });
    setError(null);
    setLoading(false);
    return result;
  }, []);

  const login = useCallback((payload) => authenticate(authApi.login, payload), [authenticate]);
  const register = useCallback((payload) => authenticate(authApi.register, payload), [authenticate]);
  const patchUser = useCallback((partial) => {
    setIdentity((previous) => previous?.session === getSessionVersion()
      ? { ...previous, user: { ...previous.user, ...partial } } : previous);
  }, []);

  const logout = useCallback(() => {
    clearStoredToken();
    setIdentity(null);
    setLoading(false);
    setError(null);
  }, []);

  const value = useMemo(() => ({
    session, token, user, loading, error, isAuthenticated: Boolean(token && user),
    login, register, logout, refreshUser, patchUser,
  }), [session, token, user, loading, error, login, register, logout, refreshUser, patchUser]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
