const TOKEN_KEY = 'secureinbox_token';
const listeners = new Set();
let sessionVersion = 0;

/** Notify same-tab readers and invalidate work from the previous session. */
function sessionChanged() {
  sessionVersion += 1;
  listeners.forEach((listener) => listener());
}

export const getSessionVersion = () => sessionVersion;
export function subscribeToSession(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export const getStoredToken = () =>
  typeof window === 'undefined' ? null : window.localStorage.getItem(TOKEN_KEY);

export function setStoredToken(token) {
  window.localStorage.setItem(TOKEN_KEY, token);
  sessionChanged();
}

export function clearStoredToken() {
  window.localStorage.removeItem(TOKEN_KEY);
  sessionChanged();
}

// Storage events cover login/logout in another tab, including storage.clear().
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.storageArea === window.localStorage && (event.key === TOKEN_KEY || event.key === null)) {
      sessionChanged();
    }
  });
}
