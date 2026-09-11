import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useContext } from 'react';
import { getMe } from '../../src/api/usersApi.js';
import { login as loginApi } from '../../src/api/authApi.js';
import { clearStoredToken, setStoredToken } from '../../src/utils/tokenStorage.js';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AuthContext, AuthProvider } from '../../src/context/AuthContext.jsx';

vi.mock('../../src/api/authApi.js', () => ({
  login: vi.fn().mockResolvedValue({
    token: 'new-token',
    user: {
      _id: 'u1',
      name: 'Test User',
      email: 'test@example.com',
      settings: { aiEnabled: true },
    },
  }),
  register: vi.fn(),
}));

vi.mock('../../src/api/usersApi.js', () => ({
  getMe: vi.fn().mockResolvedValue({
    _id: 'u1',
    name: 'Stored User',
    email: 'stored@example.com',
    settings: { aiEnabled: true },
  }),
}));

afterEach(() => {
  window.localStorage.clear();
});

function Consumer() {
  return (
    <AuthContext.Consumer>
      {(auth) => (
        <div>
          <span data-testid="auth-state">{auth.isAuthenticated ? 'yes' : 'no'}</span>
          <span data-testid="user-name">{auth.user?.name || 'none'}</span>
          <button type="button" onClick={() => auth.login({ email: 'test@example.com', password: 'Password1!' })}>
            Login
          </button>
          <button type="button" onClick={auth.logout}>
            Logout
          </button>
        </div>
      )}
    </AuthContext.Consumer>
  );
}

describe('AuthProvider', () => {
  it('stores token and exposes user after login', async () => {
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>
    );

    await userEvent.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('yes'));
    expect(screen.getByTestId('user-name')).toHaveTextContent('Test User');
    expect(window.localStorage.getItem('secureinbox_token')).toBe('new-token');
  });

  it('clears local auth state on logout', async () => {
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>
    );

    await userEvent.click(screen.getByRole('button', { name: 'Login' }));
    await userEvent.click(screen.getByRole('button', { name: 'Logout' }));

    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('no'));
    expect(window.localStorage.getItem('secureinbox_token')).toBeNull();
  });
});

it('ignores a pending identity refresh after logout', async () => {
  setStoredToken('A');
  const pending = Promise.withResolvers();
  getMe.mockReturnValueOnce(pending.promise);
  const hook = renderHook(() => useContext(AuthContext), { wrapper: AuthProvider });
  act(() => hook.result.current.logout());
  await act(async () => { pending.resolve({ _id: 'A', name: 'Stale A' }); });
  expect(hook.result.current.user).toBeNull();
  expect(hook.result.current.isAuthenticated).toBe(false);
  expect(hook.result.current.loading).toBe(false);
});

it('ignores a login that completes after logout', async () => {
  const pending = Promise.withResolvers();
  loginApi.mockReturnValueOnce(pending.promise);
  const hook = renderHook(() => useContext(AuthContext), { wrapper: AuthProvider });
  let login;
  act(() => { login = hook.result.current.login({}); });
  act(() => hook.result.current.logout());
  await act(async () => { pending.resolve({ token: 'A', user: { _id: 'A' } }); await login; });
  expect(hook.result.current.user).toBeNull();
  expect(window.localStorage.getItem('secureinbox_token')).toBeNull();
});

it('reacts immediately to authentication failure outside the provider', async () => {
  const hook = renderHook(() => useContext(AuthContext), { wrapper: AuthProvider });
  await act(async () => { await hook.result.current.login({}); });
  expect(hook.result.current.isAuthenticated).toBe(true);
  act(() => clearStoredToken());
  expect(hook.result.current.user).toBeNull();
  expect(hook.result.current.isAuthenticated).toBe(false);
});

it('finishes checking the session when the initial identity refresh expires', async () => {
  setStoredToken('expired');
  getMe.mockRejectedValueOnce(new Error('Session expired'));
  const hook = renderHook(() => useContext(AuthContext), { wrapper: AuthProvider });
  await waitFor(() => expect(hook.result.current.loading).toBe(false));
  expect(hook.result.current.user).toBeNull();
  expect(hook.result.current.isAuthenticated).toBe(false);
  expect(window.localStorage.getItem('secureinbox_token')).toBeNull();
});
