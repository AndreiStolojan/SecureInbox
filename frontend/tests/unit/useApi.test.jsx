import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useApi, bustCache, bustCacheByPrefix } from '../../src/hooks/useApi.js';
import { clearStoredToken, setStoredToken } from '../../src/utils/tokenStorage.js';

const deferred = () => Promise.withResolvers();
afterEach(() => { clearStoredToken(); bustCacheByPrefix(''); });

it('never shows A cached data or a late A response in session B', async () => {
  setStoredToken('synthetic-A');
  const lateA = deferred();
  const fetcher = vi.fn().mockResolvedValueOnce('A cached').mockReturnValueOnce(lateA.promise);
  const a = renderHook(() => useApi(fetcher, [], 'sender-lists'));
  await waitFor(() => expect(a.result.current.data).toBe('A cached'));
  let pending;
  act(() => { pending = a.result.current.reload(); });
  act(() => { clearStoredToken(); setStoredToken('synthetic-B'); });
  a.unmount();
  const pendingB = deferred();
  const b = renderHook(() => useApi(() => pendingB.promise, [], 'sender-lists'));
  expect(b.result.current.data).toBeNull();
  await act(async () => { lateA.resolve('A late'); await pending; });
  const revisit = renderHook(() => useApi(() => pendingB.promise, [], 'sender-lists'));
  expect(revisit.result.current.data).toBeNull();
  await act(async () => { pendingB.resolve('B only'); });
  expect(b.result.current.data).toBe('B only');
});

it('reloads when only the key changes and rejects older success', async () => {
  const old = deferred();
  const next = deferred();
  const hook = renderHook(({ key }) => useApi(() => key === 'old' ? old.promise : next.promise, [], key), { initialProps: { key: 'old' } });
  hook.rerender({ key: 'next' });
  await act(async () => { next.resolve('new result'); });
  expect(hook.result.current.data).toBe('new result');
  await act(async () => { old.resolve('old result'); });
  expect(hook.result.current.data).toBe('new result');
});

it('older errors cannot change the newer request loading or error', async () => {
  const old = deferred();
  const next = deferred();
  const fetcher = vi.fn().mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise);
  const hook = renderHook(() => useApi(fetcher));
  act(() => { hook.result.current.reload(); });
  await act(async () => { old.reject(new Error('old failure')); });
  expect(hook.result.current.error).toBeNull();
  expect(hook.result.current.loading).toBe(true);
  await act(async () => { next.resolve('current'); });
  expect(hook.result.current.data).toBe('current');
});

it('unmounted requests cannot repopulate the cache', async () => {
  const pending = deferred();
  const hook = renderHook(() => useApi(() => pending.promise, [], 'unmounted'));
  hook.unmount();
  await act(async () => { pending.resolve('discarded'); });
  const revisit = renderHook(() => useApi(() => new Promise(() => {}), [], 'unmounted'));
  expect(revisit.result.current.data).toBeNull();
});

it('bounds cache history without clearing an active result', async () => {
  const first = renderHook(() => useApi(() => Promise.resolve('first'), [], 'bound-0'));
  await waitFor(() => expect(first.result.current.data).toBe('first'));
  for (let i = 1; i <= 32; i++) {
    const hook = renderHook(() => useApi(() => Promise.resolve(i), [], `bound-${i}`));
    await waitFor(() => expect(hook.result.current.data).toBe(i));
    hook.unmount();
  }
  expect(first.result.current.data).toBe('first');
  const revisit = renderHook(() => useApi(() => new Promise(() => {}), [], 'bound-0'));
  expect(revisit.result.current.data).toBeNull();
});

it('preserves same-session revalidation, optimistic state and exact/prefix invalidation', async () => {
  const initial = renderHook(() => useApi(() => Promise.resolve('cached'), [], 'rules-1'));
  await waitFor(() => expect(initial.result.current.data).toBe('cached'));
  initial.unmount();
  const pending = deferred();
  const revisit = renderHook(() => useApi(() => pending.promise, [], 'rules-1'));
  expect(revisit.result.current.data).toBe('cached');
  expect(revisit.result.current.loading).toBe(false);
  act(() => revisit.result.current.setData((data) => `${data} optimistic`));
  expect(revisit.result.current.data).toBe('cached optimistic');
  bustCache('rules-1');
  await act(async () => { pending.resolve('pre-mutation response'); });
  const invalidated = renderHook(() => useApi(() => new Promise(() => {}), [], 'rules-1'));
  expect(invalidated.result.current.data).toBeNull();
  const sibling = renderHook(() => useApi(() => Promise.resolve('sibling'), [], 'rules-2'));
  await waitFor(() => expect(sibling.result.current.data).toBe('sibling'));
  bustCacheByPrefix('rules-');
  const cleared = renderHook(() => useApi(() => new Promise(() => {}), [], 'rules-2'));
  expect(cleared.result.current.data).toBeNull();
});

it('clears mounted data on logout from another tab', async () => {
  setStoredToken('cross-tab-A');
  const fetcher = vi.fn().mockResolvedValueOnce('private A').mockImplementation(() => new Promise(() => {}));
  const hook = renderHook(() => useApi(fetcher, [], 'cross-tab'));
  await waitFor(() => expect(hook.result.current.data).toBe('private A'));
  act(() => {
    window.localStorage.removeItem('secureinbox_token');
    const event = new Event('storage');
    Object.defineProperties(event, { key: { value: 'secureinbox_token' }, storageArea: { value: window.localStorage } });
    window.dispatchEvent(event);
  });
  expect(hook.result.current.data).toBeNull();
});
