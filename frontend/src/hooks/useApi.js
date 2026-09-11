import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { getSessionVersion, subscribeToSession } from '../utils/tokenStorage.js';

// Keep at most 32 results from this session, evicting the oldest written entry.
const CACHE_LIMIT = 32;
const cache = new Map();
let cacheVersion = 0;
subscribeToSession(() => {
  cache.clear();
  cacheVersion += 1;
});

/** Cached reads revalidate on mount, key/dependency changes and explicit reload. */
export function useApi(fetcher, deps = [], cacheKey = null) {
  const session = useSyncExternalStore(subscribeToSession, getSessionVersion);
  const [state, setState] = useState(null);
  const request = useRef(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const cached = cache.get(cacheKey);
  const current = state?.session === session && state?.cacheKey === cacheKey;
  const visible = current ? state : {
    session, cacheKey, data: cached ?? null, loading: cached === undefined, error: null,
  };

  const load = useCallback(async () => {
    if (session !== getSessionVersion()) return null;
    const id = ++request.current;
    const version = cacheVersion;
    const isCurrent = () => id === request.current && session === getSessionVersion();
    setState((previous) => ({
      session, cacheKey,
      data: previous?.session === session && previous?.cacheKey === cacheKey
        ? previous.data : cache.get(cacheKey) ?? null,
      loading: !cache.has(cacheKey), error: null,
    }));
    try {
      const result = await fetcherRef.current();
      if (!isCurrent()) return null;
      if (cacheKey && version === cacheVersion) {
        cache.delete(cacheKey);
        cache.set(cacheKey, result);
        if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
      }
      setState({ session, cacheKey, data: result, loading: false, error: null });
      return result;
    } catch (err) {
      if (isCurrent()) {
        setState((previous) => ({ ...previous, error: err.message || 'Failed to load data.', loading: false }));
      }
      return null;
    }
    // Callers provide query dependencies; inline fetchers stay in the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, cacheKey, ...deps]);

  useEffect(() => {
    load();
    return () => { request.current += 1; };
  }, [load]);

  const setData = useCallback((update) => {
    if (session !== getSessionVersion()) return;
    setState((previous) => {
      if (previous?.session !== session || previous?.cacheKey !== cacheKey) return previous;
      return { ...previous, data: typeof update === 'function' ? update(previous.data) : update };
    });
  }, [session, cacheKey]);

  return { data: visible.data, loading: visible.loading, error: visible.error, reload: load, setData };
}

/** Invalidate cached reads after mutations, including pending cache writes. */
export function bustCache(...keys) {
  cacheVersion += 1;
  keys.forEach((key) => cache.delete(key));
}

export function bustCacheByPrefix(...prefixes) {
  cacheVersion += 1;
  for (const key of cache.keys()) {
    if (prefixes.some((prefix) => key.startsWith(prefix))) cache.delete(key);
  }
}
