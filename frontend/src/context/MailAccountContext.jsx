// ─────────────────────────────────────────────────────────────────────────────
// MailAccountContext.jsx — contul Gmail conectat și starea sincronizării.
//
// Ce face, pe scurt: ține lista conturilor de mail conectate (în acest proiect,
// practic un singur cont Gmail), starea de sincronizare (`syncing`,
// `lastSync`) și expune funcția `sync()` pentru butonul "Sync now".
//
// Mecanismul "syncVersion": de fiecare dată când `sync()` reușește, se
// incrementează `syncVersion`. Paginile (Dashboard, Inbox etc.) pun
// `syncVersion` în array-ul de dependențe al lui `useApi`, deci atunci când
// crește, TOATE se reîncarcă automat cu emailurile noi — un singur semnal
// reîmprospătează tot UI-ul, fără să fie nevoie ca paginile să comunice
// direct între ele.
//
// MailAccountProvider înfășoară doar zona logată (din AppShell), nu toată
// aplicația ca AuthProvider.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import { getMailAccounts, syncMailAccount } from '@/api/mailAccountsApi';

// Contextul propriu-zis — accesat de obicei prin hook-ul useMailAccount() de mai jos.
const MailAccountContext = createContext(null);

// Backend-ul poate trimite id-ul fie ca `id`, fie ca `_id` (Mongo) — funcția
// de mai jos îl normalizează indiferent de formă.
const accountId = (account) => account?.id || account?._id;

// MailAccountProvider — furnizor: ține conturile de mail și starea sincronizării.
export function MailAccountProvider({ children }) {
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [lastSync, setLastSync] = useState(null);
  // Crescut după fiecare sincronizare cu succes, ca paginile să-și
  // reîncarce datele (vezi explicația "syncVersion" de mai sus).
  const [syncVersion, setSyncVersion] = useState(0);

  // reload — (re)încarcă lista conturilor de mail conectate din backend.
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getMailAccounts();
      setAccounts(Array.isArray(result) ? result : result?.items || []);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to load mail accounts.');
    } finally {
      setLoading(false);
    }
  }, []);

  // La montarea Provider-ului, încărcăm o dată lista de conturi.
  // [reload] e stabil (memorat cu useCallback([])), deci efectul rulează o singură dată.
  useEffect(() => {
    reload();
  }, [reload]);

  // Pentru acest proiect există cel mult un cont Gmail conectat -> primul din listă.
  const account = accounts[0] || null;
  const isConnected = Boolean(account);

  // sync — singurul mod corect de a sincroniza: cheamă API-ul de sync pentru
  // contul curent, salvează rezultatul ca `lastSync`, incrementează
  // `syncVersion` (declanșează reîncărcarea automată în toate paginile) și
  // reîncarcă lista de conturi (ex. ca să se actualizeze data ultimei sincronizări).
  const sync = useCallback(async () => {
    if (!account) return null;
    setSyncing(true);
    try {
      const result = await syncMailAccount(accountId(account));
      setLastSync(result);
      setSyncVersion((v) => v + 1);
      await reload();
      return result;
    } finally {
      setSyncing(false);
    }
  }, [account, reload]);

  // Auto-poll: acum că sincronizarea incrementală e ieftină (doar diff-ul de
  // istoric Gmail, nu tot inbox-ul), verificăm periodic dacă au apărut
  // emailuri noi, ca userul să nu mai fie nevoit să dea Refresh manual.
  // Se oprește când tab-ul e ascuns (economisește la baterie/rețea) și când
  // nu există un cont conectat.
  useEffect(() => {
    if (!isConnected) return undefined;

    const tick = () => {
      if (document.visibilityState !== 'visible') return;
      sync().catch(() => {});
    };

    const intervalId = setInterval(tick, 45_000);
    document.addEventListener('visibilitychange', tick);

    return () => {
      clearInterval(intervalId);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [isConnected, sync]);

  // value e memorat cu useMemo: se recalculează doar când se schimbă efectiv
  // unul din câmpurile listate, ca să evităm re-render-uri inutile la
  // componentele care citesc acest context.
  const value = useMemo(
    () => ({
      accounts,
      account,
      isConnected,
      loading,
      error,
      syncing,
      lastSync,
      syncVersion,
      sync,
      reload,
    }),
    [accounts, account, isConnected, loading, error, syncing, lastSync, syncVersion, sync, reload]
  );

  return <MailAccountContext.Provider value={value}>{children}</MailAccountContext.Provider>;
}

// useMailAccount — hook pentru a citi contextul de mai sus. Aruncă o eroare
// clară dacă e folosit într-o componentă care nu e înfășurată în
// MailAccountProvider (ajută la depanare în timpul dezvoltării).
export function useMailAccount() {
  const context = useContext(MailAccountContext);
  if (!context) {
    throw new Error('useMailAccount must be used inside MailAccountProvider.');
  }
  return context;
}
